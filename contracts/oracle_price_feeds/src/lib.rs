#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, vec, Address, Env, Symbol, Vec,
};
use soroban_pausable::{Pausable, PausableError};
use soroban_access_control::{extend_storage_ttl, require_admin_permission};

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    NotAuthorized = 5001,
    PriceTooStale = 5002,
    InvalidPrice = 5003,
    InvalidDeviation = 5004,
    UnknownPair = 5005,
    QuorumNotMet = 5006,
    Paused = 5007,
}

impl From<PausableError> for ContractError {
    fn from(err: PausableError) -> Self {
        match err {
            PausableError::Paused => ContractError::Paused,
            PausableError::NotAuthorized => ContractError::NotAuthorized,
        }
    }
}

#[contracttype]
#[derive(Clone)]
pub struct PriceFeed {
    pub pair: Symbol,
    pub price: i128,
    pub decimals: u32,
    pub updated_at: u64,
    pub sequence: u64,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Paused,
    Sources(Symbol),
    Price(Symbol),
    Quorum(Symbol),
    StalenessThreshold,
    MaxDeviationBps,
}

// ────────────────────────────────────────────────────────────────────────────
// Contract
// ────────────────────────────────────────────────────────────────────────────

#[contract]
pub struct OraclePriceFeeds;

#[contractimpl]
impl OraclePriceFeeds {
    /// Initialize the contract with an admin.
    pub fn init(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ContractError::NotAuthorized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::StalenessThreshold, &600u64);
        env.storage().instance().set(&DataKey::MaxDeviationBps, &500u32);
        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "initialized")),
            admin,
        );
        Ok(())
    }

    /// Add an authorized source for a price pair.
    pub fn add_source(
        env: Env,
        admin: Address,
        pair: Symbol,
        source: Address,
    ) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "add_source",
            ContractError::NotAuthorized,
        )?;

        let mut sources = Self::get_sources(&env, &pair);
        if !sources.contains(&source) {
            sources.push_back(source.clone());
            let key = DataKey::Sources(pair.clone());
            env.storage().persistent().set(&key, &sources);
            extend_storage_ttl(&env, &key);
        }

        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "source_added")),
            (pair, source),
        );
        Ok(())
    }

    /// Remove an authorized source for a price pair.
    pub fn remove_source(
        env: Env,
        admin: Address,
        pair: Symbol,
        source: Address,
    ) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "remove_source",
            ContractError::NotAuthorized,
        )?;

        let mut sources = Self::get_sources(&env, &pair);
        sources.retain(|s| s != &source);
        let key = DataKey::Sources(pair.clone());
        env.storage().persistent().set(&key, &sources);
        extend_storage_ttl(&env, &key);

        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "source_removed")),
            (pair, source),
        );
        Ok(())
    }

    /// Get all sources for a pair.
    pub fn get_sources(env: Env, pair: Symbol) -> Vec<Address> {
        let key = DataKey::Sources(pair);
        env.storage()
            .persistent()
            .get::<_, Vec<Address>>(&key)
            .unwrap_or_else(|| vec![&env])
    }

    /// Set the quorum required for a pair.
    pub fn set_quorum(env: Env, admin: Address, pair: Symbol, quorum: u32) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "set_quorum",
            ContractError::NotAuthorized,
        )?;

        let key = DataKey::Quorum(pair.clone());
        env.storage().persistent().set(&key, &quorum);
        extend_storage_ttl(&env, &key);

        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "quorum_set")),
            (pair, quorum),
        );
        Ok(())
    }

    /// Update price for a pair. Only authorized sources can call this.
    /// Rejects non-positive prices and prices that deviate too much from current price.
    pub fn update_price(
        env: Env,
        source: Address,
        pair: Symbol,
        price: i128,
    ) -> Result<(), ContractError> {
        // Check if paused
        if Self::is_paused(env.clone()) {
            return Err(ContractError::Paused);
        }

        source.require_auth();

        // Reject non-positive prices
        if price <= 0 {
            return Err(ContractError::InvalidPrice);
        }

        // Verify source is authorized for this pair
        let sources = Self::get_sources_internal(&env, &pair);
        if !sources.contains(&source) {
            return Err(ContractError::NotAuthorized);
        }

        // Check deviation from current price if one exists
        if let Some(current_feed) = Self::get_price_internal(&env, &pair) {
            let max_deviation_bps = Self::get_max_deviation_bps(&env);
            let deviation_bps = Self::calculate_deviation_bps(current_feed.price, price);
            if deviation_bps > max_deviation_bps {
                return Err(ContractError::InvalidDeviation);
            }
        }

        // Get current sequence or start at 0
        let price_key = DataKey::Price(pair.clone());
        let sequence = if let Some(current_feed) = Self::get_price_internal(&env, &pair) {
            current_feed.sequence + 1
        } else {
            0
        };

        let feed = PriceFeed {
            pair: pair.clone(),
            price,
            decimals: 7,
            updated_at: env.ledger().timestamp(),
            sequence,
        };

        env.storage().persistent().set(&price_key, &feed);
        extend_storage_ttl(&env, &price_key);

        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "price_updated")),
            (pair, price),
        );
        Ok(())
    }

    /// Get the current price feed for a pair.
    /// Fails if price is stale or doesn't exist.
    pub fn get_price(env: Env, pair: Symbol) -> Result<PriceFeed, ContractError> {
        let feed = Self::get_price_internal(&env, &pair)
            .ok_or(ContractError::UnknownPair)?;

        let staleness_threshold = Self::get_staleness_threshold(&env);
        let now = env.ledger().timestamp();
        if now.saturating_sub(feed.updated_at) > staleness_threshold {
            return Err(ContractError::PriceTooStale);
        }

        Ok(feed)
    }

    /// Check if a price is stale.
    pub fn is_stale(env: Env, pair: Symbol) -> Result<bool, ContractError> {
        let feed = Self::get_price_internal(&env, &pair)
            .ok_or(ContractError::UnknownPair)?;

        let staleness_threshold = Self::get_staleness_threshold(&env);
        let now = env.ledger().timestamp();
        Ok(now.saturating_sub(feed.updated_at) > staleness_threshold)
    }

    /// Set the staleness threshold (in seconds).
    pub fn set_staleness_threshold(
        env: Env,
        admin: Address,
        threshold: u64,
    ) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "set_staleness_threshold",
            ContractError::NotAuthorized,
        )?;

        let key = DataKey::StalenessThreshold;
        env.storage().instance().set(&key, &threshold);

        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "staleness_threshold_set")),
            threshold,
        );
        Ok(())
    }

    /// Set the maximum deviation in basis points.
    pub fn set_max_deviation_bps(
        env: Env,
        admin: Address,
        bps: u32,
    ) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "set_max_deviation_bps",
            ContractError::NotAuthorized,
        )?;

        let key = DataKey::MaxDeviationBps;
        env.storage().instance().set(&key, &bps);

        env.events().publish(
            (
                Symbol::new(&env, "oracle"),
                Symbol::new(&env, "max_deviation_bps_set"),
            ),
            bps,
        );
        Ok(())
    }

    /// Pause the contract.
    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "pause",
            ContractError::NotAuthorized,
        )?;

        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "paused")),
            (),
        );
        Ok(())
    }

    /// Unpause the contract.
    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin(&env)?;
        require_admin_permission(
            &env,
            &stored_admin,
            &admin,
            "unpause",
            ContractError::NotAuthorized,
        )?;

        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish(
            (Symbol::new(&env, "oracle"), Symbol::new(&env, "unpaused")),
            (),
        );
        Ok(())
    }

    /// Check if the contract is paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    fn get_admin(env: &Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ContractError::NotAuthorized)
    }

    fn get_price_internal(env: &Env, pair: &Symbol) -> Option<PriceFeed> {
        let key = DataKey::Price(pair.clone());
        env.storage().persistent().get(&key)
    }

    fn get_sources_internal(env: &Env, pair: &Symbol) -> Vec<Address> {
        let key = DataKey::Sources(pair.clone());
        env.storage()
            .persistent()
            .get::<_, Vec<Address>>(&key)
            .unwrap_or_else(|| vec![&env])
    }

    fn get_staleness_threshold(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&DataKey::StalenessThreshold)
            .unwrap_or(600)
    }

    fn get_max_deviation_bps(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&DataKey::MaxDeviationBps)
            .unwrap_or(500)
    }

    /// Calculate deviation in basis points between old and new price.
    fn calculate_deviation_bps(old_price: i128, new_price: i128) -> u32 {
        if old_price == 0 {
            return 0;
        }
        let diff = if new_price > old_price {
            new_price - old_price
        } else {
            old_price - new_price
        };
        // bps = (diff / old_price) * 10000
        let bps = (diff as u128 * 10000 / old_price as u128) as u32;
        bps
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    fn setup(env: &Env) -> (Address, soroban_sdk::Address, OraclePriceFeedsClient) {
        let contract_id = env.register(OraclePriceFeeds, ());
        let client = OraclePriceFeedsClient::new(env, &contract_id);
        let admin = Address::generate(env);
        let pair = Symbol::new(env, "NGN/USDC");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "init",
                args: (admin.clone(),).into_val(env),
                sub_invokes: &[],
            },
        }]);

        client.init(&admin).unwrap();
        (admin, pair, client)
    }

    #[test]
    fn init_succeeds() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = env.register(OraclePriceFeeds, ());
        let client = OraclePriceFeedsClient::new(&env, &contract_id);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "init",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.init(&admin);
        assert!(result.is_ok());
    }

    #[test]
    fn init_emits_event() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = env.register(OraclePriceFeeds, ());
        let client = OraclePriceFeedsClient::new(&env, &contract_id);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "init",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.init(&admin).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }

    #[test]
    fn add_source_requires_admin() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let attacker = Address::generate(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (attacker.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_add_source(&attacker, &pair, &source);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn add_source_emits_event() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }

    #[test]
    fn remove_source_requires_admin() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let attacker = Address::generate(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove_source",
                args: (attacker.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_remove_source(&attacker, &pair, &source);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn remove_source_emits_event() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.remove_source(&admin, &pair, &source).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }

    #[test]
    fn unauthorized_source_rejected() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let unauthorized_source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &unauthorized_source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (unauthorized_source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&unauthorized_source, &pair, 1000000);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn non_positive_price_rejected() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        // Test zero price
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 0i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&source, &pair, 0);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::InvalidPrice);

        // Test negative price
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), -100i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&source, &pair, -100);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::InvalidPrice);
    }

    #[test]
    fn deviation_guard_rejects_large_deviation() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        // First price
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        // Try to set a price that deviates more than 500 bps (5%)
        // 1000000 + 600000 = 1600000 (60% increase, well above 5%)
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1600000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&source, &pair, 1600000);
        assert_eq!(
            result.unwrap_err().unwrap(),
            ContractError::InvalidDeviation
        );
    }

    #[test]
    fn deviation_guard_accepts_within_bounds() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        // First price
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        // Price within 5% (500 bps)
        // 1000000 * 0.05 = 50000, so 1050000 is exactly at the threshold
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1050000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&source, &pair, 1050000);
        assert!(result.is_ok());
    }

    #[test]
    fn staleness_check_rejects_stale_price() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        // Advance ledger past staleness threshold (default 600s)
        env.ledger().with_mut(|l| {
            l.timestamp = 700;
        });

        let result = client.try_get_price(&pair);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::PriceTooStale);
    }

    #[test]
    fn get_price_within_threshold() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        let result = client.get_price(&pair);
        assert!(result.is_ok());
        let feed = result.unwrap();
        assert_eq!(feed.price, 1000000);
        assert_eq!(feed.decimals, 7);
    }

    #[test]
    fn is_stale_returns_false_for_fresh_price() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        let result = client.is_stale(&pair);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn is_stale_returns_true_for_stale_price() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        // Advance ledger
        env.ledger().with_mut(|l| {
            l.timestamp = 700;
        });

        let result = client.is_stale(&pair);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn pause_blocks_updates() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "pause",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.pause(&admin).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&source, &pair, 1000000);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::Paused);
    }

    #[test]
    fn unpause_allows_updates() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "pause",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.pause(&admin).unwrap();

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "unpause",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.unpause(&admin).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_update_price(&source, &pair, 1000000);
        assert!(result.is_ok());
    }

    #[test]
    fn pause_requires_admin() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "pause",
                args: (attacker.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_pause(&attacker);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn unpause_requires_admin() {
        let env = Env::default();
        let (admin, _pair, client) = setup(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "pause",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.pause(&admin).unwrap();

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "unpause",
                args: (attacker.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_unpause(&attacker);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn price_feed_fields_match_backend_expectations() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        let result = client.get_price(&pair);
        assert!(result.is_ok());
        let feed = result.unwrap();

        // Verify field names match backend expectations
        assert_eq!(feed.price, 1000000);
        assert_eq!(feed.decimals, 7);
        assert!(feed.updated_at > 0);
        assert_eq!(feed.sequence, 0);
    }

    #[test]
    fn set_staleness_threshold_requires_admin() {
        let env = Env::default();
        let (_admin, _pair, client) = setup(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "set_staleness_threshold",
                args: (attacker.clone(), 300u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_set_staleness_threshold(&attacker, &300u64);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn set_staleness_threshold_emits_event() {
        let env = Env::default();
        let (admin, _pair, client) = setup(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "set_staleness_threshold",
                args: (admin.clone(), 300u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.set_staleness_threshold(&admin, &300u64).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }

    #[test]
    fn set_max_deviation_bps_requires_admin() {
        let env = Env::default();
        let (_admin, _pair, client) = setup(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "set_max_deviation_bps",
                args: (attacker.clone(), 1000u32).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_set_max_deviation_bps(&attacker, &1000u32);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn set_max_deviation_bps_emits_event() {
        let env = Env::default();
        let (admin, _pair, client) = setup(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "set_max_deviation_bps",
                args: (admin.clone(), 1000u32).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.set_max_deviation_bps(&admin, &1000u32).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }

    #[test]
    fn sequence_increments_on_each_price_update() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        // First update
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        let feed1 = client.get_price(&pair).unwrap();
        assert_eq!(feed1.sequence, 0);

        // Second update (within deviation bounds)
        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1010000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1010000).unwrap();

        let feed2 = client.get_price(&pair).unwrap();
        assert_eq!(feed2.sequence, 1);
    }

    #[test]
    fn price_update_emits_event() {
        let env = Env::default();
        let (admin, pair, client) = setup(&env);
        let source = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add_source",
                args: (admin.clone(), pair.clone(), source.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add_source(&admin, &pair, &source).unwrap();

        env.mock_auths(&[MockAuth {
            address: &source,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "update_price",
                args: (source.clone(), pair.clone(), 1000000i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.update_price(&source, &pair, 1000000).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }
}
