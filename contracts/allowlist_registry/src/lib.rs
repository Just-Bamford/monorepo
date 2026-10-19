#![no_std]

use soroban_access_control::{extend_storage_ttl, require_admin_permission};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, vec, Address, Env, String, Symbol, Vec,
};

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    NotAuthorized = 6001,
    NotFound = 6002,
    BulkSizeExceeded = 6003,
}

#[contracttype]
#[derive(Clone)]
pub struct AllowlistEntry {
    pub label: String,
    pub expires_at: u64,
    pub added_at: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Entry(Address),
    MemberCount,
}

const MAX_BULK_SIZE: u32 = 100;

// ────────────────────────────────────────────────────────────────────────────
// Contract
// ────────────────────────────────────────────────────────────────────────────

#[contract]
pub struct AllowlistRegistry;

#[contractimpl]
impl AllowlistRegistry {
    /// Initialize the contract with an admin.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ContractError::NotAuthorized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::MemberCount, &0u32);
        env.events().publish(
            (
                Symbol::new(&env, "allowlist"),
                Symbol::new(&env, "initialized"),
            ),
            admin,
        );
        Ok(())
    }

    /// Add an address to the allowlist with a label and optional expiry.
    pub fn add(
        env: Env,
        address: Address,
        label: String,
        expires_at: u64,
    ) -> Result<(), ContractError> {
        let admin = Self::get_admin(&env)?;
        admin.require_auth();

        let is_new = !Self::has_entry(&env, &address);
        let added_at = env.ledger().sequence();

        let entry = AllowlistEntry {
            label: label.clone(),
            expires_at,
            added_at,
        };

        let key = DataKey::Entry(address.clone());
        env.storage().persistent().set(&key, &entry);
        extend_storage_ttl(&env, &key);

        if is_new {
            let count_key = DataKey::MemberCount;
            let current_count = Self::get_member_count(&env);
            env.storage().instance().set(&count_key, &(current_count + 1));
        }

        env.events().publish(
            (Symbol::new(&env, "allowlist"), Symbol::new(&env, "added")),
            (address, label, expires_at),
        );
        Ok(())
    }

    /// Remove an address from the allowlist.
    pub fn remove(env: Env, address: Address) -> Result<(), ContractError> {
        let admin = Self::get_admin(&env)?;
        admin.require_auth();

        let key = DataKey::Entry(address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(ContractError::NotFound);
        }

        env.storage().persistent().remove(&key);

        let count_key = DataKey::MemberCount;
        let current_count = Self::get_member_count(&env);
        if current_count > 0 {
            env.storage().instance().set(&count_key, &(current_count - 1));
        }

        env.events().publish(
            (Symbol::new(&env, "allowlist"), Symbol::new(&env, "removed")),
            address,
        );
        Ok(())
    }

    /// Check if an address is an active member (not expired).
    pub fn is_member(env: Env, address: Address) -> bool {
        if let Some(entry) = Self::get_entry_internal(&env, &address) {
            let now = env.ledger().timestamp();
            if entry.expires_at == 0 {
                return true;
            }
            now <= entry.expires_at
        } else {
            false
        }
    }

    /// Get the allowlist entry for an address.
    pub fn get_entry(env: Env, address: Address) -> Result<AllowlistEntry, ContractError> {
        Self::get_entry_internal(&env, &address)
            .ok_or(ContractError::NotFound)
    }

    /// Add multiple entries in bulk.
    pub fn bulk_add(env: Env, entries: Vec<(Address, String, u64)>) -> Result<(), ContractError> {
        let admin = Self::get_admin(&env)?;
        admin.require_auth();

        if entries.len() > MAX_BULK_SIZE as usize {
            return Err(ContractError::BulkSizeExceeded);
        }

        let mut new_count = 0u32;
        for (address, label, expires_at) in entries.iter() {
            let is_new = !Self::has_entry(&env, &address);
            if is_new {
                new_count += 1;
            }

            let added_at = env.ledger().sequence();
            let entry = AllowlistEntry {
                label: label.clone(),
                expires_at,
                added_at,
            };

            let key = DataKey::Entry(address.clone());
            env.storage().persistent().set(&key, &entry);
            extend_storage_ttl(&env, &key);

            env.events().publish(
                (Symbol::new(&env, "allowlist"), Symbol::new(&env, "added")),
                (address.clone(), label.clone(), expires_at),
            );
        }

        if new_count > 0 {
            let count_key = DataKey::MemberCount;
            let current_count = Self::get_member_count(&env);
            env.storage().instance().set(&count_key, &(current_count + new_count));
        }

        Ok(())
    }

    /// Get the total number of members.
    pub fn member_count(env: Env) -> u32 {
        Self::get_member_count(&env)
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

    fn get_entry_internal(env: &Env, address: &Address) -> Option<AllowlistEntry> {
        let key = DataKey::Entry(address.clone());
        env.storage().persistent().get(&key)
    }

    fn has_entry(env: &Env, address: &Address) -> bool {
        let key = DataKey::Entry(address.clone());
        env.storage().persistent().has(&key)
    }

    fn get_member_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&DataKey::MemberCount)
            .unwrap_or(0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    fn setup(env: &Env) -> (Address, AllowlistRegistryClient) {
        let contract_id = env.register(AllowlistRegistry, ());
        let client = AllowlistRegistryClient::new(env, &contract_id);
        let admin = Address::generate(env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "initialize",
                args: (admin.clone(),).into_val(env),
                sub_invokes: &[],
            },
        }]);

        client.initialize(&admin).unwrap();
        (admin, client)
    }

    #[test]
    fn initialize_succeeds() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = env.register(AllowlistRegistry, ());
        let client = AllowlistRegistryClient::new(&env, &contract_id);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "initialize",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.initialize(&admin);
        assert!(result.is_ok());
    }

    #[test]
    fn add_requires_admin() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        let attacker = Address::generate(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "test");

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_add(&address, &label, &0u64);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn add_new_member() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "verified");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_add(&address, &label, &0u64);
        assert!(result.is_ok());

        assert!(client.is_member(&address));
    }

    #[test]
    fn add_updates_existing_member() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label1 = String::from_slice(&env, "kyc_level_1");
        let label2 = String::from_slice(&env, "kyc_level_2");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label1.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label1, &0u64).unwrap();

        let entry1 = client.get_entry(&address).unwrap();
        assert_eq!(entry1.label, label1);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label2.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label2, &0u64).unwrap();

        let entry2 = client.get_entry(&address).unwrap();
        assert_eq!(entry2.label, label2);

        // Should still have only 1 member
        assert_eq!(client.member_count(&), 1);
    }

    #[test]
    fn is_member_false_for_non_member() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        let address = Address::generate(&env);

        assert!(!client.is_member(&address));
    }

    #[test]
    fn is_member_false_for_expired() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "expired");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 100u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &100u64).unwrap();

        // Before expiry
        env.ledger().with_mut(|l| {
            l.timestamp = 50;
        });
        assert!(client.is_member(&address));

        // At expiry boundary
        env.ledger().with_mut(|l| {
            l.timestamp = 100;
        });
        assert!(client.is_member(&address));

        // After expiry
        env.ledger().with_mut(|l| {
            l.timestamp = 101;
        });
        assert!(!client.is_member(&address));
    }

    #[test]
    fn is_member_true_for_no_expiry() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "permanent");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &0u64).unwrap();

        env.ledger().with_mut(|l| {
            l.timestamp = 1000000;
        });

        assert!(client.is_member(&address));
    }

    #[test]
    fn get_entry_returns_correct_fields() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "test_label");
        let expires_at = 5000u64;

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), expires_at).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &expires_at).unwrap();

        let entry = client.get_entry(&address).unwrap();
        assert_eq!(entry.label, label);
        assert_eq!(entry.expires_at, expires_at);
        assert!(entry.added_at > 0);
    }

    #[test]
    fn get_entry_not_found() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        let address = Address::generate(&env);

        let result = client.try_get_entry(&address);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotFound);
    }

    #[test]
    fn remove_requires_admin() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let attacker = Address::generate(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "test");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &0u64).unwrap();

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove",
                args: (address.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_remove(&address);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotAuthorized);
    }

    #[test]
    fn remove_succeeds() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "test");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &0u64).unwrap();
        assert!(client.is_member(&address));

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove",
                args: (address.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.remove(&admin, &address).unwrap();
        assert!(!client.is_member(&address));
    }

    #[test]
    fn remove_not_found() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove",
                args: (address.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_remove(&address);
        assert_eq!(result.unwrap_err().unwrap(), ContractError::NotFound);
    }

    #[test]
    fn bulk_add_succeeds() {
        let env = Env::default();
        let (admin, client) = setup(&env);

        let mut entries = vec![&env];
        for i in 0..10 {
            let address = Address::generate(&env);
            let label = String::from_slice(&env, "bulk_member");
            entries.push_back((address, label, 0u64));
        }

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "bulk_add",
                args: (entries.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_bulk_add(&entries);
        assert!(result.is_ok());

        assert_eq!(client.member_count(&), 10);
    }

    #[test]
    fn bulk_add_exceeds_limit() {
        let env = Env::default();
        let (admin, client) = setup(&env);

        let mut entries = vec![&env];
        for _ in 0..101 {
            let address = Address::generate(&env);
            let label = String::from_slice(&env, "bulk_member");
            entries.push_back((address, label, 0u64));
        }

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "bulk_add",
                args: (entries.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_bulk_add(&entries);
        assert_eq!(
            result.unwrap_err().unwrap(),
            ContractError::BulkSizeExceeded
        );
    }

    #[test]
    fn member_count_accuracy() {
        let env = Env::default();
        let (admin, client) = setup(&env);

        assert_eq!(client.member_count(&), 0);

        for i in 0..5 {
            let address = Address::generate(&env);
            let label = String::from_slice(&env, "member");

            env.mock_auths(&[MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &client.address,
                    fn_name: "add",
                    args: (address.clone(), label.clone(), 0u64).into_val(&env),
                    sub_invokes: &[],
                },
            }]);

            client.add(&admin, &address, &label, &0u64).unwrap();
            assert_eq!(client.member_count(&), (i + 1) as u32);
        }

        // Remove one
        let to_remove = Address::generate(&env);
        let label = String::from_slice(&env, "member");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (to_remove.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &to_remove, &label, &0u64).unwrap();
        assert_eq!(client.member_count(&), 6);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove",
                args: (to_remove.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.remove(&admin, &to_remove).unwrap();
        assert_eq!(client.member_count(&), 5);
    }

    #[test]
    fn add_emits_event() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "test");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &0u64).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }

    #[test]
    fn remove_emits_event() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let address = Address::generate(&env);
        let label = String::from_slice(&env, "test");

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "add",
                args: (address.clone(), label.clone(), 0u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.add(&admin, &address, &label, &0u64).unwrap();

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "remove",
                args: (address.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.remove(&admin, &address).unwrap();

        let events = env.events().all();
        assert!(!events.is_empty());
    }
}
