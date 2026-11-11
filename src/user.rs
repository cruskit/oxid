//! End users.
//!
//! This version has no registration: users come from configuration, or, when
//! none are configured, a single built-in demo user. The [`UserStore`] trait
//! is the seam for a real user directory later.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Result, anyhow, ensure};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use serde_json::{Map, Value, json};

use crate::config::UserConfig;

/// Username of the built-in demo user.
pub const DEMO_USERNAME: &str = "demo";
/// Password of the built-in demo user. Development only.
pub const DEMO_PASSWORD: &str = "demo-password";

#[derive(Debug, Clone)]
pub struct User {
    /// Stable internal identifier; clients only ever see a pairwise value
    /// derived from it.
    pub subject: String,
    pub username: String,
    password_hash: String,
    /// Identity claims, keyed by OpenID Connect claim name.
    pub claims: Map<String, Value>,
}

impl User {
    pub fn new(
        subject: impl Into<String>,
        username: impl Into<String>,
        password_hash: impl Into<String>,
        claims: Map<String, Value>,
    ) -> Result<Self> {
        let user = Self {
            subject: subject.into(),
            username: username.into(),
            password_hash: password_hash.into(),
            claims,
        };
        ensure!(!user.subject.is_empty(), "user subject must not be empty");
        ensure!(!user.username.is_empty(), "username must not be empty");
        PasswordHash::new(&user.password_hash)
            .map_err(|e| anyhow!("user '{}': invalid password_hash: {e}", user.username))?;
        Ok(user)
    }

    pub fn from_config(config: &UserConfig) -> Result<Self> {
        Self::new(
            &config.subject,
            &config.username,
            &config.password_hash,
            config.claims.clone(),
        )
    }

    fn password_matches(&self, password: &str) -> bool {
        PasswordHash::new(&self.password_hash).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    }
}

/// Hash a password with Argon2id, producing a PHC string for configuration.
pub fn hash_password(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow!("hashing password: {e}"))
}

/// Authentication and lookup of end users.
pub trait UserStore: Send + Sync + Debug {
    /// Check credentials. This is deliberately slow (password hashing), so
    /// async callers should run it on a blocking thread.
    fn authenticate(&self, username: &str, password: &str) -> Option<Arc<User>>;

    fn find_by_subject(&self, subject: &str) -> Option<Arc<User>>;
}

/// A fixed set of users held in memory.
#[derive(Debug)]
pub struct StaticUserStore {
    by_username: HashMap<String, Arc<User>>,
    /// Verified against when the username is unknown, so that response time
    /// does not reveal which usernames exist.
    decoy_hash: String,
}

impl StaticUserStore {
    pub fn new(users: impl IntoIterator<Item = User>) -> Result<Self> {
        let mut by_username = HashMap::new();
        let mut subjects = std::collections::HashSet::new();
        for user in users {
            ensure!(
                subjects.insert(user.subject.clone()),
                "duplicate subject '{}'",
                user.subject
            );
            let username = user.username.clone();
            ensure!(
                by_username
                    .insert(username.clone(), Arc::new(user))
                    .is_none(),
                "duplicate username '{username}'"
            );
        }
        Ok(Self {
            by_username,
            decoy_hash: hash_password("oxid-decoy-password")?,
        })
    }

    pub fn from_config(configs: &[UserConfig]) -> Result<Self> {
        Self::new(
            configs
                .iter()
                .map(User::from_config)
                .collect::<Result<Vec<_>>>()?,
        )
    }

    /// The hard-coded user this version ships with.
    pub fn demo() -> Result<Self> {
        Self::new([demo_user()?])
    }

    pub fn len(&self) -> usize {
        self.by_username.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_username.is_empty()
    }
}

impl UserStore for StaticUserStore {
    fn authenticate(&self, username: &str, password: &str) -> Option<Arc<User>> {
        if let Some(user) = self.by_username.get(username) {
            user.password_matches(password).then(|| Arc::clone(user))
        } else {
            if let Ok(hash) = PasswordHash::new(&self.decoy_hash) {
                let _ = Argon2::default().verify_password(password.as_bytes(), &hash);
            }
            None
        }
    }

    fn find_by_subject(&self, subject: &str) -> Option<Arc<User>> {
        self.by_username
            .values()
            .find(|user| user.subject == subject)
            .cloned()
    }
}

/// The built-in user: a fictional person carrying every claim ConnectID
/// requires a provider to support.
fn demo_user() -> Result<User> {
    let Value::Object(claims) = json!({
        "name": "Alex Jordan Citizen",
        "given_name": "Alex",
        "middle_name": "Jordan",
        "family_name": "Citizen",
        "email": "alex.citizen@example.com",
        "email_verified": true,
        "birthdate": "1985-04-12",
        "phone_number": "+61 400 000 000",
        "phone_number_verified": true,
        "address": {
            "formatted": "1 Example Street\nSydney NSW 2000\nAustralia",
            "street_address": "1 Example Street",
            "locality": "Sydney",
            "region": "NSW",
            "postal_code": "2000",
            "country": "Australia"
        }
    }) else {
        unreachable!("literal is an object");
    };
    User::new(
        "demo-user-0001",
        DEMO_USERNAME,
        hash_password(DEMO_PASSWORD)?,
        claims,
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::OnceLock;

    use super::*;

    /// Hashing is slow, so tests share one demo store.
    pub fn demo_store() -> &'static StaticUserStore {
        static STORE: OnceLock<StaticUserStore> = OnceLock::new();
        STORE.get_or_init(|| StaticUserStore::demo().expect("demo store"))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::demo_store;
    use super::*;

    #[test]
    fn demo_user_authenticates_with_the_right_password_only() {
        let store = demo_store();
        let user = store
            .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
            .expect("valid credentials");
        assert_eq!(user.username, DEMO_USERNAME);
        assert!(store.authenticate(DEMO_USERNAME, "wrong").is_none());
        assert!(store.authenticate(DEMO_USERNAME, "").is_none());
        assert!(store.authenticate("nobody", DEMO_PASSWORD).is_none());
    }

    #[test]
    fn demo_user_has_the_connectid_mandatory_claims() {
        let user = demo_store()
            .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
            .unwrap();
        for claim in [
            "given_name",
            "middle_name",
            "family_name",
            "email",
            "birthdate",
            "phone_number",
            "address",
        ] {
            assert!(user.claims.contains_key(claim), "{claim}");
        }
    }

    #[test]
    fn finds_users_by_internal_subject() {
        let store = demo_store();
        assert_eq!(
            store.find_by_subject("demo-user-0001").unwrap().username,
            DEMO_USERNAME
        );
        assert!(store.find_by_subject("missing").is_none());
    }

    #[test]
    fn hashes_are_salted_phc_strings() {
        let a = hash_password("secret").unwrap();
        let b = hash_password("secret").unwrap();
        assert!(a.starts_with("$argon2id$"));
        assert_ne!(a, b, "each hash has its own salt");
    }

    #[test]
    fn debug_output_is_safe_to_log() {
        // The hash is a PHC string, not the password, but check the password
        // itself can never appear.
        let user = demo_store()
            .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
            .unwrap();
        assert!(!format!("{user:?}").contains(DEMO_PASSWORD));
    }

    #[test]
    fn rejects_invalid_users() {
        let hash = hash_password("x").unwrap();
        assert!(User::new("", "u", &hash, Map::new()).is_err());
        assert!(User::new("s", "", &hash, Map::new()).is_err());
        assert!(User::new("s", "u", "plaintext-is-not-a-hash", Map::new()).is_err());
    }

    #[test]
    fn store_rejects_duplicates() {
        let hash = hash_password("x").unwrap();
        let user = |sub: &str, name: &str| User::new(sub, name, &hash, Map::new()).unwrap();
        assert!(StaticUserStore::new([user("1", "a"), user("2", "a")]).is_err());
        assert!(StaticUserStore::new([user("1", "a"), user("1", "b")]).is_err());
        assert_eq!(
            StaticUserStore::new([user("1", "a"), user("2", "b")])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn loads_users_from_config() {
        let config = UserConfig {
            username: "sam".into(),
            password_hash: hash_password("pw").unwrap(),
            subject: "u-9".into(),
            claims: Map::new(),
        };
        let store = StaticUserStore::from_config(&[config]).unwrap();
        assert!(store.authenticate("sam", "pw").is_some());
    }
}
