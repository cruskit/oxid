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
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::config::UserConfig;

/// Username of the built-in demo user.
pub const DEMO_USERNAME: &str = "demo";
/// Password of the built-in demo user. Development only.
pub const DEMO_PASSWORD: &str = "demo-password";

/// The kind of a `PayID`, in the notation ConnectID uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum PayIdType {
    /// An email address.
    #[serde(rename = "/EMAL")]
    Email,
    /// A mobile number.
    #[serde(rename = "/TELI")]
    Mobile,
    /// An Australian Business Number.
    #[serde(rename = "/AUBN")]
    Abn,
    /// An organisation identifier.
    #[serde(rename = "/ORGN")]
    Organisation,
}

impl PayIdType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "/EMAL",
            Self::Mobile => "/TELI",
            Self::Abn => "/AUBN",
            Self::Organisation => "/ORGN",
        }
    }
}

/// A bank account the user owns and can receive payments into. It is the
/// source of the ConnectID `beneficiary_account_*` verified claims.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BankAccount {
    /// Legal name of the account holder.
    pub beneficiary_name: String,
    /// BSB: six digits, no separator.
    pub bsb: String,
    pub account_number: String,
    /// The `PayID` registered against the account, if any.
    pub payid: Option<String>,
    pub payid_type: Option<PayIdType>,
    /// BIC issued by SWIFT for the user's bank. Needed for
    /// `beneficiary_account_international`.
    pub bic_swift_code: Option<String>,
    /// Account number for international payments. Defaults to the BSB and
    /// account number concatenated.
    pub account_number_international: Option<String>,
}

impl BankAccount {
    pub fn validate(&self) -> Result<()> {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        ensure!(
            !self.beneficiary_name.trim().is_empty(),
            "bank_account.beneficiary_name must not be empty"
        );
        ensure!(
            self.bsb.len() == 6 && digits(&self.bsb),
            "bank_account.bsb must be six digits with no separator"
        );
        ensure!(
            self.account_number.len() <= 10 && digits(&self.account_number),
            "bank_account.account_number must be 1 to 10 digits"
        );
        ensure!(
            self.payid.is_some() == self.payid_type.is_some(),
            "bank_account.payid and bank_account.payid_type must be set together"
        );
        ensure!(
            self.payid.as_deref().is_none_or(|p| !p.trim().is_empty()),
            "bank_account.payid must not be empty"
        );
        if let Some(bic) = &self.bic_swift_code {
            ensure!(
                matches!(bic.len(), 8 | 11)
                    && bic
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
                "bank_account.bic_swift_code must be 8 or 11 upper-case letters and digits"
            );
        }
        if let Some(number) = &self.account_number_international {
            ensure!(
                !number.trim().is_empty(),
                "bank_account.account_number_international must not be empty"
            );
        }
        Ok(())
    }

    /// The account number to quote for international payments.
    pub fn international_number(&self) -> String {
        self.account_number_international
            .clone()
            .unwrap_or_else(|| format!("{}{}", self.bsb, self.account_number))
    }
}

#[derive(Debug, Clone)]
pub struct User {
    /// Stable internal identifier; clients only ever see a pairwise value
    /// derived from it.
    pub subject: String,
    pub username: String,
    password_hash: String,
    /// Identity claims, keyed by OpenID Connect claim name.
    pub claims: Map<String, Value>,
    /// Source of the beneficiary account verified claims.
    pub bank_account: Option<BankAccount>,
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
            bank_account: None,
        };
        ensure!(!user.subject.is_empty(), "user subject must not be empty");
        ensure!(!user.username.is_empty(), "username must not be empty");
        PasswordHash::new(&user.password_hash)
            .map_err(|e| anyhow!("user '{}': invalid password_hash: {e}", user.username))?;
        Ok(user)
    }

    /// Attach the user's bank account.
    pub fn with_bank_account(mut self, account: BankAccount) -> Result<Self> {
        account
            .validate()
            .map_err(|e| anyhow!("user '{}': {e}", self.username))?;
        self.bank_account = Some(account);
        Ok(self)
    }

    pub fn from_config(config: &UserConfig) -> Result<Self> {
        let user = Self::new(
            &config.subject,
            &config.username,
            &config.password_hash,
            config.claims.clone(),
        )?;
        match &config.bank_account {
            Some(account) => user.with_bank_account(account.clone()),
            None => Ok(user),
        }
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

/// The built-in user: a fictional person carrying every standard `OpenID`
/// Connect claim, and so every claim the ConnectID profile defines.
fn demo_user() -> Result<User> {
    let Value::Object(claims) = json!({
        "name": "Alex Jordan Citizen",
        "nickname": "Al",
        "preferred_username": "alex",
        "profile": "https://example.com/people/alex",
        "picture": "https://example.com/people/alex.jpg",
        "website": "https://alex.example.com",
        "email_verified": true,
        "gender": "non-binary",
        "zoneinfo": "Australia/Sydney",
        "locale": "en-AU",
        "phone_number_verified": true,
        // 2026-01-01T00:00:00Z
        "updated_at": 1_767_225_600,
        "given_name": "Alex",
        "middle_name": "Jordan",
        "family_name": "Citizen",
        "email": "alex.citizen@example.com",
        "birthdate": "1985-04-12",
        "phone_number": "+61 400 000 000",
        "address": {
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
    )?
    .with_bank_account(BankAccount {
        beneficiary_name: "Alex Jordan Citizen".to_owned(),
        bsb: "123456".to_owned(),
        account_number: "12345678".to_owned(),
        payid: Some("alex.citizen@example.com".to_owned()),
        payid_type: Some(PayIdType::Email),
        bic_swift_code: Some("OXIDAU2SXXX".to_owned()),
        account_number_international: None,
    })
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
            bank_account: None,
        };
        let store = StaticUserStore::from_config(std::slice::from_ref(&config)).unwrap();
        let user = store.authenticate("sam", "pw").unwrap();
        assert!(user.bank_account.is_none());

        let with_account = UserConfig {
            bank_account: Some(account()),
            ..config.clone()
        };
        let store = StaticUserStore::from_config(&[with_account]).unwrap();
        let user = store.authenticate("sam", "pw").unwrap();
        assert_eq!(user.bank_account.as_ref().unwrap().bsb, "100200");

        let invalid = UserConfig {
            bank_account: Some(BankAccount {
                bsb: "100-200".into(),
                ..account()
            }),
            ..config
        };
        let err = StaticUserStore::from_config(&[invalid]).unwrap_err();
        assert!(err.to_string().contains("sam"), "{err}");
    }

    fn account() -> BankAccount {
        BankAccount {
            beneficiary_name: "Sam Smith".into(),
            bsb: "100200".into(),
            account_number: "12345678".into(),
            payid: None,
            payid_type: None,
            bic_swift_code: None,
            account_number_international: None,
        }
    }

    #[test]
    fn bank_account_details_are_validated() {
        type Edit = fn(&mut BankAccount);
        account().validate().unwrap();
        let bad: [(&str, Edit); 9] = [
            ("blank name", |a| a.beneficiary_name = "  ".into()),
            ("bsb with a dash", |a| a.bsb = "100-200".into()),
            ("short bsb", |a| a.bsb = "10020".into()),
            ("account with letters", |a| a.account_number = "12A".into()),
            ("empty account", |a| a.account_number = String::new()),
            ("payid without a type", |a| {
                a.payid = Some("0400000321".into());
            }),
            ("type without a payid", |a| {
                a.payid_type = Some(PayIdType::Mobile);
            }),
            ("malformed bic", |a| a.bic_swift_code = Some("abc".into())),
            ("blank international number", |a| {
                a.account_number_international = Some(" ".into());
            }),
        ];
        for (name, edit) in bad {
            let mut account = account();
            edit(&mut account);
            assert!(account.validate().is_err(), "{name}");
        }
    }

    #[test]
    fn international_number_defaults_to_bsb_and_account() {
        assert_eq!(account().international_number(), "10020012345678");
        let explicit = BankAccount {
            account_number_international: Some("AU99".into()),
            ..account()
        };
        assert_eq!(explicit.international_number(), "AU99");
    }

    #[test]
    fn payid_types_use_connectid_notation() {
        for (text, kind) in [
            ("/EMAL", PayIdType::Email),
            ("/TELI", PayIdType::Mobile),
            ("/AUBN", PayIdType::Abn),
            ("/ORGN", PayIdType::Organisation),
        ] {
            assert_eq!(kind.as_str(), text);
            let parsed: PayIdType = serde_json::from_value(json!(text)).unwrap();
            assert_eq!(parsed, kind);
        }
        assert!(serde_json::from_value::<PayIdType>(json!("/CARD")).is_err());
    }

    #[test]
    fn demo_user_has_a_bank_account_for_every_beneficiary_claim() {
        let user = demo_store()
            .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
            .unwrap();
        let account = user.bank_account.as_ref().unwrap();
        account.validate().unwrap();
        assert!(account.payid.is_some() && account.bic_swift_code.is_some());
    }
}
