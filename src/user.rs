//! End users.
//!
//! This version has no registration: users come from configuration, or, when
//! none are configured, a single built-in demo user. The [`UserStore`] trait
//! is the seam for a real user directory later.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::config::UserConfig;
use crate::util::Secret;
use jiff::tz::TimeZone;

/// Username of the first built-in demo user (see `demo_users.toml`).
#[cfg(any(test, feature = "test-util"))]
#[cfg_attr(
    not(feature = "test-util"),
    expect(unreachable_pub, reason = "the integration tests use it")
)]
pub const DEMO_USERNAME: &str = "demo";
/// Password of the built-in demo user. Development only.
#[cfg_attr(
    not(feature = "test-util"),
    expect(unreachable_pub, reason = "the integration tests use it")
)]
#[cfg(any(test, feature = "test-util"))]
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

/// The time zone in which ages are worked out when neither the
/// configuration nor the user's `zoneinfo` claim says otherwise: ConnectID
/// serves Australia.
pub(crate) const DEFAULT_TIME_ZONE: &str = "Australia/Sydney";

/// The time zone named [`DEFAULT_TIME_ZONE`].
#[expect(
    clippy::expect_used,
    reason = "the time zone database is compiled in and always has this zone"
)]
pub(crate) fn default_time_zone() -> TimeZone {
    TimeZone::get(DEFAULT_TIME_ZONE).expect("the bundled time zone database has Australia/Sydney")
}

#[derive(Debug, Clone)]
pub(crate) struct User {
    /// Stable internal identifier; clients only ever see a pairwise value
    /// derived from it.
    pub subject: String,
    pub username: String,
    /// `None` for a user who cannot sign in with a password. Such users can
    /// still be selected in the technical experience.
    password_hash: Option<Secret<String>>,
    /// Identity claims, keyed by OpenID Connect claim name.
    pub claims: Map<String, Value>,
    /// Source of the beneficiary account verified claims.
    pub bank_account: Option<BankAccount>,
    /// Where the user's birthdays start: their `zoneinfo` claim, else the
    /// provider's configured `time_zone`.
    time_zone: TimeZone,
}

impl User {
    pub(crate) fn new(
        subject: impl Into<String>,
        username: impl Into<String>,
        password_hash: Option<String>,
        claims: Map<String, Value>,
    ) -> Result<Self> {
        let mut user = Self {
            subject: subject.into(),
            username: username.into(),
            password_hash: password_hash.map(Secret::new),
            time_zone: default_time_zone(),
            claims,
            bank_account: None,
        };
        ensure!(!user.subject.is_empty(), "user subject must not be empty");
        if let Some(birthdate) = user.claims.get("birthdate") {
            ensure!(
                birthdate
                    .as_str()
                    .and_then(crate::claims::parse_date)
                    .is_some(),
                "user '{}': birthdate must be a date as YYYY-MM-DD",
                user.username
            );
        }
        if let Some(zone) = user.zoneinfo() {
            let zone = TimeZone::get(zone).map_err(|e| {
                anyhow!(
                    "user '{}': zoneinfo '{zone}' is not a known time zone: {e}",
                    user.username
                )
            })?;
            user.time_zone = zone;
        }
        ensure!(!user.username.is_empty(), "username must not be empty");
        if let Some(hash) = &user.password_hash {
            PasswordHash::new(hash.expose())
                .map_err(|e| anyhow!("user '{}': invalid password_hash: {e}", user.username))?;
        }
        Ok(user)
    }

    /// The user's `zoneinfo` claim, if they have one.
    fn zoneinfo(&self) -> Option<&str> {
        self.claims.get("zoneinfo").and_then(Value::as_str)
    }

    /// Work out ages in `zone`, unless the user's `zoneinfo` claim names
    /// their own.
    #[must_use]
    pub(crate) fn with_default_time_zone(mut self, zone: &TimeZone) -> Self {
        self.time_zone = self
            .zoneinfo()
            .and_then(|name| TimeZone::get(name).ok())
            .unwrap_or_else(|| zone.clone());
        self
    }

    /// The time zone in which the user's birthdays start.
    pub(crate) fn time_zone(&self) -> &TimeZone {
        &self.time_zone
    }

    /// Attach the user's bank account.
    pub(crate) fn with_bank_account(mut self, account: BankAccount) -> Result<Self> {
        account
            .validate()
            .map_err(|e| anyhow!("user '{}': {e}", self.username))?;
        self.bank_account = Some(account);
        Ok(self)
    }

    pub(crate) fn from_config(config: &UserConfig) -> Result<Self> {
        let user = Self::new(
            &config.subject,
            &config.username,
            config
                .password_hash
                .as_ref()
                .map(|hash| hash.expose().clone()),
            config.claims.clone(),
        )?;
        match &config.bank_account {
            Some(account) => user.with_bank_account(account.clone()),
            None => Ok(user),
        }
    }

    /// A name to show for this user: their `name` claim, else given and
    /// family names, else the username.
    pub(crate) fn display_name(&self) -> String {
        let claim = |name: &str| self.claims.get(name).and_then(Value::as_str);
        if let Some(name) = claim("name") {
            return name.to_owned();
        }
        let parts: Vec<&str> = [claim("given_name"), claim("family_name")]
            .into_iter()
            .flatten()
            .collect();
        if parts.is_empty() {
            self.username.clone()
        } else {
            parts.join(" ")
        }
    }

    /// Whether `password` is this user's. A user without a password never
    /// matches, but the check still costs a full hash verification, so the
    /// response time does not reveal which users have none.
    fn password_matches(&self, password: &str) -> bool {
        let Some(hash) = &self.password_hash else {
            verify_decoy(password);
            return false;
        };
        PasswordHash::new(hash.expose()).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    }
}

/// Verified against when a username is unknown (or its user has no password),
/// so that response time does not reveal which usernames exist. It is the
/// hash of a random password nobody kept, with the same parameters as
/// [`hash_password`]: precomputed so that a cold start does not pay for it.
const DECOY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$TVs5tMgE/FS28BBEu7uI9A$e0EFOYlUFlmAwN2BIP5mQw7FqzrdWnB324v1gBurBM0";

/// Spend what checking a real password costs, and discard the result.
fn verify_decoy(password: &str) {
    if let Ok(hash) = PasswordHash::new(DECOY_HASH) {
        let _ = Argon2::default().verify_password(password.as_bytes(), &hash);
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
pub(crate) trait UserStore: Send + Sync + Debug {
    /// Check credentials. This is deliberately slow (password hashing), so
    /// async callers should run it on a blocking thread.
    fn authenticate(&self, username: &str, password: &str) -> Option<Arc<User>>;

    fn find_by_subject(&self, subject: &str) -> Option<Arc<User>>;

    /// Every user, in a stable order. Used by experiences that let a user be
    /// picked from a list.
    fn list(&self) -> &[Arc<User>];
}

/// A fixed set of users held in memory.
#[derive(Debug)]
pub(crate) struct StaticUserStore {
    by_username: HashMap<String, Arc<User>>,
    /// Users in the order they were defined.
    ordered: Vec<Arc<User>>,
}

impl StaticUserStore {
    pub(crate) fn new(users: impl IntoIterator<Item = User>) -> Result<Self> {
        let mut by_username = HashMap::new();
        let mut ordered = Vec::new();
        let mut subjects = std::collections::HashSet::new();
        for user in users {
            ensure!(
                subjects.insert(user.subject.clone()),
                "duplicate subject '{}'",
                user.subject
            );
            let username = user.username.clone();
            let user = Arc::new(user);
            ordered.push(Arc::clone(&user));
            ensure!(
                by_username.insert(username.clone(), user).is_none(),
                "duplicate username '{username}'"
            );
        }
        Ok(Self {
            by_username,
            ordered,
        })
    }

    /// The configured users, whose ages are worked out in `time_zone`
    /// unless their `zoneinfo` claim says otherwise.
    pub(crate) fn from_config(configs: &[UserConfig], time_zone: &TimeZone) -> Result<Self> {
        Self::new(
            configs
                .iter()
                .map(|config| Ok(User::from_config(config)?.with_default_time_zone(time_zone)))
                .collect::<Result<Vec<_>>>()?,
        )
    }

    /// The built-in customers, used when none are configured. They all
    /// share [`DEMO_PASSWORD`].
    pub(crate) fn demo(time_zone: &TimeZone) -> Result<Self> {
        Self::new(
            demo_users()?
                .into_iter()
                .map(|user| user.with_default_time_zone(time_zone)),
        )
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_username.len()
    }
}

impl UserStore for StaticUserStore {
    fn authenticate(&self, username: &str, password: &str) -> Option<Arc<User>> {
        if let Some(user) = self.by_username.get(username) {
            user.password_matches(password).then(|| Arc::clone(user))
        } else {
            verify_decoy(password);
            None
        }
    }

    fn find_by_subject(&self, subject: &str) -> Option<Arc<User>> {
        self.ordered
            .iter()
            .find(|user| user.subject == subject)
            .cloned()
    }

    fn list(&self) -> &[Arc<User>] {
        &self.ordered
    }
}

/// The built-in customers (`demo_users.toml`), loaded through the same
/// path as configured users.
fn demo_users() -> Result<Vec<User>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DemoUsers {
        users: Vec<UserConfig>,
    }
    let demo: DemoUsers =
        toml::from_str(include_str!("user/demo_users.toml")).context("demo_users.toml")?;
    demo.users.iter().map(User::from_config).collect()
}

#[cfg(test)]
mod tests;
