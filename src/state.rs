//! Shared application state.

use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use url::Url;

use crate::client::{ClientRegistry, StaticClientRegistry};
use crate::config::{Config, SecurityConfig};
use crate::experience::{self, Experience, Kind};
use crate::keys::SigningKey;
use crate::store::Store;
use crate::user::{StaticUserStore, UserStore};
use crate::util::{Clock, SystemClock, random_token};

#[derive(Debug)]
pub struct Inner {
    pub issuer: String,
    pub mtls_base_url: String,
    pub security: SecurityConfig,
    pub signing_key: SigningKey,
    pub clients: Arc<dyn ClientRegistry>,
    pub users: Arc<dyn UserStore>,
    /// The user experience at the authorization endpoint.
    pub experience: Arc<dyn Experience>,
    pub store: Store,
    pub clock: Arc<dyn Clock>,
    pub pairwise_salt: Vec<u8>,
}

/// Cheaply cloneable handle to the provider's state.
#[derive(Debug, Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn from_config(config: &Config) -> Result<Self> {
        Self::from_config_with_clock(config, Arc::new(SystemClock))
    }

    pub fn from_config_with_clock(config: &Config, clock: Arc<dyn Clock>) -> Result<Self> {
        config.validate()?;

        let signing_key = if let Some(path) = &config.keys.signing_key {
            SigningKey::from_pem_file(path)?
        } else {
            tracing::warn!(
                "keys.signing_key is not set: using an ephemeral signing key (development only)"
            );
            SigningKey::generate()?
        };

        let clients = StaticClientRegistry::from_config(&config.clients).context("clients")?;
        if clients.is_empty() {
            tracing::warn!("no clients are configured; no client will be able to authenticate");
        }

        let users = if config.users.is_empty() {
            tracing::warn!(
                "no users are configured: using the built-in demo customers (development only)"
            );
            StaticUserStore::demo()?
        } else {
            StaticUserStore::from_config(&config.users).context("users")?
        };

        let pairwise_salt = if let Some(salt) = &config.keys.pairwise_salt {
            salt.clone().into_bytes()
        } else {
            tracing::warn!(
                "keys.pairwise_salt is not set: subject identifiers will change on restart"
            );
            random_token(32).into_bytes()
        };

        let users: Arc<dyn UserStore> = Arc::new(users);
        if config.experience == Kind::Technical {
            tracing::warn!(
                "experience is 'technical': anyone who can reach the authorization endpoint \
                 can act as any customer and edit responses (development and testing only)"
            );
        }
        tracing::info!(experience = %config.experience, "user experience selected");
        let experience = experience::build(config.experience, Arc::clone(&users));

        Ok(Self(Arc::new(Inner {
            issuer: config.issuer.clone(),
            mtls_base_url: config.mtls_base_url.clone(),
            security: config.security.clone(),
            signing_key,
            clients: Arc::new(clients),
            users,
            experience,
            store: Store::new(),
            clock,
            pairwise_salt,
        })))
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// URL of an endpoint on the public listener.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    /// URL of an endpoint on the mTLS listener.
    pub fn mtls_url(&self, path: &str) -> String {
        format!("{}{path}", self.mtls_base_url)
    }
}

/// Host names a self-signed development certificate should cover.
pub fn certificate_names(config: &Config) -> Vec<String> {
    let mut names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    for base in [&config.issuer, &config.mtls_base_url] {
        if let Some(host) = Url::parse(base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            && !names.contains(&host)
        {
            names.push(host);
        }
    }
    names
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use super::*;
    use crate::client::test_support::client_with_key;
    use crate::keys::test_support::shared_key;
    use crate::user::test_support::demo_store;
    use crate::util::ManualClock;

    pub const ISSUER: &str = "https://op.example.com";
    pub const MTLS: &str = "https://mtls.op.example.com";
    pub const NOW: i64 = 1_800_000_000;

    #[derive(Debug)]
    struct SharedUsers;

    impl UserStore for SharedUsers {
        fn authenticate(&self, username: &str, password: &str) -> Option<Arc<crate::user::User>> {
            demo_store().authenticate(username, password)
        }

        fn find_by_subject(&self, subject: &str) -> Option<Arc<crate::user::User>> {
            demo_store().find_by_subject(subject)
        }

        fn list(&self) -> Vec<Arc<crate::user::User>> {
            demo_store().list()
        }
    }

    /// State with client `rp` (keyed by the shared test key), the demo user
    /// and a manual clock at [`NOW`]. The client and the provider share one
    /// key purely to keep tests fast.
    pub fn state() -> (AppState, Arc<ManualClock>) {
        state_with(Kind::Login)
    }

    /// As [`state`], with the given user experience.
    pub fn state_with(kind: Kind) -> (AppState, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(NOW));
        let users: Arc<dyn UserStore> = Arc::new(SharedUsers);
        let clients = StaticClientRegistry::new([client_with_key("rp", shared_key())]).unwrap();
        let state = AppState(Arc::new(Inner {
            issuer: ISSUER.to_owned(),
            mtls_base_url: MTLS.to_owned(),
            security: SecurityConfig::default(),
            signing_key: SigningKey::generate().unwrap(),
            clients: Arc::new(clients),
            experience: experience::build(kind, Arc::clone(&users)),
            users,
            store: Store::new(),
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            pairwise_salt: b"unit-test-pairwise-salt".to_vec(),
        }));
        (state, clock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        toml::from_str(&format!(
            "issuer = \"https://op.example.com:9443\"\nmtls_base_url = \"https://mtls.example.com:9444\"\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn builds_from_minimal_config_with_development_fallbacks() {
        let state = AppState::from_config(&config("")).unwrap();
        assert_eq!(state.url("/token"), "https://op.example.com:9443/token");
        assert_eq!(
            state.mtls_url("/token"),
            "https://mtls.example.com:9444/token"
        );
        assert!(
            state
                .users
                .authenticate(crate::user::DEMO_USERNAME, crate::user::DEMO_PASSWORD)
                .is_some()
        );
        assert!(state.clients.get("anything").is_none());
        assert!(state.now() > 1_704_067_200);
    }

    #[test]
    fn configured_salt_is_used_verbatim() {
        let state =
            AppState::from_config(&config("[keys]\npairwise_salt = \"0123456789abcdef\"")).unwrap();
        assert_eq!(state.pairwise_salt, b"0123456789abcdef");
    }

    #[test]
    fn invalid_config_is_rejected() {
        let mut bad = config("");
        bad.security.access_token_ttl = 3600;
        assert!(AppState::from_config(&bad).is_err());

        let missing_key = config("[keys]\nsigning_key = \"/nonexistent/key.pem\"");
        assert!(AppState::from_config(&missing_key).is_err());
    }

    #[test]
    fn certificate_names_include_configured_hosts_once() {
        let names = certificate_names(&config(""));
        assert_eq!(
            names,
            [
                "localhost",
                "127.0.0.1",
                "op.example.com",
                "mtls.example.com"
            ]
        );
        let local: Config = toml::from_str(
            "issuer = \"https://localhost:9443\"\nmtls_base_url = \"https://localhost:9444\"",
        )
        .unwrap();
        assert_eq!(certificate_names(&local), ["localhost", "127.0.0.1"]);
    }
}
