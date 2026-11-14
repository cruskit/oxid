//! Shared application state.

use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use url::Url;

use crate::client::{ClientRegistry, StaticClientRegistry};
use crate::config::{CiConfig, Config, SecurityConfig, StoreBackend};
use crate::experience::{self, Experience, Kind};
use crate::keys::SigningKey;
use crate::store::{MemoryBackend, Store};
use crate::user::{StaticUserStore, UserStore};
use crate::util::{Clock, SystemClock, random_token};

#[derive(Debug)]
pub struct Inner {
    pub issuer: String,
    pub mtls_base_url: String,
    pub security: SecurityConfig,
    /// Settings of the `ci` experience.
    pub ci: CiConfig,
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
    pub async fn from_config(config: &Config) -> Result<Self> {
        Self::build(config, Arc::new(SystemClock), Vec::new()).await
    }

    /// Everything that happens before the first request: validate the
    /// configuration, load clients from the registry if that is enabled,
    /// and open the store.
    pub async fn start(config: &Config, clock: Option<Arc<dyn Clock>>) -> Result<Self> {
        config.validate()?;
        // Load clients from the registry before accepting any request, so
        // the provider never runs with a partial list.
        let synced_clients = match &config.client_sync {
            Some(sync) if sync.enabled => crate::client_sync::fetch(sync)
                .await
                .context("synchronising clients from the registry")?,
            _ => Vec::new(),
        };
        let clock = clock.unwrap_or_else(|| Arc::new(SystemClock));
        Self::build(config, clock, synced_clients).await
    }

    /// Build the state. `synced_clients` are clients loaded from outside the
    /// configuration file (see [`crate::client_sync`]); they are added to
    /// the configured ones, which win if a client id appears in both.
    pub async fn build(
        config: &Config,
        clock: Arc<dyn Clock>,
        synced_clients: Vec<crate::client::Client>,
    ) -> Result<Self> {
        config.validate()?;

        let store = open_store(config)
            .await?
            .grant_lifetime(config.security.refresh_token_ttl + config.security.access_token_ttl)
            .session_ttl(config.security.session_ttl);
        let shared = config.store.backend != StoreBackend::Memory;

        // Without a configured key, one is generated and kept in the store:
        // every instance sharing the store then signs with the same key.
        let signing_key = if let Some(path) = &config.keys.signing_key {
            SigningKey::from_pem_file(path)?
        } else {
            if shared {
                tracing::info!("keys.signing_key is not set: using the signing key in the store");
            } else {
                tracing::warn!(
                    "keys.signing_key is not set: using an ephemeral signing key (development only)"
                );
            }
            let pem = store
                .secret("signing-key", SigningKey::generate_pem)
                .await
                .context("signing key")?;
            SigningKey::from_pem(pem.as_bytes()).context("signing key held in the store")?
        };

        let mut clients = config
            .clients
            .iter()
            .map(crate::client::Client::from_config)
            .collect::<Result<Vec<_>>>()
            .context("clients")?;
        let configured = clients.len();
        for client in synced_clients {
            if clients.iter().any(|existing| existing.id == client.id) {
                tracing::warn!(
                    client_id = %client.id,
                    "client from the registry is also in the configuration file; \
                     the configured one is used"
                );
            } else {
                clients.push(client);
            }
        }
        tracing::info!(
            configured,
            synced = clients.len() - configured,
            "clients registered"
        );
        let clients = StaticClientRegistry::new(clients).context("clients")?;
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
            if shared {
                tracing::info!("keys.pairwise_salt is not set: using the salt in the store");
            } else {
                tracing::warn!(
                    "keys.pairwise_salt is not set: subject identifiers will change on restart"
                );
            }
            store
                .secret("pairwise-salt", || Ok(random_token(32)))
                .await
                .context("pairwise salt")?
                .into_bytes()
        };

        let users: Arc<dyn UserStore> = Arc::new(users);
        if config.experience == Kind::Technical {
            tracing::warn!(
                "experience is 'technical': anyone who can reach the authorization endpoint \
                 can act as any customer and edit responses (development and testing only)"
            );
        }
        if config.experience == Kind::Ci {
            tracing::warn!(
                response_delay = config.ci.response_delay,
                "experience is 'ci': authorization requests are answered automatically, with \
                 no user and no authentication (automated testing only)"
            );
        }
        tracing::info!(experience = %config.experience, "user experience selected");
        let experience = experience::build(config.experience, Arc::clone(&users));

        Ok(Self(Arc::new(Inner {
            issuer: config.issuer.clone(),
            mtls_base_url: config.mtls_base_url.clone(),
            security: config.security.clone(),
            ci: config.ci.clone(),
            signing_key,
            clients: Arc::new(clients),
            users,
            experience,
            store,
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

#[cfg_attr(not(feature = "aws"), allow(clippy::unused_async))]
async fn open_store(config: &Config) -> Result<Store> {
    match config.store.backend {
        StoreBackend::Memory => Ok(Store::new(Arc::new(MemoryBackend::new()))),
        StoreBackend::Dynamodb => {
            #[cfg(feature = "aws")]
            {
                let backend = crate::store::dynamodb::DynamoBackend::connect(&config.store)
                    .await
                    .context("store")?;
                tracing::info!(
                    table = config.store.table.as_deref().unwrap_or_default(),
                    "state is kept in DynamoDB"
                );
                Ok(Store::new(Arc::new(backend)))
            }
            #[cfg(not(feature = "aws"))]
            {
                anyhow::bail!(
                    "store.backend = \"dynamodb\" needs oxID built with the 'aws' feature"
                )
            }
        }
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
        state_with_ci(kind, CiConfig::default())
    }

    /// As [`state_with`], with the given settings for the `ci` experience.
    pub fn state_with_ci(kind: Kind, ci: CiConfig) -> (AppState, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(NOW));
        let users: Arc<dyn UserStore> = Arc::new(SharedUsers);
        let clients = StaticClientRegistry::new([client_with_key("rp", shared_key())]).unwrap();
        let state = AppState(Arc::new(Inner {
            issuer: ISSUER.to_owned(),
            mtls_base_url: MTLS.to_owned(),
            security: SecurityConfig::default(),
            ci,
            signing_key: SigningKey::generate().unwrap(),
            clients: Arc::new(clients),
            experience: experience::build(kind, Arc::clone(&users)),
            users,
            store: Store::default(),
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

    #[tokio::test]
    async fn builds_from_minimal_config_with_development_fallbacks() {
        let state = AppState::from_config(&config("")).await.unwrap();
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

    #[tokio::test]
    async fn configured_salt_is_used_verbatim() {
        let state = AppState::from_config(&config("[keys]\npairwise_salt = \"0123456789abcdef\""))
            .await
            .unwrap();
        assert_eq!(state.pairwise_salt, b"0123456789abcdef");
    }

    #[tokio::test]
    async fn invalid_config_is_rejected() {
        let mut bad = config("");
        bad.security.access_token_ttl = 3600;
        assert!(AppState::from_config(&bad).await.is_err());

        let missing_key = config("[keys]\nsigning_key = \"/nonexistent/key.pem\"");
        assert!(AppState::from_config(&missing_key).await.is_err());
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
