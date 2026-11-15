//! Shared application state.

use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::client::{ClientRegistry, StaticClientRegistry};
use crate::epoch::Timestamp;
use crate::config::{BaseUrl, CiConfig, Config, SecurityConfig, StoreBackend};
use crate::experience::{self, Experience, Kind};
use crate::keys::SigningKey;
use crate::store::{MemoryBackend, Store};
use crate::theme::Theme;
use crate::user::{StaticUserStore, UserStore};
use crate::util::{Clock, Secret, SystemClock, random_token};

#[derive(Debug)]
pub(crate) struct Inner {
    pub issuer: BaseUrl,
    pub mtls_base_url: BaseUrl,
    pub security: SecurityConfig,
    /// Settings of the `ci` experience.
    pub ci: CiConfig,
    pub signing_key: SigningKey,
    pub clients: Arc<dyn ClientRegistry>,
    pub users: Arc<dyn UserStore>,
    /// The user experience at the authorization endpoint.
    pub experience: Arc<dyn Experience>,
    /// The name, logo and colours of the pages users see.
    pub theme: Theme,
    pub store: Store,
    pub clock: Arc<dyn Clock>,
    pub pairwise_salt: Secret<Vec<u8>>,
}

/// Cheaply cloneable handle to the provider's state.
#[derive(Debug, Clone)]
pub(crate) struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    #[cfg(test)]
    pub(crate) async fn from_config(config: &Config) -> Result<Self> {
        Self::build(config, Arc::new(SystemClock), Vec::new()).await
    }

    /// Everything that happens before the first request: load clients from
    /// the registry if that is enabled, and open the store. The
    /// configuration was validated when the [`Config`] was made.
    pub(crate) async fn start(config: &Config, clock: Option<Arc<dyn Clock>>) -> Result<Self> {
        // Load clients from the registry before accepting any request, so
        // the provider never runs with a partial list.
        let clock = clock.unwrap_or_else(|| Arc::new(SystemClock));
        let synced_clients = match &config.client_sync {
            Some(sync) if sync.enabled => crate::client_sync::fetch(sync, clock.as_ref())
                .await
                .context("synchronising clients from the registry")?,
            _ => Vec::new(),
        };
        Self::build(config, clock, synced_clients).await
    }

    /// Build the state. `synced_clients` are clients loaded from outside the
    /// configuration file (see [`crate::client_sync`]); they are added to
    /// the configured ones, which win if a client id appears in both.
    pub(crate) async fn build(
        config: &Config,
        clock: Arc<dyn Clock>,
        synced_clients: Vec<crate::client::Client>,
    ) -> Result<Self> {
        let store = configure_store(open_store(config).await?, config);
        let parts = Parts {
            signing_key: load_signing_key(config, &store).await?,
            clients: load_clients(config, synced_clients)?,
            users: load_users(config)?,
            pairwise_salt: load_salt(config, &store).await?,
            store,
            clock,
        };
        log_experience(config);
        tracing::info!(
            name = %config.theme.name,
            logo = config.theme.has_logo(),
            "theme loaded"
        );
        Ok(Self::assemble(config, parts))
    }

    /// The state for `config` and `parts`. The only place [`Inner`] is
    /// built, so a new field is added here once; the unit test fixture comes
    /// through here too, with parts of its own.
    pub(crate) fn assemble(config: &Config, parts: Parts) -> Self {
        let Parts {
            signing_key,
            clients,
            users,
            pairwise_salt,
            store,
            clock,
        } = parts;
        Self(Arc::new(Inner {
            issuer: config.issuer.clone(),
            mtls_base_url: config.mtls_base_url.clone(),
            security: config.security.clone(),
            ci: config.ci.clone(),
            signing_key,
            clients: Arc::new(clients),
            experience: experience::build(config.experience, Arc::clone(&users)),
            users,
            theme: config.theme.clone(),
            store,
            clock,
            pairwise_salt,
        }))
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// What issuing tokens needs, as of now.
    pub(crate) fn issuer_context(&self) -> crate::id_token::IssuerContext<'_> {
        crate::id_token::IssuerContext {
            issuer: &self.issuer,
            signing_key: &self.signing_key,
            pairwise_salt: self.pairwise_salt.expose(),
            id_token_ttl: self.security.id_token_ttl,
            now: self.now(),
        }
    }

    /// URL of an endpoint on the public listener.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    /// URL of an endpoint on the mTLS listener.
    pub(crate) fn mtls_url(&self, path: &str) -> String {
        format!("{}{path}", self.mtls_base_url)
    }
}

/// What [`AppState::assemble`] needs besides the configuration: the parts
/// that are loaded, generated or (in tests) made up.
pub(crate) struct Parts {
    pub signing_key: SigningKey,
    pub clients: StaticClientRegistry,
    pub users: Arc<dyn UserStore>,
    pub pairwise_salt: Secret<Vec<u8>>,
    pub store: Store,
    pub clock: Arc<dyn Clock>,
}

/// Give the store the lifetimes the configuration sets.
pub(crate) fn configure_store(store: Store, config: &Config) -> Store {
    store
        .grant_lifetime(config.security.refresh_token_ttl + config.security.access_token_ttl)
        .session_ttl(config.security.session_ttl)
        .consent_retention(config.store.consent_retention())
}

fn store_is_shared(config: &Config) -> bool {
    config.store.backend != StoreBackend::Memory
}

/// The configured signing key or, without one, the key kept in the store
/// (generated on first use): every instance sharing the store then signs
/// with the same key.
async fn load_signing_key(config: &Config, store: &Store) -> Result<SigningKey> {
    if let Some(path) = &config.keys.signing_key {
        return SigningKey::from_pem_file(path);
    }
    if store_is_shared(config) {
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
    SigningKey::from_pem(pem.as_bytes()).context("signing key held in the store")
}

/// The configured clients, then those from the registry that are not also
/// configured.
fn load_clients(
    config: &Config,
    synced_clients: Vec<crate::client::Client>,
) -> Result<StaticClientRegistry> {
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
    Ok(clients)
}

/// The configured users or, without any, the built-in demo customers.
fn load_users(config: &Config) -> Result<Arc<dyn UserStore>> {
    let time_zone = &config.time_zone;
    let users = if config.users.is_empty() {
        tracing::warn!(
            "no users are configured: using the built-in demo customers (development only)"
        );
        StaticUserStore::demo(time_zone)?
    } else {
        StaticUserStore::from_config(&config.users, time_zone).context("users")?
    };
    Ok(Arc::new(users))
}

/// The configured pairwise salt or, without one, the salt kept in the store.
async fn load_salt(config: &Config, store: &Store) -> Result<Secret<Vec<u8>>> {
    if let Some(salt) = &config.keys.pairwise_salt {
        return Ok(Secret::new(salt.expose().clone().into_bytes()));
    }
    if store_is_shared(config) {
        tracing::info!("keys.pairwise_salt is not set: using the salt in the store");
    } else {
        tracing::warn!("keys.pairwise_salt is not set: subject identifiers will change on restart");
    }
    store
        .secret("pairwise-salt", || Ok(random_token(32)))
        .await
        .context("pairwise salt")
        .map(|salt| Secret::new(salt.into_bytes()))
}

/// The startup warnings the unauthenticated experiences must give.
fn log_experience(config: &Config) {
    if config.experience == Kind::Technical {
        tracing::warn!(
            "experience is 'technical': anyone who can reach the authorization endpoint \
             can act as any customer and edit responses (development and testing only)"
        );
    }
    if config.experience == Kind::Ci {
        tracing::warn!(
            response_delay = config.ci.response_delay.get(),
            "experience is 'ci': authorization requests are answered automatically, with \
             no user and no authentication (automated testing only)"
        );
    }
    tracing::info!(experience = %config.experience, "user experience selected");
}

#[cfg_attr(
    not(feature = "aws"),
    expect(clippy::unused_async, reason = "awaits only the DynamoDB backend")
)]
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
pub(crate) fn certificate_names(config: &Config) -> Vec<String> {
    let mut names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    for base in [&config.issuer, &config.mtls_base_url] {
        if let Some(host) = base.host()
            && !names.iter().any(|name| name == host)
        {
            names.push(host.to_owned());
        }
    }
    names
}

#[cfg(test)]
mod tests;
