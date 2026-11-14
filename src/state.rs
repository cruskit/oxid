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
use crate::theme::Theme;
use crate::user::{StaticUserStore, UserStore};
use crate::util::{Clock, Secret, SystemClock, random_token};

#[derive(Debug)]
pub(crate) struct Inner {
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
    /// Wrap already-built state. Unit test fixtures build [`Inner`] directly.
    #[cfg(test)]
    pub(crate) fn from_inner(inner: Inner) -> Self {
        Self(Arc::new(inner))
    }

    #[cfg(test)]
    pub(crate) async fn from_config(config: &Config) -> Result<Self> {
        Self::build(config, Arc::new(SystemClock), Vec::new()).await
    }

    /// Everything that happens before the first request: validate the
    /// configuration, load clients from the registry if that is enabled,
    /// and open the store.
    pub(crate) async fn start(config: &Config, clock: Option<Arc<dyn Clock>>) -> Result<Self> {
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
    pub(crate) async fn build(
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

        let time_zone = jiff::tz::TimeZone::get(&config.time_zone)
            .with_context(|| format!("time_zone '{}'", config.time_zone))?;
        let users = if config.users.is_empty() {
            tracing::warn!(
                "no users are configured: using the built-in demo customers (development only)"
            );
            StaticUserStore::demo(&time_zone)?
        } else {
            StaticUserStore::from_config(&config.users, &time_zone).context("users")?
        };

        let pairwise_salt = if let Some(salt) = &config.keys.pairwise_salt {
            Secret::new(salt.expose().clone().into_bytes())
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
                .context("pairwise salt")
                .map(|salt| Secret::new(salt.into_bytes()))?
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

        let theme = Theme::from_config(&config.theme).context("theme")?;
        tracing::info!(
            name = %theme.name,
            logo = theme.has_logo(),
            "theme loaded"
        );

        Ok(Self(Arc::new(Inner {
            issuer: config.issuer.clone(),
            mtls_base_url: config.mtls_base_url.clone(),
            security: config.security.clone(),
            ci: config.ci.clone(),
            signing_key,
            clients: Arc::new(clients),
            users,
            experience,
            theme,
            store,
            clock,
            pairwise_salt,
        })))
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now()
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
mod tests;
