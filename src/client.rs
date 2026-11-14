//! Registered clients.
//!
//! This version ships a static registry populated from configuration. The
//! [`ClientRegistry`] trait is the seam where dynamic registration or a
//! database-backed registry will plug in later.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use jsonwebtoken::jwk::JwkSet;
use url::Url;

use crate::config::ClientConfig;

pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";

/// Which set of identity claims a client works with. The security profile
/// (FAPI 2.0 with the ConnectID restrictions) is the same for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// The ConnectID Identity Assurance Profile: its standard claims and
    /// `verified_claims`, requested with the `claims` parameter only.
    #[default]
    Connectid,
    /// Standard `OpenID` Connect: every claim of Core §5.1, requested with
    /// the `claims` parameter or the claim scopes.
    Oidc,
}

/// A confidential client. FAPI 2.0 §5.3.2.1-3 permits no other kind.
#[derive(Debug, Clone)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// Public keys for `private_key_jwt` and request object verification.
    pub jwks: JwkSet,
    pub scopes: BTreeSet<String>,
    pub grant_types: BTreeSet<String>,
    /// Host that scopes this client's pairwise subject identifiers.
    pub sector_identifier: String,
    pub profile: Profile,
    /// Claims this client is provisioned to receive (ConnectID identity
    /// assurance §5.1), within its profile. `None` allows every claim of
    /// the profile.
    pub claims: Option<BTreeSet<String>>,
}

impl Client {
    pub fn from_config(config: &ClientConfig) -> Result<Self> {
        let id = config.client_id.trim();
        ensure!(!id.is_empty(), "client_id must not be empty");
        ensure!(
            !config.redirect_uris.is_empty(),
            "client '{id}' has no redirect_uris"
        );

        let mut hosts = BTreeSet::new();
        for uri in &config.redirect_uris {
            hosts.insert(validate_redirect_uri(uri).with_context(|| format!("client '{id}'"))?);
        }
        let sector_identifier = match (&config.sector_identifier, hosts.len()) {
            (Some(explicit), _) => explicit.clone(),
            (None, 1) => hosts.into_iter().next().unwrap_or_default(),
            (None, _) => {
                bail!("client '{id}' has redirect_uris on several hosts; set sector_identifier")
            }
        };

        let jwks = match (&config.jwks, &config.jwks_file) {
            (Some(jwks), None) => jwks.clone(),
            (None, Some(path)) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing {}", path.display()))?
            }
            _ => bail!("client '{id}' needs exactly one of jwks or jwks_file"),
        };
        ensure!(!jwks.keys.is_empty(), "client '{id}' has an empty JWK Set");

        let grant_types: BTreeSet<String> = config.grant_types.iter().cloned().collect();
        for grant in &grant_types {
            ensure!(
                grant == GRANT_AUTHORIZATION_CODE || grant == GRANT_REFRESH_TOKEN,
                "client '{id}': unsupported grant type '{grant}'"
            );
        }
        ensure!(
            grant_types.contains(GRANT_AUTHORIZATION_CODE),
            "client '{id}' must allow the authorization_code grant"
        );

        if let Some(unknown) = config
            .claims
            .iter()
            .flatten()
            .find(|name| !crate::claims::profile_allows(config.profile, name))
        {
            bail!("client '{id}': claim '{unknown}' is not available under its profile");
        }

        Ok(Self {
            id: id.to_owned(),
            name: config.client_name.clone().unwrap_or_else(|| id.to_owned()),
            redirect_uris: config.redirect_uris.clone(),
            jwks,
            scopes: config.scopes.iter().cloned().collect(),
            grant_types,
            sector_identifier,
            profile: config.profile,
            claims: config
                .claims
                .as_ref()
                .map(|claims| claims.iter().cloned().collect()),
        })
    }

    /// Whether this client may be given the claim `name`: its profile must
    /// define the claim and the client must be provisioned for it.
    pub fn allows_claim(&self, name: &str) -> bool {
        crate::claims::profile_allows(self.profile, name)
            && self
                .claims
                .as_ref()
                .is_none_or(|allowed| allowed.contains(name))
    }

    /// Exact string comparison, as required by RFC 9700 §2.1.
    pub fn has_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered == uri)
    }

    pub fn allows_refresh_tokens(&self) -> bool {
        self.grant_types.contains(GRANT_REFRESH_TOKEN)
    }
}

/// Validate a redirect URI and return its host.
///
/// FAPI 2.0 §5.3.2.2-8: only `https`, except loopback `http` for native apps.
fn validate_redirect_uri(uri: &str) -> Result<String> {
    let url = Url::parse(uri).with_context(|| format!("redirect_uri '{uri}' is not a URL"))?;
    ensure!(
        url.fragment().is_none(),
        "redirect_uri '{uri}' must not have a fragment"
    );
    let host = url.host_str().unwrap_or_default().to_owned();
    ensure!(!host.is_empty(), "redirect_uri '{uri}' must have a host");
    let loopback = matches!(host.as_str(), "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!("redirect_uri '{uri}' must use https"),
    }
    Ok(host)
}

/// Lookup of registered clients.
pub trait ClientRegistry: Send + Sync + Debug {
    fn get(&self, client_id: &str) -> Option<Arc<Client>>;

    /// The profiles registered clients use. Discovery advertises the claims
    /// and scopes of these profiles only, so a deployment serving ConnectID
    /// clients alone advertises exactly the ConnectID claims.
    fn profiles(&self) -> BTreeSet<Profile>;
}

/// A fixed set of clients held in memory.
#[derive(Debug, Default)]
pub struct StaticClientRegistry {
    clients: HashMap<String, Arc<Client>>,
}

impl StaticClientRegistry {
    pub fn new(clients: impl IntoIterator<Item = Client>) -> Result<Self> {
        let mut map = HashMap::new();
        for client in clients {
            let id = client.id.clone();
            ensure!(
                map.insert(id.clone(), Arc::new(client)).is_none(),
                "duplicate client_id '{id}'"
            );
        }
        Ok(Self { clients: map })
    }

    pub fn from_config(configs: &[ClientConfig]) -> Result<Self> {
        let clients = configs
            .iter()
            .map(Client::from_config)
            .collect::<Result<Vec<_>>>()?;
        Self::new(clients)
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

impl ClientRegistry for StaticClientRegistry {
    fn get(&self, client_id: &str) -> Option<Arc<Client>> {
        self.clients.get(client_id).cloned()
    }

    fn profiles(&self) -> BTreeSet<Profile> {
        if self.clients.is_empty() {
            return BTreeSet::from([Profile::default()]);
        }
        self.clients.values().map(|client| client.profile).collect()
    }
}

#[cfg(test)]
mod tests;
