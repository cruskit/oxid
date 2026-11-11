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

        Ok(Self {
            id: id.to_owned(),
            name: config.client_name.clone().unwrap_or_else(|| id.to_owned()),
            redirect_uris: config.redirect_uris.clone(),
            jwks,
            scopes: config.scopes.iter().cloned().collect(),
            grant_types,
            sector_identifier,
        })
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
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::keys::SigningKey;

    /// A client whose JWK Set holds `key`'s public half.
    pub fn client_with_key(id: &str, key: &SigningKey) -> Client {
        Client::from_config(&ClientConfig {
            client_id: id.to_owned(),
            client_name: Some("Test RP".to_owned()),
            redirect_uris: vec!["https://rp.example.com/cb".to_owned()],
            jwks_file: None,
            jwks: Some(key.jwks()),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            grant_types: vec![
                GRANT_AUTHORIZATION_CODE.to_owned(),
                GRANT_REFRESH_TOKEN.to_owned(),
            ],
            sector_identifier: None,
        })
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::test_support::shared_key;

    fn config() -> ClientConfig {
        ClientConfig {
            client_id: "rp".to_owned(),
            client_name: None,
            redirect_uris: vec!["https://rp.example.com/cb".to_owned()],
            jwks_file: None,
            jwks: Some(shared_key().jwks()),
            scopes: vec!["openid".to_owned()],
            grant_types: vec![GRANT_AUTHORIZATION_CODE.to_owned()],
            sector_identifier: None,
        }
    }

    #[test]
    fn builds_a_client_with_derived_defaults() {
        let client = Client::from_config(&config()).unwrap();
        assert_eq!(client.name, "rp");
        assert_eq!(client.sector_identifier, "rp.example.com");
        assert!(!client.allows_refresh_tokens());
    }

    #[test]
    fn redirect_uri_matching_is_exact() {
        let client = Client::from_config(&config()).unwrap();
        assert!(client.has_redirect_uri("https://rp.example.com/cb"));
        assert!(!client.has_redirect_uri("https://rp.example.com/cb/"));
        assert!(!client.has_redirect_uri("https://rp.example.com/cb?x=1"));
        assert!(!client.has_redirect_uri("https://RP.example.com/cb"));
    }

    #[test]
    fn rejects_insecure_or_malformed_redirect_uris() {
        for bad in [
            "http://rp.example.com/cb",
            "https://rp.example.com/cb#frag",
            "custom-scheme://cb",
            "http://localhost/cb",
            "not a url",
        ] {
            let mut c = config();
            c.redirect_uris = vec![bad.to_owned()];
            assert!(Client::from_config(&c).is_err(), "{bad}");
        }
    }

    #[test]
    fn loopback_http_is_allowed_for_native_clients() {
        let mut c = config();
        c.redirect_uris = vec!["http://127.0.0.1:8123/cb".to_owned()];
        Client::from_config(&c).unwrap();
    }

    #[test]
    fn several_redirect_hosts_need_an_explicit_sector() {
        let mut c = config();
        c.redirect_uris
            .push("https://other.example.com/cb".to_owned());
        assert!(Client::from_config(&c).is_err());
        c.sector_identifier = Some("rp.example.com".to_owned());
        assert_eq!(
            Client::from_config(&c).unwrap().sector_identifier,
            "rp.example.com"
        );
    }

    #[test]
    fn needs_keys_and_supported_grants() {
        let mut no_keys = config();
        no_keys.jwks = None;
        assert!(Client::from_config(&no_keys).is_err());

        let mut empty_keys = config();
        empty_keys.jwks = Some(JwkSet { keys: vec![] });
        assert!(Client::from_config(&empty_keys).is_err());

        let mut password_grant = config();
        password_grant.grant_types.push("password".to_owned());
        assert!(Client::from_config(&password_grant).is_err());

        let mut refresh_only = config();
        refresh_only.grant_types = vec![GRANT_REFRESH_TOKEN.to_owned()];
        assert!(Client::from_config(&refresh_only).is_err());

        let mut no_redirects = config();
        no_redirects.redirect_uris.clear();
        assert!(Client::from_config(&no_redirects).is_err());
    }

    #[test]
    fn registry_looks_up_by_id_and_rejects_duplicates() {
        let registry = StaticClientRegistry::from_config(&[config()]).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("rp").is_some());
        assert!(registry.get("unknown").is_none());
        assert!(StaticClientRegistry::from_config(&[config(), config()]).is_err());
    }
}
