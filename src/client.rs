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
            // A second scope, so scope handling can be exercised. Scopes
            // other than `openid` imply no claims.
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            grant_types: vec![
                GRANT_AUTHORIZATION_CODE.to_owned(),
                GRANT_REFRESH_TOKEN.to_owned(),
            ],
            sector_identifier: None,
            profile: Profile::Connectid,
            claims: None,
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
            profile: Profile::Connectid,
            claims: None,
        }
    }

    #[test]
    fn claims_default_to_everything_and_can_be_restricted() {
        let open = Client::from_config(&config()).unwrap();
        assert!(open.allows_claim("email") && open.allows_claim("beneficiary_account_au"));

        let mut c = config();
        c.claims = Some(vec!["given_name".to_owned(), "over18".to_owned()]);
        let limited = Client::from_config(&c).unwrap();
        assert!(limited.allows_claim("given_name") && limited.allows_claim("over18"));
        assert!(!limited.allows_claim("email") && !limited.allows_claim("over21"));

        c.claims = Some(vec![]);
        assert!(!Client::from_config(&c).unwrap().allows_claim("given_name"));

        c.claims = Some(vec!["nickname".to_owned()]);
        let err = Client::from_config(&c).unwrap_err().to_string();
        assert!(err.contains("nickname"), "{err}");

        // The same list is fine for a standard OpenID Connect client, which
        // in turn has no ConnectID verified claims.
        c.profile = Profile::Oidc;
        let oidc = Client::from_config(&c).unwrap();
        assert!(oidc.allows_claim("nickname") && !oidc.allows_claim("email"));
        c.claims = None;
        let oidc = Client::from_config(&c).unwrap();
        assert!(oidc.allows_claim("name") && oidc.allows_claim("email_verified"));
        assert!(!oidc.allows_claim("over18"));
        assert!(!open.allows_claim("name"), "not a ConnectID claim");
        c.claims = Some(vec!["over18".to_owned()]);
        assert!(Client::from_config(&c).is_err());
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

        assert_eq!(registry.profiles(), BTreeSet::from([Profile::Connectid]));
        let mut oidc = config();
        oidc.client_id = "rp2".to_owned();
        oidc.profile = Profile::Oidc;
        let mixed = StaticClientRegistry::from_config(&[config(), oidc]).unwrap();
        assert_eq!(
            mixed.profiles(),
            BTreeSet::from([Profile::Connectid, Profile::Oidc])
        );
        assert_eq!(
            StaticClientRegistry::default().profiles(),
            BTreeSet::from([Profile::Connectid])
        );
    }
}
