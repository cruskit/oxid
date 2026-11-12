//! Loading relying party clients from the ConnectID registry.
//!
//! ConnectID identity providers do not register clients themselves: they
//! copy them from the scheme's registry (ConnectID Client Registration
//! §6.1). This module does that once, at startup:
//!
//! 1. obtain an access token from the registry's token endpoint with the
//!    client credentials grant, authenticating with `private_key_jwt` over
//!    mutual TLS (the endpoint advertised in `mtls_endpoint_aliases`);
//! 2. `GET` the clients endpoint with that token, over mutual TLS, asking
//!    for `page` 0, 1, 2... until the `totalPages` it reports have all been
//!    read;
//! 3. turn each active entry into a [`Client`], fetching its keys from its
//!    `jwks_uri`.
//!
//! The clients found are added to those in the configuration file. A
//! registry that cannot be reached, or that refuses the request, stops the
//! provider from starting: running with a partial client list would be worse
//! than not running. A single malformed entry is logged and skipped.
//!
//! Periodic refresh (of the list, and of each client's keys) is not done
//! yet.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use jsonwebtoken::jwk::JwkSet;
use reqwest::header::ACCEPT;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::client::{Client, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN, Profile};
use crate::client_auth::ASSERTION_TYPE;
use crate::config::ClientConfig;
use crate::keys::SigningKey;
use crate::util::random_token;

/// Time allowed for each request to the registry.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on pages read, as a guard against a pagination loop.
const MAX_PAGES: u32 = 10_000;
/// Client key sets fetched at the same time.
const JWKS_CONCURRENCY: usize = 8;

/// `[client_sync]` in the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSyncConfig {
    /// Whether to synchronise at startup. The section can be left in place
    /// and switched off.
    #[serde(default)]
    pub enabled: bool,
    /// The registry authorization server's metadata document. The token
    /// endpoint is taken from its `mtls_endpoint_aliases`, and the client
    /// assertion audience from its `issuer`.
    pub discovery_url: Option<String>,
    /// The registry's mutual TLS token endpoint, if not using discovery.
    pub token_endpoint: Option<String>,
    /// Audience of the client assertion. Defaults to the discovered issuer,
    /// or to the token endpoint when discovery is not used.
    pub audience: Option<String>,
    /// The registry's clients endpoint.
    pub clients_url: String,
    /// This provider's client id at the registry.
    pub client_id: String,
    /// Scope to request for the access token.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// PEM certificate (chain) presented to the registry for mutual TLS.
    pub transport_cert: PathBuf,
    /// PEM private key for `transport_cert`.
    pub transport_key: PathBuf,
    /// PEM RSA private key that signs the client assertion (PS256).
    pub signing_key: PathBuf,
    /// The `kid` the registry knows the signing key by.
    pub signing_key_id: String,
    /// PEM bundle of extra certificate authorities to trust when talking to
    /// the registry and the client key stores, in addition to the system's.
    pub ca: Option<PathBuf>,
    /// The `size` to ask the clients endpoint for: the most results on one
    /// page.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// The claims profile given to synchronised clients.
    #[serde(default)]
    pub profile: Profile,
}

fn default_scope() -> String {
    "directory:software".to_owned()
}

/// The registry's own default.
fn default_page_size() -> u32 {
    50
}

impl ClientSyncConfig {
    pub fn validate(&self) -> Result<()> {
        let https = |name: &str, value: &str| -> Result<()> {
            let url = Url::parse(value).with_context(|| format!("{name} is not a URL"))?;
            ensure!(url.scheme() == "https", "{name} must use https");
            Ok(())
        };
        ensure!(
            self.discovery_url.is_some() || self.token_endpoint.is_some(),
            "set discovery_url or token_endpoint"
        );
        if let Some(url) = &self.discovery_url {
            https("discovery_url", url)?;
        }
        if let Some(url) = &self.token_endpoint {
            https("token_endpoint", url)?;
        }
        https("clients_url", &self.clients_url)?;
        ensure!(!self.client_id.trim().is_empty(), "client_id is empty");
        ensure!(
            !self.signing_key_id.trim().is_empty(),
            "signing_key_id is empty"
        );
        ensure!(
            (1..=1000).contains(&self.page_size),
            "page_size must be between 1 and 1000"
        );
        Ok(())
    }
}

/// Fetch every client from the registry.
pub async fn fetch(config: &ClientSyncConfig) -> Result<Vec<Client>> {
    config.validate()?;
    let signing_key = SigningKey::from_pem_file(&config.signing_key)?;
    let mtls = http_client(config, true)?;
    let plain = http_client(config, false)?;

    let (token_endpoint, audience) = token_endpoint(config, &mtls).await?;
    tracing::info!(%token_endpoint, clients_url = %config.clients_url, "synchronising clients from the registry");
    let access_token =
        access_token(config, &mtls, &signing_key, &token_endpoint, &audience).await?;
    let entries = all_pages(config, &mtls, &access_token).await?;
    let found = entries.len();

    let clients = build_clients(config, &plain, entries).await;
    tracing::info!(
        found,
        registered = clients.len(),
        skipped = found - clients.len(),
        "client synchronisation finished"
    );
    Ok(clients)
}

/// An HTTP client for the registry. With `mutual_tls`, it presents the
/// transport certificate.
fn http_client(config: &ClientSyncConfig, mutual_tls: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("oxid/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = &config.ca {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parsing {}", path.display()))?;
        ensure!(
            !certificates.is_empty(),
            "{} has no certificates",
            path.display()
        );
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    if mutual_tls {
        let read = |path: &PathBuf| {
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))
        };
        let mut pem = read(&config.transport_cert)?;
        pem.push(b'\n');
        pem.extend(read(&config.transport_key)?);
        let identity = reqwest::Identity::from_pem(&pem)
            .context("loading the transport certificate and key")?;
        builder = builder.identity(identity);
    }
    builder.build().context("building the HTTP client")
}

/// The token endpoint to use and the audience for the client assertion.
async fn token_endpoint(
    config: &ClientSyncConfig,
    http: &reqwest::Client,
) -> Result<(String, String)> {
    let mut endpoint = config.token_endpoint.clone();
    let mut issuer = None;
    if let Some(url) = &config.discovery_url {
        let metadata: Value = get_json(http.get(url), "registry metadata").await?;
        issuer = metadata["issuer"].as_str().map(str::to_owned);
        if endpoint.is_none() {
            endpoint = discovered_token_endpoint(&metadata);
        }
    }
    let endpoint =
        endpoint.ok_or_else(|| anyhow!("the registry metadata has no token endpoint"))?;
    ensure!(
        endpoint.starts_with("https://"),
        "the registry token endpoint must use https"
    );
    let audience = config
        .audience
        .clone()
        .or(issuer)
        .unwrap_or_else(|| endpoint.clone());
    Ok((endpoint, audience))
}

/// RFC 8705 §5: prefer the mutual TLS alias of the token endpoint.
fn discovered_token_endpoint(metadata: &Value) -> Option<String> {
    metadata["mtls_endpoint_aliases"]["token_endpoint"]
        .as_str()
        .or_else(|| metadata["token_endpoint"].as_str())
        .map(str::to_owned)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or_default()
}

/// The `private_key_jwt` assertion that authenticates this provider.
fn client_assertion(
    config: &ClientSyncConfig,
    signing_key: &SigningKey,
    audience: &str,
    now: i64,
) -> Result<String> {
    signing_key
        .sign_with_kid(
            &config.signing_key_id,
            Some("JWT"),
            &json!({
                "iss": config.client_id,
                "sub": config.client_id,
                "aud": audience,
                "jti": random_token(16),
                "iat": now,
                "nbf": now,
                "exp": now + 60,
            }),
        )
        .map_err(|error| anyhow!("signing the client assertion: {error}"))
}

async fn access_token(
    config: &ClientSyncConfig,
    http: &reqwest::Client,
    signing_key: &SigningKey,
    token_endpoint: &str,
    audience: &str,
) -> Result<String> {
    let assertion = client_assertion(config, signing_key, audience, now())?;
    let request = http.post(token_endpoint).form(&[
        ("grant_type", "client_credentials"),
        ("scope", config.scope.as_str()),
        ("client_id", config.client_id.as_str()),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ]);
    let body: Value = get_json(request, "registry token endpoint").await?;
    body["access_token"]
        .as_str()
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("the registry token response has no access_token"))
}

/// Send a request and parse a JSON body, turning a failure status into an
/// error that says what the registry answered.
async fn get_json(request: reqwest::RequestBuilder, what: &str) -> Result<Value> {
    let response = request
        .header(ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("calling the {what}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("reading the {what} response"))?;
    if !status.is_success() {
        // Error bodies can be long; the start is enough to diagnose. The
        // clients endpoint answers a 400 with `{"errors": [...]}`.
        let detail: String = text.chars().take(300).collect();
        bail!("the {what} answered {status}: {detail}");
    }
    serde_json::from_str(&text).with_context(|| format!("the {what} response is not JSON"))
}

/// One page of the clients endpoint (`RegisteredClientsResponse` in the
/// registry's API definition): the client entries in `content`, with the
/// pagination properties beside them.
#[derive(Debug, Clone, PartialEq)]
struct ClientsPage {
    entries: Vec<Value>,
    /// `totalPages`: how many pages there are in all.
    total_pages: u64,
    /// `totalSize`: how many clients there are in all.
    total_size: Option<u64>,
}

impl ClientsPage {
    /// Read a response to a request for page `requested` (zero-indexed).
    fn parse(body: &Value, requested: u32) -> Result<Self> {
        let entries = body["content"]
            .as_array()
            .ok_or_else(|| anyhow!("the clients response has no content list"))?
            .clone();
        let total_pages = body["totalPages"]
            .as_u64()
            .ok_or_else(|| anyhow!("the clients response has no totalPages"))?;
        // If the registry says which page this is, it must be the one asked
        // for; otherwise pages could be skipped or read twice unnoticed.
        if let Some(number) = body["pageNumber"].as_u64() {
            ensure!(
                number == u64::from(requested),
                "asked the registry for page {requested} of clients but received page {number}"
            );
        }
        if body["empty"].as_bool() == Some(true) {
            ensure!(
                entries.is_empty(),
                "the clients response says it is empty but has content"
            );
        }
        Ok(Self {
            entries,
            total_pages,
            total_size: body["totalSize"].as_u64(),
        })
    }

    /// Whether another page follows page `requested`.
    fn has_next(&self, requested: u32) -> bool {
        u64::from(requested) + 1 < self.total_pages
    }
}

/// Read the clients endpoint to the end: `page` is zero-indexed and `size`
/// is the largest number of results per page, as the registry defines them.
async fn all_pages(
    config: &ClientSyncConfig,
    http: &reqwest::Client,
    access_token: &str,
) -> Result<Vec<Value>> {
    let base = Url::parse(&config.clients_url).context("clients_url")?;
    let mut entries = Vec::new();
    let mut expected_total = None;
    for page in 0..MAX_PAGES {
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("page", &page.to_string())
            .append_pair("size", &config.page_size.to_string());
        let request = http.get(url).bearer_auth(access_token);
        let body = get_json(request, "registry clients endpoint").await?;
        let mut found = ClientsPage::parse(&body, page)?;
        tracing::debug!(
            page,
            total_pages = found.total_pages,
            clients = found.entries.len(),
            "read a page of clients"
        );
        expected_total = expected_total.or(found.total_size);
        let has_next = found.has_next(page);
        entries.append(&mut found.entries);
        if !has_next {
            // The list can change while it is being read. A mismatch is not
            // fatal, but it should not pass silently.
            if let Some(total) = expected_total
                && u64::try_from(entries.len()).ok() != Some(total)
            {
                tracing::warn!(
                    expected = total,
                    received = entries.len(),
                    "the registry's client count changed during synchronisation"
                );
            }
            return Ok(entries);
        }
    }
    bail!("the clients endpoint has more than {MAX_PAGES} pages")
}

/// A client as the registry describes it (ConnectID Client Registration
/// §7.1), reduced to what registration needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryClient {
    client_id: String,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    jwks_uri: Option<String>,
    jwks: Option<JwkSet>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    claims: Vec<String>,
    sector_identifier: Option<String>,
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Whether a status member says the client or its organisation is active.
/// The registry's values are `Active`, `Suspended` and `Inactive`; only the
/// first is registered. A missing status is taken as active.
fn is_active(value: &Value) -> bool {
    value
        .as_str()
        .is_none_or(|status| status.eq_ignore_ascii_case("active"))
}

impl RegistryClient {
    /// Read a registry entry. `Ok(None)` means the entry is valid but not
    /// to be registered (it is inactive).
    fn parse(entry: &Value, profile: Profile) -> Result<Option<Self>> {
        let client_id = entry["client_id"]
            .as_str()
            .or_else(|| entry["software_id"].as_str())
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| anyhow!("entry has no client_id"))?
            .to_owned();
        if !is_active(&entry["status"]) || !is_active(&entry["org_status"]) {
            return Ok(None);
        }

        let redirect_uris = strings(&entry["redirect_uris"]);
        ensure!(!redirect_uris.is_empty(), "no redirect_uris");

        // Only the grants this provider implements are kept.
        let mut grant_types: Vec<String> = strings(&entry["grant_types"])
            .into_iter()
            .filter(|grant| grant == GRANT_AUTHORIZATION_CODE || grant == GRANT_REFRESH_TOKEN)
            .collect();
        if !grant_types.iter().any(|g| g == GRANT_AUTHORIZATION_CODE) {
            grant_types.insert(0, GRANT_AUTHORIZATION_CODE.to_owned());
        }

        let mut scopes: Vec<String> = entry["scope"]
            .as_str()
            .unwrap_or("openid")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if !scopes.iter().any(|scope| scope == "openid") {
            scopes.insert(0, "openid".to_owned());
        }

        // `claims` and `claims_in_verified_claims` together are what the
        // client is accredited for. Names this provider does not know are
        // dropped: they could never be released anyway.
        let mut claims: Vec<String> = strings(&entry["claims"])
            .into_iter()
            .chain(strings(&entry["claims_in_verified_claims"]))
            .filter(|name| crate::claims::profile_allows(profile, name))
            .collect();
        claims.sort();
        claims.dedup();

        // The sector identifier is the host of sector_identifier_uri.
        let sector_identifier = entry["sector_identifier_uri"]
            .as_str()
            .and_then(|uri| Url::parse(uri).ok())
            .and_then(|url| url.host_str().map(str::to_owned));

        let jwks = match entry.get("jwks") {
            Some(value) if !value.is_null() => {
                Some(serde_json::from_value::<JwkSet>(value.clone()).context("jwks is malformed")?)
            }
            _ => None,
        };
        let jwks_uri = entry["jwks_uri"].as_str().map(str::to_owned);
        ensure!(
            jwks.is_some() || jwks_uri.is_some(),
            "neither jwks_uri nor jwks"
        );

        Ok(Some(Self {
            client_id,
            client_name: entry["client_name"].as_str().map(str::to_owned),
            redirect_uris,
            jwks_uri,
            jwks,
            grant_types,
            scopes,
            claims,
            sector_identifier,
        }))
    }

    fn into_client(self, jwks: JwkSet, profile: Profile) -> Result<Client> {
        Client::from_config(&ClientConfig {
            client_id: self.client_id,
            client_name: self.client_name,
            redirect_uris: self.redirect_uris,
            jwks_file: None,
            jwks: Some(jwks),
            scopes: self.scopes,
            grant_types: self.grant_types,
            sector_identifier: self.sector_identifier,
            profile,
            claims: Some(self.claims),
        })
    }
}

async fn fetch_jwks(http: &reqwest::Client, uri: &str) -> Result<JwkSet> {
    ensure!(uri.starts_with("https://"), "jwks_uri must use https");
    let body = get_json(http.get(uri), "client key set").await?;
    serde_json::from_value(body).context("the client key set is malformed")
}

/// Turn registry entries into clients, fetching key sets where needed.
/// Entries that cannot be registered are logged and left out.
async fn build_clients(
    config: &ClientSyncConfig,
    http: &reqwest::Client,
    entries: Vec<Value>,
) -> Vec<Client> {
    let profile = config.profile;
    let limit = Arc::new(tokio::sync::Semaphore::new(JWKS_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    let mut seen = BTreeSet::new();

    for (index, entry) in entries.into_iter().enumerate() {
        let parsed = match RegistryClient::parse(&entry, profile) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => {
                tracing::debug!(
                    client_id = entry["client_id"].as_str().unwrap_or_default(),
                    "skipping an inactive client"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    client_id = entry["client_id"].as_str().unwrap_or_default(),
                    %error,
                    "skipping a client from the registry"
                );
                continue;
            }
        };
        if !seen.insert(parsed.client_id.clone()) {
            tracing::warn!(client_id = %parsed.client_id, "the registry lists a client twice; keeping the first");
            continue;
        }
        let http = http.clone();
        let limit = Arc::clone(&limit);
        tasks.spawn(async move {
            let client_id = parsed.client_id.clone();
            let result = async {
                let jwks = match (&parsed.jwks, &parsed.jwks_uri) {
                    (Some(jwks), _) => jwks.clone(),
                    (None, Some(uri)) => {
                        let _permit = limit.acquire().await;
                        fetch_jwks(&http, uri).await?
                    }
                    (None, None) => bail!("no keys"),
                };
                parsed.into_client(jwks, profile)
            }
            .await;
            (index, client_id, result)
        });
    }

    let mut clients = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((index, _, Ok(client))) => clients.push((index, client)),
            Ok((_, client_id, Err(error))) => {
                tracing::warn!(%client_id, error = %format!("{error:#}"), "skipping a client from the registry");
            }
            Err(error) => tracing::warn!(%error, "a client registration task failed"),
        }
    }
    // Keep the registry's order, whatever order the key sets arrived in.
    clients.sort_by_key(|(index, _)| *index);
    clients.into_iter().map(|(_, client)| client).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::{Jws, SigningAlg};
    use crate::keys::test_support::shared_key;

    fn config() -> ClientSyncConfig {
        toml::from_str(
            r#"
            enabled = true
            discovery_url = "https://auth.registry.example/.well-known/openid-configuration"
            clients_url = "https://matls-api.registry.example/clients"
            client_id = "oxid-idp"
            transport_cert = "transport.pem"
            transport_key = "transport.key"
            signing_key = "signing.key"
            signing_key_id = "registry-kid-1"
            "#,
        )
        .unwrap()
    }

    fn entry() -> Value {
        json!({
            "client_id": "26c2183c-5e9c-4a63-bc65-164d8e316719",
            "software_id": "26c2183c-5e9c-4a63-bc65-164d8e316719",
            "client_name": "Great Accounting App",
            "redirect_uris": ["https://my.accountingapp.com/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "jwks_uri": "https://keystore.registry.example/org/app/application.jwks",
            "sector_identifier_uri": "https://sector.accountingapp.com/redirect_uris.json",
            "subject_type": "pairwise",
            "claims": ["given_name", "family_name", "address"],
            "claims_in_verified_claims": ["over18", "over21"],
            "status": "Active",
            "org_status": "Active",
            "org_name": "Test Org",
        })
    }

    #[test]
    fn config_has_defaults_and_is_validated() {
        type Edit = fn(&mut ClientSyncConfig);
        let defaults = config();
        defaults.validate().unwrap();
        assert_eq!(defaults.scope, "directory:software");
        assert_eq!(defaults.page_size, 50);
        assert_eq!(defaults.profile, Profile::Connectid);
        assert!(defaults.ca.is_none());

        let bad: [(&str, Edit); 7] = [
            ("no way to find the token endpoint", |c| {
                c.discovery_url = None;
            }),
            ("plain http discovery", |c| {
                c.discovery_url = Some("http://registry.example/meta".into());
            }),
            ("plain http clients", |c| {
                c.clients_url = "http://registry.example/clients".into();
            }),
            ("plain http token endpoint", |c| {
                c.token_endpoint = Some("http://registry.example/token".into());
            }),
            ("empty client id", |c| c.client_id = " ".into()),
            ("empty key id", |c| c.signing_key_id = String::new()),
            ("zero page size", |c| c.page_size = 0),
        ];
        for (name, edit) in bad {
            let mut config = config();
            edit(&mut config);
            assert!(config.validate().is_err(), "{name}");
        }

        let mut explicit = config();
        explicit.discovery_url = None;
        explicit.token_endpoint = Some("https://matls-auth.registry.example/token".into());
        explicit.validate().unwrap();

        assert!(
            toml::from_str::<ClientSyncConfig>("enabled = true\nclient_secret = \"x\"").is_err(),
            "unknown fields are refused"
        );
    }

    #[test]
    fn token_endpoint_prefers_the_mtls_alias() {
        let metadata = json!({
            "issuer": "https://auth.registry.example",
            "token_endpoint": "https://auth.registry.example/token",
            "mtls_endpoint_aliases": {"token_endpoint": "https://matls-auth.registry.example/token"},
        });
        assert_eq!(
            discovered_token_endpoint(&metadata).unwrap(),
            "https://matls-auth.registry.example/token"
        );
        let plain = json!({"token_endpoint": "https://auth.registry.example/token"});
        assert_eq!(
            discovered_token_endpoint(&plain).unwrap(),
            "https://auth.registry.example/token"
        );
        assert!(discovered_token_endpoint(&json!({})).is_none());
    }

    #[test]
    fn client_assertion_is_a_private_key_jwt_with_the_registry_kid() {
        let config = config();
        let assertion =
            client_assertion(&config, shared_key(), "https://auth.registry.example", 1000).unwrap();
        let jws = Jws::parse(&assertion, &[SigningAlg::PS256]).unwrap();
        assert_eq!(jws.kid.as_deref(), Some("registry-kid-1"));
        assert_eq!(jws.str_claim("iss"), Some("oxid-idp"));
        assert_eq!(jws.str_claim("sub"), Some("oxid-idp"));
        assert_eq!(jws.str_claim("aud"), Some("https://auth.registry.example"));
        assert_eq!(jws.time_claim("iat"), Some(1000));
        assert_eq!(jws.time_claim("exp"), Some(1060));
        assert!(jws.str_claim("jti").is_some_and(|jti| jti.len() >= 16));

        // The signature is by the configured key, whatever kid is claimed.
        let mut jwks = shared_key().jwks();
        jwks.keys[0].common.key_id = Some("registry-kid-1".to_owned());
        jws.verify(&jwks).unwrap();

        let again =
            client_assertion(&config, shared_key(), "https://auth.registry.example", 1000).unwrap();
        let other = Jws::parse(&again, &[SigningAlg::PS256]).unwrap();
        assert_ne!(
            jws.str_claim("jti"),
            other.str_claim("jti"),
            "jti is unique"
        );
    }

    /// A response shaped like the registry's `RegisteredClientsResponse`.
    fn response(clients: usize, page: u64, size: u64, total: u64) -> Value {
        json!({
            "content": vec![json!({}); clients],
            "totalPages": total.div_ceil(size),
            "totalSize": total,
            "pageable": {"number": page, "size": size, "offset": page * size},
            "size": size,
            "offset": page * size,
            "empty": clients == 0,
            "pageNumber": page,
        })
    }

    #[test]
    fn pages_follow_the_registry_pagination_properties() {
        // 120 clients at 50 a page: pages 0 and 1 are full, page 2 has 20.
        let first = ClientsPage::parse(&response(50, 0, 50, 120), 0).unwrap();
        assert_eq!(first.entries.len(), 50);
        assert_eq!(first.total_pages, 3);
        assert_eq!(first.total_size, Some(120));
        assert!(first.has_next(0));
        let second = ClientsPage::parse(&response(50, 1, 50, 120), 1).unwrap();
        assert!(second.has_next(1));
        let last = ClientsPage::parse(&response(20, 2, 50, 120), 2).unwrap();
        assert_eq!(last.entries.len(), 20);
        assert!(!last.has_next(2));

        // A full last page is still the last page: totalPages decides, not
        // how many results came back.
        let exact = ClientsPage::parse(&response(50, 1, 50, 100), 1).unwrap();
        assert!(!exact.has_next(1));

        // No clients at all.
        let none = ClientsPage::parse(&response(0, 0, 50, 0), 0).unwrap();
        assert_eq!(none.entries.len(), 0);
        assert_eq!(none.total_pages, 0);
        assert!(!none.has_next(0));
    }

    #[test]
    fn optional_pagination_properties_may_be_absent() {
        let minimal = json!({"content": [{}, {}], "totalPages": 2});
        let page = ClientsPage::parse(&minimal, 0).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.total_size, None);
        assert!(page.has_next(0));
        assert!(!ClientsPage::parse(&minimal, 1).unwrap().has_next(1));
    }

    #[test]
    fn malformed_or_inconsistent_pages_are_errors() {
        for (name, body) in [
            (
                "an error body",
                json!({"errors": ["endDate format is invalid"]}),
            ),
            ("a bare list", json!([{}, {}])),
            (
                "content that is not a list",
                json!({"content": "x", "totalPages": 1}),
            ),
            ("no totalPages", json!({"content": [{}]})),
            ("a text body", json!("clients")),
            (
                "content on a page marked empty",
                json!({"content": [{}], "totalPages": 1, "empty": true}),
            ),
        ] {
            assert!(ClientsPage::parse(&body, 0).is_err(), "{name}");
        }
        // The registry answering with a different page than was asked for.
        let error = ClientsPage::parse(&response(50, 0, 50, 120), 1).unwrap_err();
        assert!(error.to_string().contains("page 1"), "{error}");
    }

    #[test]
    fn registry_entry_becomes_a_client() {
        let parsed = RegistryClient::parse(&entry(), Profile::Connectid)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.client_id, "26c2183c-5e9c-4a63-bc65-164d8e316719");
        assert_eq!(
            parsed.sector_identifier.as_deref(),
            Some("sector.accountingapp.com")
        );
        assert_eq!(
            parsed.claims,
            ["address", "family_name", "given_name", "over18", "over21"]
        );

        let client = parsed
            .into_client(shared_key().jwks(), Profile::Connectid)
            .unwrap();
        assert_eq!(client.name, "Great Accounting App");
        assert!(client.has_redirect_uri("https://my.accountingapp.com/cb"));
        assert_eq!(client.sector_identifier, "sector.accountingapp.com");
        assert!(client.allows_claim("given_name") && client.allows_claim("over18"));
        assert!(!client.allows_claim("email"), "not accredited for email");
        assert!(!client.allows_claim("over65"));
        assert!(!client.allows_refresh_tokens());
        assert_eq!(client.profile, Profile::Connectid);
    }

    #[test]
    fn registry_entries_are_normalised() {
        let mut odd = entry();
        odd["grant_types"] = json!(["refresh_token", "client_credentials", "implicit"]);
        odd["scope"] = json!("profile  payments");
        odd["claims"] = json!(["given_name", "nickname", "made_up", 7]);
        odd["claims_in_verified_claims"] = json!(["over18", "place_of_birth"]);
        odd.as_object_mut().unwrap().remove("sector_identifier_uri");
        odd.as_object_mut().unwrap().remove("client_id");
        let parsed = RegistryClient::parse(&odd, Profile::Connectid)
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed.client_id, "26c2183c-5e9c-4a63-bc65-164d8e316719",
            "software_id"
        );
        assert_eq!(parsed.grant_types, ["authorization_code", "refresh_token"]);
        assert_eq!(parsed.scopes, ["openid", "profile", "payments"]);
        assert_eq!(
            parsed.claims,
            ["given_name", "over18"],
            "unknown names are dropped"
        );
        assert!(parsed.sector_identifier.is_none());
        // Without a sector identifier URI it is derived from the redirect host.
        let client = parsed
            .into_client(shared_key().jwks(), Profile::Connectid)
            .unwrap();
        assert_eq!(client.sector_identifier, "my.accountingapp.com");
        assert!(client.allows_refresh_tokens());

        // No claims at all means nothing is released, not everything.
        let mut none = entry();
        none.as_object_mut().unwrap().remove("claims");
        none.as_object_mut()
            .unwrap()
            .remove("claims_in_verified_claims");
        let client = RegistryClient::parse(&none, Profile::Connectid)
            .unwrap()
            .unwrap()
            .into_client(shared_key().jwks(), Profile::Connectid)
            .unwrap();
        assert!(!client.allows_claim("given_name"));
    }

    #[test]
    fn inactive_clients_are_not_registered() {
        for (member, status) in [
            ("status", "Inactive"),
            ("status", "Suspended"),
            ("org_status", "Withdrawn"),
        ] {
            let mut inactive = entry();
            inactive[member] = json!(status);
            assert!(
                RegistryClient::parse(&inactive, Profile::Connectid)
                    .unwrap()
                    .is_none(),
                "{member}={status}"
            );
        }
        let mut lower = entry();
        lower["status"] = json!("active");
        assert!(
            RegistryClient::parse(&lower, Profile::Connectid)
                .unwrap()
                .is_some()
        );
        let mut missing = entry();
        missing.as_object_mut().unwrap().remove("status");
        assert!(
            RegistryClient::parse(&missing, Profile::Connectid)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn unusable_entries_are_errors() {
        type Edit = fn(&mut Value);
        let cases: [(&str, Edit); 5] = [
            ("no id", |e| {
                e.as_object_mut().unwrap().remove("client_id");
                e.as_object_mut().unwrap().remove("software_id");
            }),
            ("no redirect uris", |e| e["redirect_uris"] = json!([])),
            ("no keys", |e| {
                e.as_object_mut().unwrap().remove("jwks_uri");
            }),
            ("malformed inline keys", |e| {
                e["jwks"] = json!({"keys": "x"});
            }),
            ("blank id", |e| e["client_id"] = json!("  ")),
        ];
        for (name, edit) in cases {
            let mut bad = entry();
            edit(&mut bad);
            if name == "blank id" {
                bad.as_object_mut().unwrap().remove("software_id");
            }
            assert!(
                RegistryClient::parse(&bad, Profile::Connectid).is_err(),
                "{name}"
            );
        }

        // A client that parses but cannot be registered (insecure redirect).
        let mut insecure = entry();
        insecure["redirect_uris"] = json!(["http://my.accountingapp.com/cb"]);
        let parsed = RegistryClient::parse(&insecure, Profile::Connectid)
            .unwrap()
            .unwrap();
        assert!(
            parsed
                .into_client(shared_key().jwks(), Profile::Connectid)
                .is_err()
        );
    }

    #[test]
    fn inline_keys_are_accepted_in_place_of_a_jwks_uri() {
        let mut inline = entry();
        inline.as_object_mut().unwrap().remove("jwks_uri");
        inline["jwks"] = serde_json::to_value(shared_key().jwks()).unwrap();
        let parsed = RegistryClient::parse(&inline, Profile::Connectid)
            .unwrap()
            .unwrap();
        assert!(parsed.jwks.is_some() && parsed.jwks_uri.is_none());
    }
}
