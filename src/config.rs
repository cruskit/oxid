//! Configuration loading and validation.
//!
//! Configuration is a TOML file. Everything security-relevant has a default
//! that satisfies the ConnectID profile, and [`Config::validate`] refuses
//! values that would take the provider outside FAPI 2.0 / ConnectID limits.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use url::Url;

/// ConnectID §4.2-3.2: access tokens expire at most 10 minutes after issue.
pub const MAX_ACCESS_TOKEN_TTL: i64 = 600;
/// FAPI 2.0 §5.3.2.1-11: authorization codes live at most 60 seconds.
pub const MAX_AUTHORIZATION_CODE_TTL: i64 = 60;
/// FAPI 2.0 §5.3.2.2-12: `request_uri` `expires_in` is below 600 seconds.
pub const MAX_REQUEST_URI_TTL: i64 = 599;
/// The longest a user may be given to sign in and decide.
pub const MAX_SESSION_TTL: i64 = 60 * 60;
/// The longest the `ci` experience may wait before responding. The wait
/// happens inside the browser's request, and behind API Gateway a request
/// may take 30 seconds at most.
pub const MAX_CI_RESPONSE_DELAY: i64 = 25;
/// ConnectID §4.2-3.10/11: request object `exp - nbf` and `nbf` age limits.
pub const MAX_REQUEST_OBJECT_WINDOW: i64 = 600;
/// The longest a listener waits for a request's headers, in seconds.
pub const MAX_HEADER_READ_TIMEOUT: u64 = 60;
/// The longest a listener lets one request take, in seconds.
pub const MAX_REQUEST_TIMEOUT: u64 = 300;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The issuer identifier, e.g. `https://op.example.com`. Also the base URL
    /// of the public (non-mTLS) listener.
    pub issuer: String,
    /// Base URL of the mTLS listener, advertised via `mtls_endpoint_aliases`.
    pub mtls_base_url: String,
    /// The user experience at the authorization endpoint: `technical` (the
    /// default), `login` or `ci`.
    #[serde(default)]
    pub experience: crate::experience::Kind,
    /// Settings of the `ci` experience.
    #[serde(default)]
    pub ci: CiConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub keys: KeysConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    /// Where server-side state is kept.
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    /// Loading further clients from the ConnectID registry at startup.
    pub client_sync: Option<crate::client_sync::ClientSyncConfig>,
    /// Users. When empty, the built-in demo user is used.
    #[serde(default)]
    pub users: Vec<UserConfig>,
    /// The name, logo and colours of the pages users see. The default is
    /// the oxID theme.
    #[serde(default)]
    pub theme: crate::theme::ThemeConfig,
    /// The IANA time zone in which a user's age is worked out, for the
    /// `verified_claims` age attestations, unless the user's own `zoneinfo`
    /// claim names one. A birthday starts at midnight there.
    #[serde(default = "default_time_zone")]
    pub time_zone: String,
}

fn default_time_zone() -> String {
    crate::user::DEFAULT_TIME_ZONE.to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Address of the public listener (browser-facing endpoints, discovery).
    pub listen: SocketAddr,
    /// Address of the listener that requests a TLS client certificate.
    pub mtls_listen: SocketAddr,
    /// PEM certificate chain. When unset, an ephemeral self-signed
    /// certificate is generated (development only).
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// PEM bundle of CAs that client certificates must chain to. When unset,
    /// any certificate the client proves possession of is accepted, which is
    /// what RFC 8705 calls self-signed certificate mutual TLS.
    pub client_ca: Option<PathBuf>,
    /// Seconds an HTTP/1 client has to send a request's headers, counted
    /// from the end of the TLS handshake or of the previous response. An
    /// idle keep-alive connection is closed when it elapses.
    pub header_read_timeout: u64,
    /// Seconds a request may take, body included, before it is answered with
    /// `503`. Must exceed `ci.response_delay`, which is spent inside a
    /// request.
    pub request_timeout: u64,
    /// Connections each listener holds open at once. Further clients wait
    /// in the kernel's accept queue.
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 9443)),
            mtls_listen: SocketAddr::from(([127, 0, 0, 1], 9444)),
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            header_read_timeout: 10,
            request_timeout: 30,
            max_connections: 1024,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeysConfig {
    /// PEM RSA private key used to sign ID tokens. When unset, an ephemeral
    /// key is generated at startup (development only).
    pub signing_key: Option<PathBuf>,
    /// Secret mixed into pairwise subject identifiers. When unset, a random
    /// value is generated at startup, so subjects change across restarts.
    pub pairwise_salt: Option<crate::util::Secret<String>>,
}

/// Which backend holds server-side state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreBackend {
    /// In this process: lost on restart, not shared between instances.
    #[default]
    Memory,
    /// An Amazon DynamoDB table, shared by every instance. Needs a build
    /// with the `aws` feature.
    Dynamodb,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StoreConfig {
    pub backend: StoreBackend,
    /// DynamoDB table name. Required for the `dynamodb` backend.
    pub table: Option<String>,
    /// AWS region of the table. Defaults to the environment's region.
    pub region: Option<String>,
    /// Override the DynamoDB endpoint, e.g. `http://localhost:8000` for
    /// DynamoDB Local.
    pub endpoint_url: Option<String>,
}

impl StoreConfig {
    fn validate(&self) -> Result<()> {
        match self.backend {
            StoreBackend::Memory => ensure!(
                self.table.is_none() && self.region.is_none() && self.endpoint_url.is_none(),
                "table, region and endpoint_url apply only to backend = \"dynamodb\""
            ),
            StoreBackend::Dynamodb => {
                ensure!(
                    cfg!(feature = "aws"),
                    "backend = \"dynamodb\" needs oxID built with the 'aws' feature"
                );
                ensure!(
                    self.table.as_deref().is_some_and(|t| !t.is_empty()),
                    "table is required for backend = \"dynamodb\""
                );
            }
        }
        Ok(())
    }
}

/// Settings of the `ci` experience, which answers authorization requests by
/// itself. They have no effect under another experience.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CiConfig {
    /// Seconds to wait, from the browser's arrival, before giving the
    /// default response. It is the time a client has to say what the
    /// response should be instead; a request whose response the client has
    /// already set is answered at once.
    pub response_delay: i64,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self { response_delay: 5 }
    }
}

/// Lifetimes and tolerances, in seconds.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityConfig {
    pub access_token_ttl: i64,
    pub refresh_token_ttl: i64,
    pub id_token_ttl: i64,
    pub authorization_code_ttl: i64,
    pub request_uri_ttl: i64,
    /// How long a user has to sign in and decide once their browser has
    /// arrived at the authorization endpoint with a valid `request_uri`.
    pub session_ttl: i64,
    /// Maximum `exp - nbf` of a request object.
    pub request_object_max_lifetime: i64,
    /// Maximum age of a request object's `nbf`.
    pub request_object_max_age: i64,
    /// How far in the future `iat`/`nbf` may be. FAPI 2.0 §5.3.2.1-13 requires
    /// accepting 10 seconds and rejecting more than 60.
    pub clock_skew: i64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: 300,
            refresh_token_ttl: 24 * 60 * 60,
            id_token_ttl: 300,
            authorization_code_ttl: 60,
            request_uri_ttl: 90,
            session_ttl: crate::store::DEFAULT_SESSION_TTL,
            request_object_max_lifetime: MAX_REQUEST_OBJECT_WINDOW,
            request_object_max_age: MAX_REQUEST_OBJECT_WINDOW,
            clock_skew: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// Path to a JSON JWK Set holding the client's public keys.
    pub jwks_file: Option<PathBuf>,
    /// The client's public keys, inline. Mutually exclusive with `jwks_file`.
    pub jwks: Option<jsonwebtoken::jwk::JwkSet>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    /// Host used to derive pairwise subjects. Defaults to the host shared by
    /// all redirect URIs.
    pub sector_identifier: Option<String>,
    /// Which claims exist for this client: `connectid` (the default) or
    /// `oidc`.
    #[serde(default)]
    pub profile: crate::client::Profile,
    /// Claims this client may receive, within its profile. Requests for
    /// anything else are ignored. When unset, every claim of the profile is
    /// allowed.
    pub claims: Option<Vec<String>>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_owned()]
}

fn default_grant_types() -> Vec<String> {
    vec!["authorization_code".to_owned()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub username: String,
    /// Argon2 PHC string, as produced by `oxid hash-password`. A user
    /// without one cannot sign in under the `login` experience, but can be
    /// selected in the `technical` one.
    pub password_hash: Option<crate::util::Secret<String>>,
    /// Stable internal identifier. Never sent to clients directly; clients
    /// receive a pairwise identifier derived from it.
    pub subject: String,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
    /// The user's bank account, the source of the ConnectID
    /// `beneficiary_account_*` verified claims.
    pub bank_account: Option<crate::user::BankAccount>,
}

impl Config {
    /// Load, resolve relative paths against the file's directory, and validate.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut config: Self =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.resolve_paths(base);
        config.validate()?;
        Ok(config)
    }

    fn resolve_paths(&mut self, base: &Path) {
        let fix = |p: &mut Option<PathBuf>| {
            if let Some(path) = p
                && path.is_relative()
            {
                *path = base.join(&*path);
            }
        };
        fix(&mut self.server.tls_cert);
        fix(&mut self.server.tls_key);
        fix(&mut self.server.client_ca);
        fix(&mut self.keys.signing_key);
        fix(&mut self.theme.logo);
        fix(&mut self.theme.logo_dark);
        for client in &mut self.clients {
            fix(&mut client.jwks_file);
        }
        if let Some(sync) = &mut self.client_sync {
            let required = |path: &mut PathBuf| {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            };
            required(&mut sync.transport_cert);
            required(&mut sync.transport_key);
            required(&mut sync.signing_key);
            fix(&mut sync.ca);
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_base_url(&self.issuer).context("issuer")?;
        validate_base_url(&self.mtls_base_url).context("mtls_base_url")?;
        self.theme.validate().context("theme")?;
        jiff::tz::TimeZone::get(&self.time_zone)
            .with_context(|| format!("time_zone '{}' is not a known time zone", self.time_zone))?;

        ensure!(
            self.server.tls_cert.is_some() == self.server.tls_key.is_some(),
            "server.tls_cert and server.tls_key must be set together"
        );
        ensure!(
            (1..=MAX_HEADER_READ_TIMEOUT).contains(&self.server.header_read_timeout),
            "server.header_read_timeout must be between 1 and {MAX_HEADER_READ_TIMEOUT} seconds"
        );
        ensure!(
            (1..=MAX_REQUEST_TIMEOUT).contains(&self.server.request_timeout),
            "server.request_timeout must be between 1 and {MAX_REQUEST_TIMEOUT} seconds"
        );
        ensure!(
            self.server.max_connections > 0,
            "server.max_connections must be positive"
        );

        let s = &self.security;
        ensure!(
            (1..=MAX_ACCESS_TOKEN_TTL).contains(&s.access_token_ttl),
            "security.access_token_ttl must be between 1 and {MAX_ACCESS_TOKEN_TTL} seconds"
        );
        ensure!(
            (1..=MAX_AUTHORIZATION_CODE_TTL).contains(&s.authorization_code_ttl),
            "security.authorization_code_ttl must be between 1 and {MAX_AUTHORIZATION_CODE_TTL} seconds"
        );
        ensure!(
            (1..=MAX_REQUEST_URI_TTL).contains(&s.request_uri_ttl),
            "security.request_uri_ttl must be between 1 and {MAX_REQUEST_URI_TTL} seconds"
        );
        ensure!(
            (1..=MAX_SESSION_TTL).contains(&s.session_ttl),
            "security.session_ttl must be between 1 and {MAX_SESSION_TTL} seconds"
        );
        ensure!(
            (1..=MAX_REQUEST_OBJECT_WINDOW).contains(&s.request_object_max_lifetime),
            "security.request_object_max_lifetime must be between 1 and {MAX_REQUEST_OBJECT_WINDOW} seconds"
        );
        ensure!(
            (1..=MAX_REQUEST_OBJECT_WINDOW).contains(&s.request_object_max_age),
            "security.request_object_max_age must be between 1 and {MAX_REQUEST_OBJECT_WINDOW} seconds"
        );
        ensure!(
            (10..=60).contains(&s.clock_skew),
            "security.clock_skew must be between 10 and 60 seconds"
        );
        ensure!(
            s.refresh_token_ttl > 0,
            "security.refresh_token_ttl must be positive"
        );
        ensure!(s.id_token_ttl > 0, "security.id_token_ttl must be positive");

        ensure!(
            (0..=MAX_CI_RESPONSE_DELAY).contains(&self.ci.response_delay),
            "ci.response_delay must be between 0 and {MAX_CI_RESPONSE_DELAY} seconds"
        );
        ensure!(
            self.server.request_timeout.cast_signed() > self.ci.response_delay,
            "server.request_timeout must be longer than ci.response_delay"
        );

        if let Some(sync) = &self.client_sync {
            sync.validate().context("client_sync")?;
        }
        self.store.validate().context("store")?;

        if let Some(salt) = &self.keys.pairwise_salt {
            ensure!(
                salt.expose().len() >= 16,
                "keys.pairwise_salt must be at least 16 characters"
            );
        }
        Ok(())
    }
}

/// Issuer-style URLs: https, a host, and no query, fragment or trailing slash.
fn validate_base_url(value: &str) -> Result<()> {
    let url = Url::parse(value).with_context(|| format!("'{value}' is not a URL"))?;
    ensure!(url.scheme() == "https", "'{value}' must use https");
    ensure!(url.host_str().is_some(), "'{value}' must have a host");
    if url.query().is_some() || url.fragment().is_some() {
        bail!("'{value}' must not have a query or fragment");
    }
    ensure!(!value.ends_with('/'), "'{value}' must not end with '/'");
    Ok(())
}

#[cfg(test)]
mod tests;
