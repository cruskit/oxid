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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 9443)),
            mtls_listen: SocketAddr::from(([127, 0, 0, 1], 9444)),
            tls_cert: None,
            tls_key: None,
            client_ca: None,
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
    pub pairwise_salt: Option<String>,
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
    pub password_hash: Option<String>,
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

        ensure!(
            self.server.tls_cert.is_some() == self.server.tls_key.is_some(),
            "server.tls_cert and server.tls_key must be set together"
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

        if let Some(sync) = &self.client_sync {
            sync.validate().context("client_sync")?;
        }
        self.store.validate().context("store")?;

        if let Some(salt) = &self.keys.pairwise_salt {
            ensure!(
                salt.len() >= 16,
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
mod tests {
    use super::*;

    fn minimal() -> Config {
        toml::from_str(
            r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn minimal_config_gets_compliant_defaults() {
        let config = minimal();
        config.validate().unwrap();
        assert_eq!(config.security.access_token_ttl, 300);
        assert_eq!(config.security.authorization_code_ttl, 60);
        assert_eq!(config.security.request_object_max_lifetime, 600);
        assert!(config.clients.is_empty());
        assert!(config.users.is_empty());
        assert_eq!(config.experience, crate::experience::Kind::Technical);

        let login: Config = toml::from_str(
            "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n\
             experience = \"login\"",
        )
        .unwrap();
        assert_eq!(login.experience, crate::experience::Kind::Login);
        assert!(
            toml::from_str::<Config>(
                "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n\
                 experience = \"wizard\"",
            )
            .is_err()
        );
    }

    #[test]
    fn store_defaults_to_memory_and_dynamodb_needs_a_table() {
        let config = minimal();
        assert_eq!(config.store.backend, StoreBackend::Memory);

        let with = |store: &str| -> Config {
            toml::from_str(&format!(
                "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n[store]\n{store}"
            ))
            .unwrap()
        };
        let no_table = with("backend = \"dynamodb\"");
        assert!(no_table.validate().is_err());
        let table = with("backend = \"dynamodb\"\ntable = \"oxid\"\nregion = \"ap-southeast-2\"");
        assert_eq!(table.store.backend, StoreBackend::Dynamodb);
        // Usable only when the binary was built with DynamoDB support.
        assert_eq!(table.validate().is_ok(), cfg!(feature = "aws"));
        let stray = with("table = \"oxid\"");
        assert!(stray.validate().is_err(), "a table without the backend");
        assert!(
            toml::from_str::<Config>(
                "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n\
                 [store]\nbackend = \"redis\"",
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            isuer = "typo"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("isuer"), "{err}");
    }

    #[test]
    fn issuer_must_be_a_clean_https_url() {
        for bad in [
            "http://op.example.com",
            "https://op.example.com/",
            "https://op.example.com?x=1",
            "https://op.example.com#frag",
            "not a url",
        ] {
            let mut config = minimal();
            config.issuer = bad.to_owned();
            assert!(config.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn lifetimes_cannot_exceed_profile_limits() {
        type Setter = fn(&mut SecurityConfig);
        let cases: [(&str, Setter); 9] = [
            ("access token over 10 minutes", |s| s.access_token_ttl = 601),
            ("code over 60 seconds", |s| s.authorization_code_ttl = 61),
            ("request_uri at 600 seconds", |s| s.request_uri_ttl = 600),
            ("no session time", |s| s.session_ttl = 0),
            ("session over an hour", |s| s.session_ttl = 3601),
            ("request object lifetime", |s| {
                s.request_object_max_lifetime = 601;
            }),
            ("request object age", |s| s.request_object_max_age = 601),
            ("skew below 10", |s| s.clock_skew = 9),
            ("skew above 60", |s| s.clock_skew = 61),
        ];
        for (name, set) in cases {
            let mut config = minimal();
            set(&mut config.security);
            assert!(config.validate().is_err(), "{name}");
        }
    }

    #[test]
    fn tls_cert_and_key_must_come_as_a_pair() {
        let mut config = minimal();
        config.server.tls_cert = Some("cert.pem".into());
        assert!(config.validate().is_err());
        config.server.tls_key = Some("key.pem".into());
        config.validate().unwrap();
    }

    #[test]
    fn users_and_clients_carry_connectid_claim_settings() {
        let config: Config = toml::from_str(
            r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"

            [[clients]]
            client_id = "c"
            redirect_uris = ["https://rp.example.com/cb"]
            jwks_file = "c.jwks.json"
            claims = ["given_name", "over18", "beneficiary_account_au"]

            [[clients]]
            client_id = "d"
            redirect_uris = ["https://rp2.example.com/cb"]
            jwks_file = "d.jwks.json"
            profile = "oidc"
            scopes = ["openid", "profile", "email"]

            [[users]]
            username = "alex"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
            subject = "user-0001"

            [users.claims]
            given_name = "Alex"

            [users.claims.address]
            locality = "Sydney"

            [users.bank_account]
            beneficiary_name = "Alex Jordan Citizen"
            bsb = "123456"
            account_number = "12345678"
            payid = "0400000321"
            payid_type = "/TELI"
            bic_swift_code = "OXIDAU2SXXX"
            "#,
        )
        .unwrap();
        assert_eq!(
            config.clients[0].claims.as_deref().unwrap(),
            ["given_name", "over18", "beneficiary_account_au"]
        );
        assert_eq!(config.clients[0].profile, crate::client::Profile::Connectid);
        assert_eq!(config.clients[1].profile, crate::client::Profile::Oidc);
        let user = &config.users[0];
        assert_eq!(user.claims["address"]["locality"], "Sydney");
        let account = user.bank_account.as_ref().unwrap();
        account.validate().unwrap();
        assert_eq!(account.payid_type, Some(crate::user::PayIdType::Mobile));
        assert_eq!(account.international_number(), "12345612345678");

        let typo = toml::from_str::<Config>(
            r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            [[users]]
            username = "alex"
            subject = "s"
            [users.bank_account]
            beneficiary_name = "A"
            bsb = "123456"
            account_number = "1"
            payid_type = "/CARD"
            "#,
        );
        assert!(typo.is_err(), "unknown PayID types are refused");
    }

    #[test]
    fn short_pairwise_salt_is_rejected() {
        let mut config = minimal();
        config.keys.pairwise_salt = Some("short".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn relative_paths_resolve_against_the_config_directory() {
        let mut config: Config = toml::from_str(
            r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            [keys]
            signing_key = "keys/signing.pem"
            [server]
            tls_cert = "/abs/cert.pem"
            tls_key = "tls/key.pem"
            [[clients]]
            client_id = "c"
            redirect_uris = ["https://rp.example.com/cb"]
            jwks_file = "c.jwks.json"
            "#,
        )
        .unwrap();
        config.resolve_paths(Path::new("/etc/oxid"));
        assert_eq!(
            config.keys.signing_key.unwrap(),
            Path::new("/etc/oxid/keys/signing.pem")
        );
        assert_eq!(config.server.tls_cert.unwrap(), Path::new("/abs/cert.pem"));
        assert_eq!(
            config.server.tls_key.unwrap(),
            Path::new("/etc/oxid/tls/key.pem")
        );
        assert_eq!(
            config.clients[0].jwks_file.as_deref().unwrap(),
            Path::new("/etc/oxid/c.jwks.json")
        );
        assert_eq!(config.clients[0].scopes, ["openid"]);
        assert_eq!(config.clients[0].grant_types, ["authorization_code"]);
    }
}
