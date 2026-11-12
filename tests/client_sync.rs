//! Client synchronisation against a stand-in for the ConnectID registry.
//!
//! The stand-in is served with oxID's own TLS stack on a listener that asks
//! for a client certificate, and checks everything a registry would: the
//! certificate, the `private_key_jwt` assertion, and that the access token
//! is used with the certificate it was issued to.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Json, Router};
use common::TestOp;
use oxid::client::Profile;
use oxid::client_sync::{ClientSyncConfig, fetch};
use oxid::http::ConnInfo;
use oxid::jose::{Jws, SigningAlg};
use oxid::keys::SigningKey;
use oxid::tls::{self, ClientCertPolicy, TlsIdentity};
use serde_json::{Value, json};

const IDP_CLIENT_ID: &str = "oxid-idp";
const KEY_ID: &str = "registry-assigned-kid";
const ACCESS_TOKEN: &str = "registry-access-token";

struct Registry {
    base: String,
    /// The provider's assertion key, as registered under [`KEY_ID`].
    idp_jwks: jsonwebtoken::jwk::JwkSet,
    /// Keys of the relying parties, served from their `jwks_uri`.
    rp_jwks: Value,
    entries: Mutex<Vec<Value>>,
    /// Thumbprint of the certificate the access token was issued to.
    token_bound_to: Mutex<Option<String>>,
    /// `page` values requested from the clients endpoint, in order.
    pages_requested: Mutex<Vec<String>>,
    token_requests: Mutex<u32>,
}

type Shared = Arc<Registry>;

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({"error": error}))).into_response()
}

async fn metadata(State(registry): State<Shared>) -> Json<Value> {
    Json(json!({
        "issuer": registry.base,
        // Deliberately unusable: the mutual TLS alias must be preferred.
        "token_endpoint": format!("{}/not-the-mtls-token-endpoint", registry.base),
        "mtls_endpoint_aliases": {"token_endpoint": format!("{}/token", registry.base)},
    }))
}

async fn token(
    State(registry): State<Shared>,
    Extension(conn): Extension<ConnInfo>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    *registry.token_requests.lock().unwrap() += 1;
    let Some(cert) = conn.client_cert else {
        return oauth_error(StatusCode::UNAUTHORIZED, "no_client_certificate");
    };
    let field = |name: &str| form.get(name).map(String::as_str);
    if field("grant_type") != Some("client_credentials")
        || field("scope") != Some("directory:software")
        || field("client_id") != Some(IDP_CLIENT_ID)
        || field("client_assertion_type")
            != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(jws) = Jws::parse(
        field("client_assertion").unwrap_or_default(),
        &[SigningAlg::PS256],
    ) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let valid = jws.kid.as_deref() == Some(KEY_ID)
        && jws.verify(&registry.idp_jwks).is_ok()
        && jws.str_claim("iss") == Some(IDP_CLIENT_ID)
        && jws.str_claim("sub") == Some(IDP_CLIENT_ID)
        && jws.str_claim("aud") == Some(registry.base.as_str())
        && jws.str_claim("jti").is_some()
        && jws.time_claim("exp").is_some();
    if !valid {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    *registry.token_bound_to.lock().unwrap() = Some(cert.thumbprint);
    Json(json!({"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 300}))
        .into_response()
}

async fn clients(
    State(registry): State<Shared>,
    Extension(conn): Extension<ConnInfo>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let bound = registry.token_bound_to.lock().unwrap().clone();
    let presented = conn.client_cert.map(|cert| cert.thumbprint);
    if bearer != Some(&format!("Bearer {ACCESS_TOKEN}")) || bound.is_none() || presented != bound {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    }

    let page: usize = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(0);
    let size: usize = query.get("size").and_then(|s| s.parse().ok()).unwrap_or(20);
    registry
        .pages_requested
        .lock()
        .unwrap()
        .push(query.get("page").cloned().unwrap_or_default());

    // The response the registry's API definition gives: the clients in
    // `content`, beside the pagination properties.
    let entries = registry.entries.lock().unwrap().clone();
    let total_pages = entries.len().div_ceil(size);
    let content: Vec<Value> = entries
        .iter()
        .skip(page * size)
        .take(size)
        .cloned()
        .collect();
    Json(json!({
        "empty": content.is_empty(),
        "content": content,
        "totalPages": total_pages,
        "totalSize": entries.len(),
        "pageable": {"number": page, "size": size, "offset": page * size},
        "size": size,
        "offset": page * size,
        "pageNumber": page,
    }))
    .into_response()
}

async fn rp_jwks(State(registry): State<Shared>, Path(id): Path<String>) -> Response {
    if id == "missing" {
        return oauth_error(StatusCode::NOT_FOUND, "not_found");
    }
    Json(registry.rp_jwks.clone()).into_response()
}

/// A running stand-in registry and the files a provider needs to use it.
struct TestRegistry {
    registry: Shared,
    config: ClientSyncConfig,
    dir: PathBuf,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl TestRegistry {
    /// Must be called inside a Tokio runtime: it spawns the listener task.
    fn start(page_size: u32) -> Self {
        let dir = std::env::temp_dir().join(format!("oxid-sync-{}", oxid::util::random_token(8)));
        std::fs::create_dir_all(&dir).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );

        // The registry's TLS identity, which the provider is told to trust.
        let identity = TlsIdentity::self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(dir.join("registry-ca.pem"), identity.cert_pem()).unwrap();
        // The provider's transport certificate and assertion signing key.
        let transport = TlsIdentity::self_signed(vec!["oxid-idp".to_owned()]).unwrap();
        std::fs::write(dir.join("transport.pem"), transport.cert_pem()).unwrap();
        std::fs::write(dir.join("transport.key"), transport.key_pem()).unwrap();
        let signing_pem = SigningKey::generate_pem().unwrap();
        std::fs::write(dir.join("signing.key"), &signing_pem).unwrap();
        let mut idp_jwks = SigningKey::from_pem(signing_pem.as_bytes()).unwrap().jwks();
        idp_jwks.keys[0].common.key_id = Some(KEY_ID.to_owned());

        let rp_key = SigningKey::generate().unwrap();
        let entry = |id: &str, extra: Value| {
            let mut entry = json!({
                "client_id": id,
                "client_name": format!("Relying party {id}"),
                "redirect_uris": [format!("https://{id}.example.com/cb")],
                "grant_types": ["authorization_code"],
                "scope": "openid",
                "jwks_uri": format!("{base}/keystore/{id}/application.jwks"),
                "claims": ["given_name", "family_name"],
                "claims_in_verified_claims": ["over18"],
                "status": "Active",
            });
            for (name, value) in extra.as_object().into_iter().flatten() {
                entry[name] = value.clone();
            }
            entry
        };
        let entries = vec![
            entry("rp-one", json!({})),
            entry(
                "rp-two",
                json!({"grant_types": ["authorization_code", "refresh_token"]}),
            ),
            entry("rp-inactive", json!({"status": "Inactive"})),
            entry("rp-three", json!({})),
            // Its key store answers 404, so it cannot be registered.
            entry(
                "rp-no-keys",
                json!({"jwks_uri": format!("{base}/keystore/missing/application.jwks")}),
            ),
            entry("rp-bad", json!({"redirect_uris": []})),
            entry("rp-four", json!({})),
            // Also defined in the provider's own configuration in one test.
            entry("test-rp", json!({"client_name": "From the registry"})),
        ];

        let registry = Arc::new(Registry {
            base: base.clone(),
            idp_jwks,
            rp_jwks: serde_json::to_value(rp_key.jwks()).unwrap(),
            entries: Mutex::new(entries),
            token_bound_to: Mutex::new(None),
            pages_requested: Mutex::new(Vec::new()),
            token_requests: Mutex::new(0),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(metadata))
            .route("/token", post(token))
            .route("/clients", get(clients))
            .route("/keystore/{id}/application.jwks", get(rp_jwks))
            .with_state(Arc::clone(&registry));
        let tls = tls::server_config(&identity, ClientCertPolicy::AnyProven).unwrap();
        let (shutdown, _task) = oxid::server::spawn_tls(listener, tls, router).unwrap();

        let config: ClientSyncConfig = toml::from_str(&format!(
            r#"
            enabled = true
            discovery_url = "{base}/.well-known/openid-configuration"
            clients_url = "{base}/clients"
            client_id = "{IDP_CLIENT_ID}"
            transport_cert = "{dir}/transport.pem"
            transport_key = "{dir}/transport.key"
            signing_key = "{dir}/signing.key"
            signing_key_id = "{KEY_ID}"
            ca = "{dir}/registry-ca.pem"
            page_size = {page_size}
            "#,
            dir = dir.display(),
        ))
        .unwrap();
        Self {
            registry,
            config,
            dir,
            shutdown,
        }
    }

    fn pages(&self) -> Vec<String> {
        self.registry.pages_requested.lock().unwrap().clone()
    }

    fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ids(clients: &[oxid::client::Client]) -> Vec<&str> {
    clients.iter().map(|client| client.id.as_str()).collect()
}

/// The clients the stand-in holds that can be registered, in its order.
const REGISTRABLE: [&str; 5] = ["rp-one", "rp-two", "rp-three", "rp-four", "test-rp"];

#[tokio::test]
async fn every_page_is_loaded_and_usable_clients_are_registered() {
    let registry = TestRegistry::start(3);
    let clients = fetch(&registry.config).await.unwrap();

    // Eight entries at three per page: all three pages were read.
    assert_eq!(registry.pages(), ["0", "1", "2"]);
    assert_eq!(*registry.registry.token_requests.lock().unwrap(), 1);
    // Inactive, keyless and malformed entries are left out; order is kept.
    assert_eq!(ids(&clients), REGISTRABLE);

    let one = &clients[0];
    assert_eq!(one.name, "Relying party rp-one");
    assert!(one.has_redirect_uri("https://rp-one.example.com/cb"));
    assert_eq!(one.sector_identifier, "rp-one.example.com");
    assert_eq!(one.profile, Profile::Connectid);
    assert_eq!(one.jwks.keys.len(), 1, "keys came from the jwks_uri");
    assert!(one.allows_claim("given_name") && one.allows_claim("over18"));
    assert!(!one.allows_claim("email"), "only accredited claims");
    assert!(!one.allows_refresh_tokens());
    assert!(clients[1].allows_refresh_tokens());
    registry.stop();
}

#[tokio::test]
async fn all_pages_are_loaded_whatever_the_page_size() {
    for (page_size, expected_pages) in [
        // Eight entries in fours: exactly two full pages, and no third.
        (4, vec!["0", "1"]),
        (5, vec!["0", "1"]),
        (50, vec!["0"]),
        (1, vec!["0", "1", "2", "3", "4", "5", "6", "7"]),
    ] {
        let registry = TestRegistry::start(page_size);
        let clients = fetch(&registry.config).await.unwrap();
        assert_eq!(registry.pages(), expected_pages, "page size {page_size}");
        assert_eq!(ids(&clients), REGISTRABLE, "page size {page_size}");
        registry.stop();
    }
}

#[tokio::test]
async fn an_empty_registry_yields_no_clients() {
    let registry = TestRegistry::start(50);
    registry.registry.entries.lock().unwrap().clear();
    let clients = fetch(&registry.config).await.unwrap();
    assert_eq!(clients.len(), 0);
    assert_eq!(registry.pages(), ["0"], "one request, then stop");
    registry.stop();
}

#[tokio::test]
async fn authentication_failures_stop_the_synchronisation() {
    // An assertion signed with a key the registry does not know.
    let registry = TestRegistry::start(3);
    std::fs::write(
        registry.dir.join("signing.key"),
        SigningKey::generate_pem().unwrap(),
    )
    .unwrap();
    let error = format!("{:#}", fetch(&registry.config).await.unwrap_err());
    assert!(
        error.contains("token endpoint") && error.contains("401"),
        "{error}"
    );
    assert_eq!(
        registry.pages().len(),
        0,
        "the clients endpoint was never called"
    );
    registry.stop();

    // The wrong key id.
    let registry = TestRegistry::start(3);
    let mut config = registry.config.clone();
    config.signing_key_id = "some-other-kid".to_owned();
    assert!(fetch(&config).await.is_err());

    // The wrong scope.
    let mut config = registry.config.clone();
    config.scope = "something:else".to_owned();
    let error = format!("{:#}", fetch(&config).await.unwrap_err());
    assert!(error.contains("400"), "{error}");

    // A registry whose certificate is not trusted.
    let mut config = registry.config.clone();
    config.ca = None;
    assert!(fetch(&config).await.is_err());

    // Missing key material.
    let mut config = registry.config.clone();
    config.transport_key = registry.dir.join("nowhere.key");
    let error = format!("{:#}", fetch(&config).await.unwrap_err());
    assert!(error.contains("nowhere.key"), "{error}");
    registry.stop();
}

#[tokio::test]
async fn provider_starts_with_configured_and_synchronised_clients() {
    let registry = TestRegistry::start(3);
    let sync = registry.config.clone();
    let op = TestOp::start_with(move |config| config.client_sync = Some(sync)).await;

    let clients = &op.state().clients;
    for id in ["rp-one", "rp-two", "rp-three", "rp-four"] {
        assert!(clients.get(id).is_some(), "{id}");
    }
    for id in ["rp-inactive", "rp-no-keys", "rp-bad"] {
        assert!(clients.get(id).is_none(), "{id}");
    }
    // The registry also lists `test-rp`; the configured definition wins.
    assert_eq!(clients.get("test-rp").unwrap().name, "Integration Test RP");

    // The configured client still works end to end.
    let tokens = op.tokens(&json!({})).await;
    assert!(tokens["id_token"].is_string());
    op.stop().await;
    registry.stop();
}

#[tokio::test]
async fn synchronisation_is_off_unless_enabled_and_failure_prevents_startup() {
    let registry = TestRegistry::start(3);

    // Present but disabled: the registry is never contacted.
    let mut disabled = registry.config.clone();
    disabled.enabled = false;
    let op = TestOp::start_with(move |config| config.client_sync = Some(disabled)).await;
    assert!(op.state().clients.get("rp-one").is_none());
    assert_eq!(*registry.registry.token_requests.lock().unwrap(), 0);
    op.stop().await;

    // Enabled but failing: the provider refuses to start.
    let mut broken = registry.config.clone();
    broken.signing_key_id = "unknown-kid".to_owned();
    let started = TestOp::try_start_with(move |config| config.client_sync = Some(broken)).await;
    let error = format!("{:#}", started.err().expect("startup must fail"));
    assert!(error.contains("synchronising clients"), "{error}");
    registry.stop();
}
