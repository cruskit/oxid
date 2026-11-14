//! Fixtures shared by the unit tests, in one place.
//!
//! - this module: protocol-level values (keys, clients, users, request
//!   parameters, assertions) that need no running provider;
//! - [`state`]: an [`AppState`](crate::state::AppState) on a manual clock;
//! - [`http`]: the router driven in-process, and the browser and token legs
//!   of the flow.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde_json::{Map, Value, json};

use crate::client::{Client, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN, Profile};
use crate::config::ClientConfig;
use crate::keys::SigningKey;
use crate::user::{StaticUserStore, default_time_zone};

#[path = "../../tests/common/html.rs"]
#[allow(
    dead_code,
    reason = "shared with the integration tests, which use the rest"
)]
pub mod html;
pub mod http;
pub mod state;

/// The issuer every fixture uses.
pub const ISSUER: &str = "https://op.example.com";

/// RSA generation is slow in debug builds, so tests share one key.
pub fn shared_key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::generate().expect("generate test key"))
}

/// Hashing is slow, so tests share one demo store.
pub fn demo_store() -> &'static StaticUserStore {
    static STORE: OnceLock<StaticUserStore> = OnceLock::new();
    STORE.get_or_init(|| StaticUserStore::demo(&default_time_zone()).expect("demo store"))
}

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

/// S256 challenge for [`VERIFIER`].
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// A complete, valid set of parameters for client `rp`.
pub fn valid_params() -> Map<String, Value> {
    json!({
        "client_id": "rp",
        "redirect_uri": "https://rp.example.com/cb",
        "response_type": "code",
        "scope": "openid",
        "state": "st-1",
        "nonce": "n-1",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    })
    .as_object()
    .unwrap()
    .clone()
}

/// Claims of a valid request object issued at `now` by client `rp`.
pub fn valid_claims(now: i64) -> Value {
    let mut claims = valid_params();
    claims.insert("iss".into(), json!("rp"));
    claims.insert("aud".into(), json!(ISSUER));
    claims.insert("nbf".into(), json!(now));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(now + 300));
    Value::Object(claims)
}

/// Claims of a valid assertion from client `rp`.
pub fn valid_assertion(issuer: &str, now: i64) -> Value {
    json!({
        "iss": "rp",
        "sub": "rp",
        "aud": issuer,
        "jti": "jti-1",
        "iat": now,
        "exp": now + 60,
    })
}

/// A consent in which the user shares every claim that exists.
pub fn everything() -> BTreeSet<String> {
    crate::claims::OIDC_STANDARD_CLAIMS
        .iter()
        .map(|&name| name.to_owned())
        .chain(crate::claims::verified_claims_supported())
        .collect()
}
