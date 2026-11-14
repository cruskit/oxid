
use serde_json::json;

use super::test_support::valid_assertion;
use super::*;
use crate::client::StaticClientRegistry;
use crate::client::test_support::client_with_key;
use crate::error::ErrorCode;
use crate::keys::SigningKey;
use crate::keys::test_support::shared_key;
use crate::util::b64url;

const ISSUER: &str = "https://op.example.com";
const NOW: i64 = 1_800_000_000;

fn registry() -> StaticClientRegistry {
    StaticClientRegistry::new([client_with_key("rp", shared_key())]).unwrap()
}

fn attempt(assertion: &str, client_id: Option<&str>) -> Result<Authenticated, OAuthError> {
    authenticate(
        Credentials {
            client_id,
            client_assertion_type: Some(ASSERTION_TYPE),
            client_assertion: Some(assertion),
        },
        &registry(),
        ISSUER,
        10,
        NOW,
    )
}

fn check(claims: &Value) -> Result<Authenticated, OAuthError> {
    attempt(&shared_key().sign(Some("JWT"), claims).unwrap(), None)
}

fn with(name: &str, value: Value) -> Value {
    let mut claims = valid_assertion(ISSUER, NOW);
    claims[name] = value;
    claims
}

fn without(name: &str) -> Value {
    let mut claims = valid_assertion(ISSUER, NOW);
    claims.as_object_mut().unwrap().remove(name);
    claims
}

fn rejected(claims: &Value) {
    assert_eq!(
        check(claims).unwrap_err().code,
        ErrorCode::InvalidClient,
        "{claims}"
    );
}

#[test]
fn accepts_a_valid_assertion() {
    let auth = check(&valid_assertion(ISSUER, NOW)).unwrap();
    assert_eq!(auth.client.id, "rp");
    assert_eq!(auth.jti, "jti-1");
    assert_eq!(auth.expires_at, NOW + 60);
}

#[test]
fn client_id_parameter_must_agree_with_the_assertion() {
    let token = shared_key()
        .sign(None, &valid_assertion(ISSUER, NOW))
        .unwrap();
    attempt(&token, Some("rp")).unwrap();
    assert!(attempt(&token, Some("other")).is_err());
}

#[test]
fn requires_assertion_and_correct_type() {
    let token = shared_key()
        .sign(None, &valid_assertion(ISSUER, NOW))
        .unwrap();
    let missing = authenticate(Credentials::default(), &registry(), ISSUER, 10, NOW);
    assert_eq!(missing.unwrap_err().code, ErrorCode::InvalidClient);

    let wrong_type = authenticate(
        Credentials {
            client_id: None,
            client_assertion_type: Some("urn:ietf:params:oauth:client-assertion-type:saml2-bearer"),
            client_assertion: Some(&token),
        },
        &registry(),
        ISSUER,
        10,
        NOW,
    );
    assert!(wrong_type.is_err());
}

#[test]
fn audience_must_be_the_issuer_as_a_single_string() {
    rejected(&with("aud", json!(format!("{ISSUER}/token"))));
    rejected(&with("aud", json!(format!("{ISSUER}/par"))));
    rejected(&with("aud", json!([ISSUER])));
    rejected(&with("aud", json!([ISSUER, format!("{ISSUER}/token")])));
    rejected(&without("aud"));
}

#[test]
fn iss_and_sub_must_both_be_the_client() {
    rejected(&with("sub", json!("someone-else")));
    rejected(&without("sub"));
    rejected(&with("iss", json!("unknown-client")));
    rejected(&without("iss"));
}

#[test]
fn expiry_is_enforced() {
    rejected(&without("exp"));
    rejected(&with("exp", json!(NOW)));
    rejected(&with("exp", json!(NOW - 300)));
    rejected(&with("exp", json!(NOW + 86_400)));
}

#[test]
fn iat_and_nbf_tolerate_small_skew_only() {
    check(&with("iat", json!(NOW + 10))).unwrap();
    rejected(&with("iat", json!(NOW + 61)));
    check(&with("nbf", json!(NOW + 10))).unwrap();
    rejected(&with("nbf", json!(NOW + 61)));
}

#[test]
fn jti_is_mandatory() {
    rejected(&without("jti"));
    rejected(&with("jti", json!("")));
}

#[test]
fn rejects_assertions_signed_by_another_key() {
    let attacker = SigningKey::generate().unwrap();
    let token = attacker.sign(None, &valid_assertion(ISSUER, NOW)).unwrap();
    assert_eq!(
        attempt(&token, None).unwrap_err().code,
        ErrorCode::InvalidClient
    );
}

#[test]
fn rejects_rs256_and_unsigned_assertions() {
    let payload = b64url(valid_assertion(ISSUER, NOW).to_string());
    for alg in ["RS256", "none", "HS256"] {
        let token = format!("{}.{payload}.c2ln", b64url(json!({"alg": alg}).to_string()));
        assert_eq!(
            attempt(&token, None).unwrap_err().code,
            ErrorCode::InvalidClient,
            "{alg}"
        );
    }
    assert!(attempt("not-a-jwt", None).is_err());
}
