
use serde_json::json;

use super::test_support::{ISSUER, valid_claims};
use super::*;
use crate::client::test_support::client_with_key;
use crate::error::ErrorCode;
use crate::keys::SigningKey;
use crate::keys::test_support::shared_key;
use crate::util::b64url;

const NOW: i64 = 1_800_000_000;

fn check(claims: &Value) -> Result<Map<String, Value>, OAuthError> {
    let token = shared_key()
        .sign(Some("oauth-authz-req+jwt"), claims)
        .unwrap();
    verify(
        &token,
        &client_with_key("rp", shared_key()),
        ISSUER,
        &SecurityConfig::default(),
        NOW,
    )
}

fn with(name: &str, value: Value) -> Value {
    let mut claims = valid_claims(NOW);
    claims[name] = value;
    claims
}

fn without(name: &str) -> Value {
    let mut claims = valid_claims(NOW);
    claims.as_object_mut().unwrap().remove(name);
    claims
}

fn rejected(claims: &Value) {
    assert_eq!(
        check(claims).unwrap_err().code,
        ErrorCode::InvalidRequestObject,
        "{claims}"
    );
}

#[test]
fn accepts_a_valid_request_object() {
    let claims = check(&valid_claims(NOW)).unwrap();
    assert_eq!(claims["redirect_uri"], "https://rp.example.com/cb");
}

#[test]
fn accepts_multiple_audiences_including_the_issuer() {
    check(&with("aud", json!(["https://other.example.com", ISSUER]))).unwrap();
}

#[test]
fn rejects_wrong_or_missing_audience() {
    rejected(&with("aud", json!("https://other.example.com")));
    rejected(&with("aud", json!(["https://other.example.com"])));
    rejected(&with("aud", json!(format!("{ISSUER}/token"))));
    rejected(&without("aud"));
}

#[test]
fn rejects_wrong_issuer() {
    rejected(&with("iss", json!("someone-else")));
    rejected(&without("iss"));
}

#[test]
fn exp_and_nbf_are_mandatory() {
    rejected(&without("exp"));
    rejected(&without("nbf"));
}

#[test]
fn rejects_expired_request_objects() {
    let mut claims = valid_claims(NOW);
    claims["nbf"] = json!(NOW - 400);
    claims["exp"] = json!(NOW - 1);
    rejected(&claims);
    rejected(&with("exp", json!(NOW)));
}

#[test]
fn nbf_may_be_slightly_in_the_future_but_not_far() {
    // FAPI 2.0 §5.3.2.1-13: accept up to 10 seconds, reject over 60.
    check(&with("nbf", json!(NOW + 8))).unwrap();
    check(&with("nbf", json!(NOW + 10))).unwrap();
    rejected(&with("nbf", json!(NOW + 61)));
}

#[test]
fn nbf_older_than_ten_minutes_is_rejected() {
    let mut claims = valid_claims(NOW);
    claims["exp"] = json!(NOW + 1);
    claims["nbf"] = json!(NOW - 599);
    check(&claims).unwrap();
    claims["nbf"] = json!(NOW - 601);
    rejected(&claims);
    // ConnectID test case: nbf 15 minutes ago.
    claims["nbf"] = json!(NOW - 900);
    claims["exp"] = json!(NOW + 60);
    rejected(&claims);
}

#[test]
fn lifetime_over_ten_minutes_is_rejected() {
    check(&with("exp", json!(NOW + 600))).unwrap();
    rejected(&with("exp", json!(NOW + 601)));
    rejected(&with("exp", json!(NOW + 3600)));
}

#[test]
fn iat_far_in_the_future_is_rejected() {
    check(&with("iat", json!(NOW + 10))).unwrap();
    rejected(&with("iat", json!(NOW + 61)));
    check(&without("iat")).unwrap();
}

#[test]
fn rejects_signature_from_an_unregistered_key() {
    let attacker = SigningKey::generate().unwrap();
    let token = attacker.sign(None, &valid_claims(NOW)).unwrap();
    let err = verify(
        &token,
        &client_with_key("rp", shared_key()),
        ISSUER,
        &SecurityConfig::default(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRequestObject);
}

#[test]
fn rejects_unsigned_and_rs256_request_objects() {
    let client = client_with_key("rp", shared_key());
    let payload = b64url(valid_claims(NOW).to_string());
    for alg in ["none", "RS256"] {
        let header = b64url(json!({"alg": alg}).to_string());
        let token = format!("{header}.{payload}.c2ln");
        let err = verify(&token, &client, ISSUER, &SecurityConfig::default(), NOW).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequestObject, "{alg}");
    }
    let unsecured = format!("{}.{payload}.", b64url(json!({"alg": "none"}).to_string()));
    assert!(verify(&unsecured, &client, ISSUER, &SecurityConfig::default(), NOW).is_err());
}

#[test]
fn rejects_unexpected_typ() {
    let token = shared_key()
        .sign(Some("at+jwt"), &valid_claims(NOW))
        .unwrap();
    let client = client_with_key("rp", shared_key());
    assert!(verify(&token, &client, ISSUER, &SecurityConfig::default(), NOW).is_err());
    let token = shared_key().sign(Some("JWT"), &valid_claims(NOW)).unwrap();
    verify(&token, &client, ISSUER, &SecurityConfig::default(), NOW).unwrap();
}
