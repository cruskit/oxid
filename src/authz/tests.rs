
use serde_json::json;

use super::test_support::valid_params;
use super::*;
use crate::client::test_support::client_with_key;
use crate::keys::test_support::shared_key;

fn client() -> Client {
    client_with_key("rp", shared_key())
}

fn with(name: &str, value: Value) -> Map<String, Value> {
    let mut params = valid_params();
    params.insert(name.to_owned(), value);
    params
}

fn without(name: &str) -> Map<String, Value> {
    let mut params = valid_params();
    params.remove(name);
    params
}

fn code(params: &Map<String, Value>) -> ErrorCode {
    AuthorizationRequest::from_params(&client(), params)
        .unwrap_err()
        .code
}

#[test]
fn accepts_a_valid_request() {
    let request = AuthorizationRequest::from_params(&client(), &valid_params()).unwrap();
    assert_eq!(request.client_id, "rp");
    assert_eq!(request.scope, ["openid"]);
    assert_eq!(request.state.as_deref(), Some("st-1"));
    assert_eq!(request.nonce.as_deref(), Some("n-1"));
    assert!(request.is_openid());
    assert!(request.claims.is_empty());
    assert!(request.purpose.is_none());
}

#[test]
fn state_and_nonce_are_optional() {
    let request = AuthorizationRequest::from_params(&client(), &without("state")).unwrap();
    assert!(request.state.is_none());
    let request = AuthorizationRequest::from_params(&client(), &without("nonce")).unwrap();
    assert!(request.nonce.is_none());
}

#[test]
fn supports_64_character_nonce() {
    let nonce = "n".repeat(64);
    let request =
        AuthorizationRequest::from_params(&client(), &with("nonce", json!(nonce))).unwrap();
    assert_eq!(request.nonce.unwrap().len(), 64);
    assert_eq!(
        code(&with("nonce", json!("n".repeat(MAX_NONCE_LEN + 1)))),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&with("state", json!("s".repeat(MAX_STATE_LEN + 1)))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn response_type_must_be_code() {
    for bad in ["code id_token", "token", "id_token"] {
        assert_eq!(
            code(&with("response_type", json!(bad))),
            ErrorCode::UnsupportedResponseType,
            "{bad}"
        );
    }
    assert_eq!(code(&without("response_type")), ErrorCode::InvalidRequest);
}

#[test]
fn redirect_uri_is_required_and_must_be_registered() {
    assert_eq!(code(&without("redirect_uri")), ErrorCode::InvalidRequest);
    assert_eq!(
        code(&with("redirect_uri", json!("https://evil.example.com/cb"))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn pkce_s256_is_mandatory() {
    assert_eq!(code(&without("code_challenge")), ErrorCode::InvalidRequest);
    assert_eq!(
        code(&without("code_challenge_method")),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&with("code_challenge_method", json!("plain"))),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&with("code_challenge", json!("short"))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn scope_must_be_permitted_for_the_client() {
    assert_eq!(code(&without("scope")), ErrorCode::InvalidRequest);
    assert_eq!(code(&with("scope", json!("  "))), ErrorCode::InvalidScope);
    assert_eq!(
        code(&with("scope", json!("openid payments"))),
        ErrorCode::InvalidScope
    );
    let request =
        AuthorizationRequest::from_params(&client(), &with("scope", json!("email openid")))
            .unwrap();
    assert_eq!(request.scope, ["email", "openid"]);
}

#[test]
fn client_id_must_match_the_authenticated_client() {
    assert_eq!(
        code(&with("client_id", json!("other"))),
        ErrorCode::InvalidRequest
    );
    assert_eq!(code(&without("client_id")), ErrorCode::InvalidRequest);
}

#[test]
fn nested_request_references_are_rejected() {
    assert_eq!(
        code(&with("request", json!("a.b.c"))),
        ErrorCode::InvalidRequestObject
    );
    assert_eq!(
        code(&with(
            "request_uri",
            json!("urn:ietf:params:oauth:request_uri:x")
        )),
        ErrorCode::InvalidRequestObject
    );
}

#[test]
fn only_query_response_mode_is_allowed() {
    AuthorizationRequest::from_params(&client(), &with("response_mode", json!("query"))).unwrap();
    for bad in ["fragment", "jwt", "form_post"] {
        assert_eq!(
            code(&with("response_mode", json!(bad))),
            ErrorCode::InvalidRequest,
            "{bad}"
        );
    }
}

#[test]
fn purpose_length_is_bounded_in_characters_not_bytes() {
    // Hangul Jamo are three bytes each in UTF-8.
    let ok = "\u{1100}".repeat(PURPOSE_MAX_CHARS);
    let request =
        AuthorizationRequest::from_params(&client(), &with("purpose", json!(ok))).unwrap();
    assert_eq!(request.purpose.unwrap().chars().count(), 300);

    let too_long = "\u{1100}".repeat(PURPOSE_MAX_CHARS + 1);
    assert_eq!(
        code(&with("purpose", json!(too_long))),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&with("purpose", json!("ab"))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn invalid_purpose_is_reported_as_the_specification_requires() {
    for bad in [
        json!("ab"),
        json!(""),
        json!("x".repeat(301)),
        json!("   "),
        json!("line one\nline two"),
        json!("bell\u{7}"),
    ] {
        let err = AuthorizationRequest::from_params(&client(), &with("purpose", bad.clone()))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest, "{bad}");
        assert_eq!(err.description, INVALID_PURPOSE, "{bad}");
    }
    assert_eq!(
        code(&with("purpose", json!(["a", "list"]))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn purpose_accepts_text_in_any_language() {
    for ok in [
        "abc",
        "Verify your identity to open an account",
        "Vérification d'identité — ouverture de compte",
        "口座開設のための本人確認",
        "<b>Markup is kept as text & escaped on display</b>",
    ] {
        let request =
            AuthorizationRequest::from_params(&client(), &with("purpose", json!(ok))).unwrap();
        assert_eq!(request.purpose.as_deref(), Some(ok));
    }
    assert!(is_valid_purpose(&"x".repeat(300)));
}

#[test]
fn claims_parameter_is_parsed_and_validated() {
    let request = AuthorizationRequest::from_params(
        &client(),
        &with("claims", json!({"id_token": {"given_name": null}})),
    )
    .unwrap();
    assert!(request.claims.id_token.contains_key("given_name"));
    assert_eq!(
        code(&with("claims", json!({"id_token": 1}))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn non_string_parameters_are_rejected() {
    assert_eq!(code(&with("state", json!(123))), ErrorCode::InvalidRequest);
    assert_eq!(
        code(&with("scope", json!(["openid"]))),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn prompt_none_yields_login_required() {
    assert_eq!(
        code(&with("prompt", json!("none"))),
        ErrorCode::LoginRequired
    );
    AuthorizationRequest::from_params(&client(), &with("prompt", json!("login consent"))).unwrap();
}
