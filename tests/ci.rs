//! The `ci` experience, end to end against a running instance: nobody
//! clicks anything, and the client chooses the response.

mod common;

use common::{ASSERTION_TYPE, Pkce, TestOp, redirect_params};
use oxid::experience::Kind;
use reqwest::StatusCode;
use serde_json::{Value, json};

/// The default response is not held back, so tests do not wait.
async fn start() -> TestOp {
    TestOp::start_with(|config| {
        config.experience = Kind::Ci;
        config.ci.response_delay = 0;
    })
    .await
}

fn claims_request() -> Value {
    json!({
        "claims": {"id_token": {
            "given_name": {"essential": true},
            "family_name": null,
            "email": null,
        }},
    })
}

/// Choose the response to a pushed request, as the relying party.
async fn choose(op: &TestOp, request_uri: &str, fields: &[(&str, &str)]) -> (StatusCode, Value) {
    let assertion = op.assertion();
    let mut form = vec![
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
        ("request_uri", request_uri),
    ];
    form.extend_from_slice(fields);
    let response = op
        .rp
        .post(op.mtls_url("/ci/response"))
        .form(&form)
        .send()
        .await
        .unwrap();
    (response.status(), response.json().await.unwrap())
}

/// Fetch the authorization URL, as `curl` would, and read the redirect.
async fn arrive(op: &TestOp, request_uri: &str) -> std::collections::HashMap<String, String> {
    let response = op
        .browser
        .get(op.authorize_url(request_uri))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    redirect_params(&response)
}

async fn id_token_claims(op: &TestOp, code: &str, pkce: &Pkce) -> serde_json::Map<String, Value> {
    let response = op.exchange(code, pkce).await;
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    op.verify_id_token(body["id_token"].as_str().unwrap()).await
}

#[tokio::test]
async fn a_plain_get_completes_the_flow_for_the_default_user() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &claims_request()).await;

    let params = arrive(&op, &request_uri).await;
    assert_eq!(params["iss"], op.issuer);
    let claims = id_token_claims(&op, &params["code"], &pkce).await;
    assert_eq!(claims["given_name"], "Alex");
    assert_eq!(claims["family_name"], "Citizen");
    assert!(claims.contains_key("email"));
    op.stop().await;
}

#[tokio::test]
async fn the_client_chooses_the_user_and_which_voluntary_claims_come_back() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &claims_request()).await;

    let (status, body) = choose(
        &op,
        &request_uri,
        &[("user", "margaret"), ("voluntary_claims", "family_name")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["claims"], json!(["family_name", "given_name"]));
    assert_eq!(body["declined"], json!(["email"]));

    let params = arrive(&op, &request_uri).await;
    let claims = id_token_claims(&op, &params["code"], &pkce).await;
    let users = op.state().users.list();
    let margaret = users.iter().find(|user| user.username == "margaret");
    let margaret = &margaret.unwrap().claims;
    assert_eq!(claims["given_name"], margaret["given_name"]);
    assert_eq!(claims["family_name"], margaret["family_name"]);
    assert!(
        !claims.contains_key("email"),
        "declined on the user's behalf"
    );
    op.stop().await;
}

#[tokio::test]
async fn the_client_chooses_an_error() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({"state": "from-the-test"})).await;

    let (status, body) = choose(
        &op,
        &request_uri,
        &[("outcome", "error"), ("error", "consent_required")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let params = arrive(&op, &request_uri).await;
    assert_eq!(params["error"], "consent_required");
    assert_eq!(
        params["error_description"],
        "the user's consent is required"
    );
    assert_eq!(params["state"], "from-the-test");
    assert_eq!(params["iss"], op.issuer);
    assert!(!params.contains_key("code"));
    op.stop().await;
}

#[tokio::test]
async fn choosing_a_response_needs_client_authentication() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let response = op
        .rp
        .post(op.mtls_url("/ci/response"))
        .form(&[("request_uri", request_uri.as_str()), ("outcome", "error")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // The request is untouched: it still gets the default response.
    assert!(arrive(&op, &request_uri).await.contains_key("code"));
    op.stop().await;
}

#[tokio::test]
async fn the_options_are_published() {
    let op = start().await;
    let options: Value = op
        .browser
        .get(op.url("/ci"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(options["response_endpoint"], op.url("/ci/response"));
    assert_eq!(options["default_user"], "demo");
    op.stop().await;
}
