use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::client_auth::ASSERTION_TYPE;
use crate::http::PATH_TOKEN;
use crate::jose::{Jws, SigningAlg};
use crate::testing::VERIFIER;
use crate::testing::http::approve;
use crate::testing::http::{CERT, Harness, json_body};
use crate::testing::http::{exchange, tokens};
use crate::testing::state::ISSUER;

async fn error_of(response: axum::http::Response<axum::body::Body>) -> (StatusCode, String) {
    let status = response.status();
    (
        status,
        json_body(response).await["error"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

async fn post(
    harness: &Harness,
    cert: Option<&str>,
    fields: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut all = vec![
        ("client_assertion_type", ASSERTION_TYPE.to_owned()),
        ("client_assertion", harness.assertion()),
    ];
    all.extend(fields.iter().map(|(k, v)| (*k, (*v).to_owned())));
    let borrowed: Vec<(&str, &str)> = all.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let response = harness.post_form(cert, PATH_TOKEN, &borrowed).await;
    let status = response.status();
    (status, json_body(response).await)
}

#[tokio::test]
async fn code_exchange_returns_bound_tokens_and_a_valid_id_token() {
    let harness = Harness::new();
    let body = tokens(&harness, &json!({})).await;
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid");
    let expires_in = body["expires_in"].as_i64().unwrap();
    assert!(expires_in > 0 && expires_in <= 600, "ConnectID 4.2-3.2");
    assert!(body["refresh_token"].is_string());

    let access = body["access_token"].as_str().unwrap();
    let stored = harness
        .state
        .store
        .access_token(access, harness.state.now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.cert_thumbprint, CERT);

    let jws = Jws::parse(body["id_token"].as_str().unwrap(), &[SigningAlg::PS256]).unwrap();
    jws.verify(&harness.state.signing_key.jwks()).unwrap();
    assert_eq!(jws.str_claim("iss"), Some(ISSUER));
    assert_eq!(jws.str_claim("aud"), Some("rp"));
    assert_eq!(jws.str_claim("nonce"), Some("n-1"));
    assert!(jws.str_claim("txn").is_some_and(|t| !t.is_empty()));
}

#[tokio::test]
async fn response_is_not_cacheable() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    let response = exchange(&harness, Some(CERT), &code).await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
}

#[tokio::test]
async fn requested_id_token_claims_are_returned() {
    let harness = Harness::new();
    let body = tokens(
        &harness,
        &json!({"claims": {"id_token": {
            "given_name": {"essential": true},
            "family_name": null,
            "verified_claims": {
                "verification": {"trust_framework": {"value": "au_connectid"}},
                "claims": {"over18": {"essential": true}},
            },
        }}}),
    )
    .await;
    let jws = Jws::parse(body["id_token"].as_str().unwrap(), &[SigningAlg::PS256]).unwrap();
    assert_eq!(jws.str_claim("given_name"), Some("Alex"));
    assert_eq!(jws.str_claim("family_name"), Some("Citizen"));
    assert_eq!(
        jws.claims["verified_claims"]["verification"]["trust_framework"],
        "au_connectid"
    );
    assert_eq!(jws.claims["verified_claims"]["claims"]["over18"], true);
    assert!(!jws.claims.contains_key("email"));
}

#[tokio::test]
async fn declined_claims_are_left_out_of_tokens_and_userinfo() {
    use crate::testing::http::approve_declining;
    let harness = Harness::new();
    let uri = harness
        .push(&json!({"claims": {
            "id_token": {
                "given_name": {"essential": true},
                "family_name": null,
                "email": null,
                "verified_claims": {
                    "verification": {"trust_framework": {"value": "au_connectid"}},
                    "claims": {"over18": null, "over21": null},
                },
            },
            "userinfo": {"email": null, "phone_number": null},
        }}))
        .await;
    // given_name is essential, so trying to decline it changes nothing.
    let code = approve_declining(&harness, &uri, &["email", "over21", "given_name"]).await;
    let body = json_body(exchange(&harness, Some(CERT), &code).await).await;
    let jws = Jws::parse(body["id_token"].as_str().unwrap(), &[SigningAlg::PS256]).unwrap();
    assert_eq!(jws.str_claim("given_name"), Some("Alex"));
    assert_eq!(jws.str_claim("family_name"), Some("Citizen"));
    assert!(!jws.claims.contains_key("email"));
    assert_eq!(
        jws.claims["verified_claims"]["claims"],
        json!({"over18": true})
    );

    let grant = harness
        .state
        .store
        .access_token(body["access_token"].as_str().unwrap(), harness.state.now())
        .await
        .unwrap()
        .unwrap()
        .grant;
    let client = harness.state.clients.get("rp").unwrap();
    let user = harness
        .state
        .users
        .find_by_subject(&grant.user_subject)
        .unwrap();
    let userinfo = crate::id_token::userinfo(&harness.state, &client, &user, &grant);
    assert!(!userinfo.contains_key("email"), "declined everywhere");
    assert_eq!(userinfo["phone_number"], "+61 400 000 000");
}

#[tokio::test]
async fn token_request_without_a_client_certificate_is_refused() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    let (status, error) = error_of(exchange(&harness, None, &code).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, "invalid_request");
    // The code was not consumed by the refused attempt.
    assert_eq!(
        exchange(&harness, Some(CERT), &code).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn code_reuse_is_rejected_and_revokes_issued_tokens() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    let first = json_body(exchange(&harness, Some(CERT), &code).await).await;
    let access = first["access_token"].as_str().unwrap();

    let (status, error) = error_of(exchange(&harness, Some(CERT), &code).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, "invalid_grant");
    assert!(
        harness
            .state
            .store
            .access_token(access, harness.state.now())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_code_is_rejected() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    harness
        .clock
        .advance(harness.state.security.authorization_code_ttl);
    let (_, error) = error_of(exchange(&harness, Some(CERT), &code).await).await;
    assert_eq!(error, "invalid_grant");
}

#[tokio::test]
async fn pkce_verifier_is_required_and_checked() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    let base = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://rp.example.com/cb"),
    ];
    let (status, body) = post(&harness, Some(CERT), &base).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "missing verifier");

    let wrong = "x".repeat(43);
    let mut fields = base.to_vec();
    fields.push(("code_verifier", &wrong));
    let (_, body) = post(&harness, Some(CERT), &fields).await;
    assert_eq!(body["error"], "invalid_grant", "wrong verifier");
}

#[tokio::test]
async fn redirect_uri_must_match_the_authorization_request() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    let (_, body) = post(
        &harness,
        Some(CERT),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", VERIFIER),
            ("redirect_uri", "https://rp.example.com/other"),
        ],
    )
    .await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn client_authentication_is_required() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let code = approve(&harness, &uri).await;
    let response = harness
        .post_form(
            Some(CERT),
            PATH_TOKEN,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp"),
            ],
        )
        .await;
    let (status, error) = error_of(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error, "invalid_client");
}

#[tokio::test]
async fn unsupported_and_missing_grant_types_are_rejected() {
    let harness = Harness::new();
    for (grant, expected) in [
        (Some("password"), "unsupported_grant_type"),
        (Some("client_credentials"), "unsupported_grant_type"),
        (None, "invalid_request"),
    ] {
        let fields: Vec<(&str, &str)> = grant.map(|g| ("grant_type", g)).into_iter().collect();
        let (status, body) = post(&harness, Some(CERT), &fields).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], expected, "{grant:?}");
    }
}

#[tokio::test]
async fn refresh_issues_a_new_bound_access_token_without_rotation() {
    let harness = Harness::new();
    let first = tokens(&harness, &json!({})).await;
    let refresh = first["refresh_token"].as_str().unwrap();

    let (status, body) = post(
        &harness,
        Some("another-cert"),
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(body["access_token"], first["access_token"]);
    assert!(
        body.get("refresh_token").is_none(),
        "refresh tokens are not rotated"
    );
    assert!(body["id_token"].is_string());
    let access = body["access_token"].as_str().unwrap();
    let stored = harness
        .state
        .store
        .access_token(access, harness.state.now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.cert_thumbprint, "another-cert",
        "bound to the cert on this request"
    );

    // The same refresh token keeps working.
    let (status, _) = post(
        &harness,
        Some(CERT),
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn refresh_scope_can_narrow_but_not_widen() {
    let harness = Harness::new();
    let first = tokens(&harness, &json!({"scope": "openid email"})).await;
    let refresh = first["refresh_token"].as_str().unwrap();

    let (status, body) = post(
        &harness,
        Some(CERT),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("scope", "openid"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "openid");

    let (_, body) = post(
        &harness,
        Some(CERT),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("scope", "openid profile"),
        ],
    )
    .await;
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn invalid_refresh_tokens_are_rejected() {
    let harness = Harness::new();
    let first = tokens(&harness, &json!({})).await;
    let access = first["access_token"].as_str().unwrap();
    for bad in ["unknown", access] {
        let (status, body) = post(
            &harness,
            Some(CERT),
            &[("grant_type", "refresh_token"), ("refresh_token", bad)],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }
    let (_, body) = post(&harness, Some(CERT), &[("grant_type", "refresh_token")]).await;
    assert_eq!(body["error"], "invalid_request");

    harness
        .clock
        .advance(harness.state.security.refresh_token_ttl);
    let refresh = first["refresh_token"].as_str().unwrap();
    let (_, body) = post(
        &harness,
        Some(CERT),
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(body["error"], "invalid_grant", "expired");
}
