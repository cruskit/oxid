use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;

use super::*;
use crate::http::PATH_USERINFO;
use crate::jose::{SigningAlg, UnverifiedJws};
use crate::testing::http::tokens;
use crate::testing::http::{CERT, Harness, json_body};

async fn call(harness: &Harness, cert: Option<&str>, authorization: Option<&str>) -> Response {
    let mut request = Request::get(PATH_USERINFO);
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    harness
        .send(cert, request.body(Body::empty()).unwrap())
        .await
}

#[tokio::test]
async fn returns_sub_matching_the_id_token_and_requested_claims() {
    let harness = Harness::new();
    let body = tokens(
        &harness,
        &json!({"claims": {"userinfo": {"email": null, "address": {"essential": true}}}}),
    )
    .await;
    let access = body["access_token"].as_str().unwrap();
    let id_token = UnverifiedJws::parse(body["id_token"].as_str().unwrap(), &[SigningAlg::PS256])
        .unwrap()
        .skip_verification_in_tests();

    let response = call(&harness, Some(CERT), Some(&format!("Bearer {access}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let info = json_body(response).await;
    assert_eq!(info["sub"].as_str(), id_token.str_claim("sub"));
    assert_eq!(info["email"], "alex.citizen@example.com");
    assert_eq!(info["address"]["locality"], "Sydney");
    assert!(info.get("given_name").is_none());
}

#[tokio::test]
async fn scheme_is_case_insensitive_and_post_is_allowed() {
    let harness = Harness::new();
    let body = tokens(&harness, &json!({})).await;
    let access = body["access_token"].as_str().unwrap();
    for scheme in ["bearer", "BEARER", "Bearer"] {
        let response = call(&harness, Some(CERT), Some(&format!("{scheme} {access}"))).await;
        assert_eq!(response.status(), StatusCode::OK, "{scheme}");
    }
    let post = Request::post(PATH_USERINFO)
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        harness.send(Some(CERT), post).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn token_is_unusable_without_the_bound_certificate() {
    let harness = Harness::new();
    let body = tokens(&harness, &json!({})).await;
    let auth = format!("Bearer {}", body["access_token"].as_str().unwrap());

    for cert in [None, Some("a-different-certificate")] {
        let response = call(&harness, cert, Some(&auth)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{cert:?}");
        let challenge = response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    }
}

#[tokio::test]
async fn missing_malformed_unknown_and_expired_tokens_are_rejected() {
    let harness = Harness::new();
    let missing = call(&harness, Some(CERT), None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.headers()[header::WWW_AUTHENTICATE], "Bearer");

    for bad in [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        "Bearer unknown-token",
    ] {
        let response = call(&harness, Some(CERT), Some(bad)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{bad}");
    }

    let body = tokens(&harness, &json!({})).await;
    let auth = format!("Bearer {}", body["access_token"].as_str().unwrap());
    harness
        .clock
        .advance(harness.state.security.access_token_ttl);
    assert_eq!(
        call(&harness, Some(CERT), Some(&auth)).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refresh_token_is_not_accepted_as_an_access_token() {
    let harness = Harness::new();
    let body = tokens(&harness, &json!({})).await;
    let auth = format!("Bearer {}", body["refresh_token"].as_str().unwrap());
    assert_eq!(
        call(&harness, Some(CERT), Some(&auth)).await.status(),
        StatusCode::UNAUTHORIZED
    );
}
