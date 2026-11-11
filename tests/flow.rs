//! End-to-end authorization code flow against a running oxID instance.

mod common;

use common::{CLIENT_ID, Pkce, TestOp, oauth_error, redirect_params};
use oxid::user::{DEMO_PASSWORD, DEMO_USERNAME};
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn discovery_document_describes_this_instance() {
    let op = TestOp::start().await;
    let response = op
        .browser
        .get(op.url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata: Value = response.json().await.unwrap();

    assert_eq!(metadata["issuer"], op.issuer);
    assert_eq!(metadata["token_endpoint"], op.url("/token"));
    assert_eq!(
        metadata["mtls_endpoint_aliases"]["token_endpoint"],
        op.mtls_url("/token")
    );
    assert_eq!(
        metadata["mtls_endpoint_aliases"]["pushed_authorization_request_endpoint"],
        op.mtls_url("/par")
    );
    assert_eq!(
        metadata["mtls_endpoint_aliases"]["userinfo_endpoint"],
        op.mtls_url("/userinfo")
    );
    assert_eq!(metadata["subject_types_supported"], json!(["pairwise"]));

    // Every advertised endpoint is actually served.
    let jwks: Value = op
        .browser
        .get(metadata["jwks_uri"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    op.stop().await;
}

#[tokio::test]
async fn full_code_flow_issues_verifiable_bound_tokens() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();

    // 1. Back channel: push the signed request over mutual TLS.
    let response = op.par(&op.request_object(&pkce, &json!({}))).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let pushed: Value = response.json().await.unwrap();
    let request_uri = pushed["request_uri"].as_str().unwrap();
    assert!(pushed["expires_in"].as_i64().unwrap() < 600);

    // 2. Front channel: the user signs in and approves.
    let page = op.open_login(request_uri).await;
    assert!(page.html.contains("Integration Test RP"));
    let response = op
        .decide(&page, request_uri, DEMO_USERNAME, DEMO_PASSWORD, "approve")
        .await;
    let params = redirect_params(&response);
    assert_eq!(params["state"], "state-123");
    assert_eq!(params["iss"], op.issuer, "RFC 9207 issuer identification");

    // 3. Back channel: exchange the code.
    let response = op.exchange(&params["code"], &pkce).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let tokens: Value = response.json().await.unwrap();
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["expires_in"].as_i64().unwrap() <= 600);

    // 4. The ID token verifies against the published keys.
    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;
    assert_eq!(claims["iss"], op.issuer);
    assert_eq!(claims["aud"], CLIENT_ID);
    assert_eq!(claims["nonce"], "nonce-456");
    assert!(claims["txn"].as_str().is_some_and(|txn| !txn.is_empty()));
    assert!(claims["exp"].as_i64().unwrap() > op.now());

    // 5. UserInfo over the same mutual TLS identity.
    let response = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let userinfo: Value = response.json().await.unwrap();
    assert_eq!(userinfo["sub"], claims["sub"]);
    op.stop().await;
}

#[tokio::test]
async fn connectid_identity_claims_are_returned_in_the_id_token() {
    let op = TestOp::start().await;
    let tokens = op
        .tokens(&json!({
            "purpose": "Verifying your identity to open an account",
            "claims": {"id_token": {
                "given_name": null,
                "middle_name": {},
                "family_name": {"essential": true},
                "email": {"essential": false},
                "birthdate": null,
                "phone_number": {},
                "address": {"essential": true},
                "txn": {"essential": true},
                "verified_claims": {
                    "verification": {"trust_framework": {"value": "au_connectid"}},
                    "claims": {
                        "over16": {"essential": true},
                        "over18": {"essential": true},
                        "over65": {"essential": true},
                        "beneficiary_account_au": {"essential": false},
                    },
                },
            }},
        }))
        .await;
    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;

    for claim in [
        "given_name",
        "middle_name",
        "family_name",
        "email",
        "birthdate",
        "phone_number",
        "address",
        "txn",
    ] {
        assert!(claims.contains_key(claim), "missing {claim}");
    }
    assert_eq!(
        claims["verified_claims"],
        json!({
            "verification": {"trust_framework": "au_connectid"},
            "claims": {"over16": true, "over18": true, "over65": false},
        })
    );
    op.stop().await;
}

#[tokio::test]
async fn subject_is_pairwise_and_stable() {
    let op = TestOp::start().await;
    let first = op.tokens(&json!({})).await;
    let second = op.tokens(&json!({})).await;
    let mut subs = Vec::new();
    for tokens in [&first, &second] {
        let claims = op
            .verify_id_token(tokens["id_token"].as_str().unwrap())
            .await;
        subs.push(claims["sub"].as_str().unwrap().to_owned());
    }
    let (a, b) = (subs[0].clone(), subs[1].clone());
    assert_eq!(a, b, "same user and client always get the same sub");
    assert_ne!(a, "demo-user-0001", "the internal subject is never exposed");
    assert_ne!(a, DEMO_USERNAME);
    op.stop().await;
}

#[tokio::test]
async fn scope_claims_are_served_from_userinfo() {
    let op = TestOp::start().await;
    let tokens = op.tokens(&json!({"scope": "openid email"})).await;
    assert_eq!(tokens["scope"], "openid email");
    let userinfo: Value = op
        .rp
        .post(op.mtls_url("/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(userinfo["email"], "alex.citizen@example.com");
    assert_eq!(userinfo["email_verified"], true);

    // Scope claims go to UserInfo, not the ID token (OIDC Core 5.4).
    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;
    assert!(!claims.contains_key("email"));
    op.stop().await;
}

#[tokio::test]
async fn refresh_token_grant_issues_a_working_access_token() {
    let op = TestOp::start().await;
    let tokens = op.tokens(&json!({})).await;
    let refresh_token = tokens["refresh_token"].as_str().unwrap();

    let response = op
        .rp
        .post(op.mtls_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_assertion_type", common::ASSERTION_TYPE),
            ("client_assertion", &op.assertion()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed: Value = response.json().await.unwrap();
    assert_ne!(refreshed["access_token"], tokens["access_token"]);
    assert!(
        refreshed.get("refresh_token").is_none(),
        "no rotation (FAPI 2.0 5.3.2.1-9)"
    );

    let response = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(refreshed["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    op.stop().await;
}

#[tokio::test]
async fn user_can_deny_the_request() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let response = op.decide(&page, &request_uri, "", "", "deny").await;
    let params = redirect_params(&response);
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["state"], "state-123");
    assert_eq!(params["iss"], op.issuer);
    assert!(!params.contains_key("code"));
    op.stop().await;
}

#[tokio::test]
async fn wrong_password_does_not_issue_a_code() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let response = op
        .decide(
            &page,
            &request_uri,
            DEMO_USERNAME,
            "not-the-password",
            "approve",
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "login page is shown again"
    );
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("username or password is incorrect")
    );

    // The same pushed request still works with the right password.
    let response = op
        .decide(&page, &request_uri, DEMO_USERNAME, DEMO_PASSWORD, "approve")
        .await;
    assert!(redirect_params(&response).contains_key("code"));
    op.stop().await;
}

#[tokio::test]
async fn interaction_id_is_echoed_on_par_token_and_userinfo() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let id = "93bac548-d2de-4546-b106-880a5018460d";

    let response = op
        .rp
        .post(op.mtls_url("/par"))
        .header("x-fapi-interaction-id", id)
        .form(&[
            ("client_assertion_type", common::ASSERTION_TYPE),
            ("client_assertion", &op.assertion()),
            ("request", &op.request_object(&pkce, &json!({}))),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-fapi-interaction-id"], id);
    let request_uri = response.json::<Value>().await.unwrap()["request_uri"]
        .as_str()
        .unwrap()
        .to_owned();

    let params = op.approve(&request_uri).await;
    let response = op
        .rp
        .post(op.mtls_url("/token"))
        .header("x-fapi-interaction-id", id)
        .form(&op.code_form(&params["code"], &pkce))
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-fapi-interaction-id"], id);
    let tokens: Value = response.json().await.unwrap();

    let response = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .header("x-fapi-interaction-id", id)
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-fapi-interaction-id"], id);

    // Without one, the server generates a UUID.
    let response = op.par(&op.request_object(&Pkce::new(), &json!({}))).await;
    let generated = response.headers()["x-fapi-interaction-id"]
        .to_str()
        .unwrap();
    assert_eq!(generated.len(), 36, "{generated}");
    op.stop().await;
}

#[tokio::test]
async fn configured_users_replace_the_demo_user() {
    let hash = oxid::user::hash_password("s3cret").unwrap();
    let op = TestOp::start_with(|config| {
        config.users.push(oxid::config::UserConfig {
            username: "sam".into(),
            password_hash: hash,
            subject: "user-sam".into(),
            claims: json!({"given_name": "Sam"}).as_object().unwrap().clone(),
        });
    })
    .await;
    let pkce = Pkce::new();
    let request_uri = op
        .push(
            &pkce,
            &json!({"claims": {"id_token": {"given_name": null}}}),
        )
        .await;
    let page = op.open_login(&request_uri).await;

    let demo = op
        .decide(&page, &request_uri, DEMO_USERNAME, DEMO_PASSWORD, "approve")
        .await;
    assert_eq!(
        demo.status(),
        StatusCode::OK,
        "demo user is not available once users are configured"
    );

    let response = op
        .decide(&page, &request_uri, "sam", "s3cret", "approve")
        .await;
    let params = redirect_params(&response);
    let tokens: Value = op
        .exchange(&params["code"], &pkce)
        .await
        .json()
        .await
        .unwrap();
    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;
    assert_eq!(claims["given_name"], "Sam");
    op.stop().await;
}

#[tokio::test]
async fn back_channel_errors_are_json_oauth_errors() {
    let op = TestOp::start().await;
    let response = op
        .rp
        .post(op.mtls_url("/token"))
        .form(&[("grant_type", "password")])
        .send()
        .await
        .unwrap();
    let (status, error) = oauth_error(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error, "invalid_client");
    op.stop().await;
}
