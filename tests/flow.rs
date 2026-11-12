//! End-to-end authorization code flow against a running oxID instance.

mod common;

use common::{ASSERTION_TYPE, CLIENT_ID, Pkce, TestOp, oauth_error, redirect_params};
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

/// A `claims` parameter asking for everything the ConnectID identity
/// assurance profile defines, in the ID token.
fn every_connectid_claim() -> Value {
    json!({"id_token": {
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
                "over21": null,
                "over25": null,
                "over65": {"essential": true},
                "beneficiary_account_au": {"essential": false},
                "beneficiary_account_au_payid": null,
                "beneficiary_account_international": {"essential": true},
            },
        },
    }})
}

#[tokio::test]
async fn connectid_identity_claims_are_returned_in_the_id_token() {
    let op = TestOp::start().await;
    let tokens = op
        .tokens(&json!({
            "purpose": "Verifying your identity to open an account",
            "claims": every_connectid_claim(),
        }))
        .await;
    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;

    assert_eq!(claims["given_name"], "Alex");
    assert_eq!(claims["middle_name"], "Jordan");
    assert_eq!(claims["family_name"], "Citizen");
    assert_eq!(claims["email"], "alex.citizen@example.com");
    assert_eq!(claims["birthdate"], "1985-04-12");
    assert_eq!(claims["phone_number"], "+61 400 000 000");
    assert_eq!(
        claims["address"],
        json!({
            "street_address": "1 Example Street",
            "locality": "Sydney",
            "region": "NSW",
            "postal_code": "2000",
            "country": "Australia",
        })
    );
    assert_eq!(claims["txn"].as_str().unwrap().len(), 36);
    assert!(!claims.contains_key("acr"), "ConnectID forbids acr");
    assert_eq!(
        claims["verified_claims"],
        json!({
            "verification": {"trust_framework": "au_connectid"},
            "claims": {
                "over16": true,
                "over18": true,
                "over21": true,
                "over25": true,
                "over65": false,
                "beneficiary_account_au": {
                    "beneficiary_name": "Alex Jordan Citizen",
                    "account_bsb": "123456",
                    "account_number": "12345678",
                },
                "beneficiary_account_au_payid": {
                    "beneficiary_name": "Alex Jordan Citizen",
                    "payid": "alex.citizen@example.com",
                    "payid_type": "/EMAL",
                },
                "beneficiary_account_international": {
                    "beneficiary_name": "Alex Jordan Citizen",
                    "bic_swift_code": "OXIDAU2SXXX",
                    "account_number_international": "12345612345678",
                    "beneficiary_residential_address":
                        "1 Example Street, Sydney, NSW 2000, Australia",
                },
            },
        })
    );
    op.stop().await;
}

#[tokio::test]
async fn verified_claims_without_the_connectid_trust_framework_are_ignored() {
    let op = TestOp::start().await;
    for verification in [
        json!({"trust_framework": null}),
        json!({"trust_framework": {"value": "uk_tfida"}}),
        json!({}),
    ] {
        let tokens = op
            .tokens(&json!({"claims": {"id_token": {
                "given_name": null,
                "verified_claims": {"verification": verification, "claims": {"over18": null}},
            }}}))
            .await;
        let claims = op
            .verify_id_token(tokens["id_token"].as_str().unwrap())
            .await;
        assert_eq!(claims["given_name"], "Alex");
        assert!(!claims.contains_key("verified_claims"));
    }
    op.stop().await;
}

#[tokio::test]
async fn clients_receive_only_the_claims_they_are_provisioned_for() {
    let op = TestOp::start_with(|config| {
        config.clients[0].claims = Some(vec![
            "given_name".to_owned(),
            "over18".to_owned(),
            "beneficiary_account_au".to_owned(),
        ]);
    })
    .await;
    let pkce = Pkce::new();
    let request_uri = op
        .push(&pkce, &json!({"claims": every_connectid_claim()}))
        .await;

    // The consent page offers only what will be shared.
    let page = op.open_login(&request_uri).await;
    assert!(page.html.contains("data-claim=\"given_name\""));
    assert!(page.html.contains("data-claim=\"beneficiary_account_au\""));
    assert!(!page.html.contains("data-claim=\"email\""));
    assert!(!page.html.contains("data-claim=\"over65\""));

    let response = op
        .decide(&page, &request_uri, DEMO_USERNAME, DEMO_PASSWORD, "approve")
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
    for withheld in [
        "family_name",
        "email",
        "birthdate",
        "phone_number",
        "address",
    ] {
        assert!(!claims.contains_key(withheld), "{withheld}");
    }
    assert_eq!(claims["given_name"], "Alex");
    assert!(claims.contains_key("txn"), "txn is issued regardless");
    let verified = claims["verified_claims"]["claims"].as_object().unwrap();
    assert_eq!(verified.len(), 2, "{verified:?}");
    assert_eq!(verified["over18"], true);
    assert_eq!(verified["beneficiary_account_au"]["account_bsb"], "123456");
    op.stop().await;
}

#[tokio::test]
async fn oidc_profile_clients_get_standard_claims_by_scope_and_claims_parameter() {
    let op = TestOp::start_with(|config| {
        let client = &mut config.clients[0];
        client.profile = oxid::client::Profile::Oidc;
        client.scopes = ["openid", "profile", "email", "phone", "address"]
            .map(str::to_owned)
            .to_vec();
    })
    .await;
    let tokens = op
        .tokens(&json!({
            "scope": "openid profile email",
            "claims": {"id_token": {
                "nickname": null,
                "phone_number_verified": {"essential": true},
                // ConnectID verified claims do not exist for this profile.
                "verified_claims": {
                    "verification": {"trust_framework": {"value": "au_connectid"}},
                    "claims": {"over18": null},
                },
            }},
        }))
        .await;
    assert_eq!(tokens["scope"], "openid profile email");

    // With only an oidc client registered, discovery advertises that profile.
    let metadata: Value = op
        .browser
        .get(op.url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        metadata["scopes_supported"],
        json!(["openid", "profile", "email", "phone", "address"])
    );
    let advertised = metadata["claims_supported"].as_array().unwrap();
    for claim in ["name", "nickname", "email_verified", "updated_at", "txn"] {
        assert!(advertised.contains(&json!(claim)), "{claim}");
    }
    assert!(metadata.get("verified_claims_supported").is_none());

    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;
    assert_eq!(claims["nickname"], "Al");
    assert_eq!(claims["phone_number_verified"], true);
    assert!(!claims.contains_key("verified_claims"));
    assert!(!claims.contains_key("name"), "scope claims go to UserInfo");

    let userinfo: Value = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(userinfo["sub"], claims["sub"]);
    for (claim, expected) in [
        ("name", json!("Alex Jordan Citizen")),
        ("given_name", json!("Alex")),
        ("family_name", json!("Citizen")),
        ("middle_name", json!("Jordan")),
        ("nickname", json!("Al")),
        ("preferred_username", json!("alex")),
        ("profile", json!("https://example.com/people/alex")),
        ("picture", json!("https://example.com/people/alex.jpg")),
        ("website", json!("https://alex.example.com")),
        ("gender", json!("non-binary")),
        ("birthdate", json!("1985-04-12")),
        ("zoneinfo", json!("Australia/Sydney")),
        ("locale", json!("en-AU")),
        ("updated_at", json!(1_767_225_600)),
        ("email", json!("alex.citizen@example.com")),
        ("email_verified", json!(true)),
    ] {
        assert_eq!(userinfo[claim], expected, "{claim}");
    }
    // The phone and address scopes were not requested.
    assert!(userinfo.get("phone_number").is_none());
    assert!(userinfo.get("address").is_none());
    op.stop().await;
}

#[tokio::test]
async fn users_choose_which_voluntary_claims_to_share() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op
        .push(
            &pkce,
            &json!({"claims": {
                "id_token": {
                    "given_name": {"essential": true},
                    "family_name": null,
                    "email": {"essential": false},
                    "verified_claims": {
                        "verification": {"trust_framework": {"value": "au_connectid"}},
                        "claims": {
                            "over18": {"essential": true},
                            "beneficiary_account_au": null,
                        },
                    },
                },
                "userinfo": {"email": null, "phone_number": null},
            }}),
        )
        .await;

    let page = op.open_login(&request_uri).await;
    // Voluntary claims are ticked checkboxes; essential ones have none.
    assert_eq!(
        page.ticked(),
        [
            "share_beneficiary_account_au",
            "share_email",
            "share_family_name",
            "share_phone_number",
        ]
    );
    assert!(
        page.html
            .contains("data-claim=\"given_name\" data-essential=\"true\"")
    );
    assert!(
        page.html
            .contains("data-claim=\"over18\" data-essential=\"true\"")
    );

    let response = op
        .decide_declining(
            &page,
            &request_uri,
            DEMO_USERNAME,
            DEMO_PASSWORD,
            "approve",
            &["email", "beneficiary_account_au"],
        )
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
    assert_eq!(claims["given_name"], "Alex");
    assert_eq!(claims["family_name"], "Citizen");
    assert!(!claims.contains_key("email"));
    assert_eq!(claims["verified_claims"]["claims"], json!({"over18": true}));

    // The choice holds for UserInfo and across a refresh.
    let userinfo: Value = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(userinfo.get("email").is_none());
    assert_eq!(userinfo["phone_number"], "+61 400 000 000");

    let refreshed: Value = op
        .rp
        .post(op.mtls_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &op.assertion()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let claims = op
        .verify_id_token(refreshed["id_token"].as_str().unwrap())
        .await;
    assert!(!claims.contains_key("email"));
    assert_eq!(claims["family_name"], "Citizen");

    let record = op
        .state()
        .store
        .consent(claims["txn"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.declined, ["beneficiary_account_au", "email"]);
    assert_eq!(
        record.claims,
        ["family_name", "given_name", "over18", "phone_number"]
    );
    op.stop().await;
}

#[tokio::test]
async fn purpose_is_shown_escaped_and_recorded_with_the_transaction() {
    let op = TestOp::start().await;
    let purpose = "Confirm you are over 18 for <Bottle & Co> — order #4521";
    let pkce = Pkce::new();
    let request_uri = op
        .push(
            &pkce,
            &json!({
                "purpose": purpose,
                "claims": {"id_token": {"verified_claims": {
                    "verification": {"trust_framework": {"value": "au_connectid"}},
                    "claims": {"over18": {"essential": true}},
                }}},
            }),
        )
        .await;
    let page = op.open_login(&request_uri).await;
    assert!(
        page.html
            .contains("Confirm you are over 18 for &lt;Bottle &amp; Co&gt; — order #4521"),
        "{}",
        page.html
    );
    assert!(!page.html.contains("<Bottle"));

    let response = op
        .decide(&page, &request_uri, DEMO_USERNAME, DEMO_PASSWORD, "approve")
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

    // The record is keyed by the txn the client received.
    let record = op
        .state()
        .store
        .consent(claims["txn"].as_str().unwrap())
        .await
        .unwrap()
        .expect("transaction recorded");
    assert_eq!(record.purpose.as_deref(), Some(purpose));
    assert_eq!(record.client_id, CLIENT_ID);
    assert_eq!(record.claims, ["over18"]);
    assert_eq!(record.user_subject.as_deref(), Some("demo-user-0001"));
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
async fn userinfo_returns_claims_requested_for_it_and_only_openid_is_a_scope() {
    let op = TestOp::start().await;
    let tokens = op
        .tokens(&json!({"claims": {
            "userinfo": {"email": null},
            "id_token": {"given_name": null},
        }}))
        .await;
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
    assert_eq!(userinfo.as_object().unwrap().len(), 2, "sub and email");

    let claims = op
        .verify_id_token(tokens["id_token"].as_str().unwrap())
        .await;
    assert!(!claims.contains_key("email"));
    assert_eq!(claims["given_name"], "Alex");

    // ConnectID defines no claim scopes: claims come from the claims parameter.
    let response = op
        .par(&op.request_object(&Pkce::new(), &json!({"scope": "openid email"})))
        .await;
    assert_eq!(oauth_error(response).await.1, "invalid_scope");
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
            password_hash: Some(hash),
            subject: "user-sam".into(),
            claims: json!({"given_name": "Sam"}).as_object().unwrap().clone(),
            bank_account: None,
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
