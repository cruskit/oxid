//! Negative and security-focused tests against a running oxID instance:
//! the FAPI 2.0 and ConnectID rules a compliant provider must enforce.

mod common;

use common::{ASSERTION_TYPE, CLIENT_ID, Pkce, REDIRECT_URI, TestOp, oauth_error, redirect_params};
use oxid::keys::SigningKey;
use oxid::util::b64url;
use reqwest::header::{LOCATION, WWW_AUTHENTICATE};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

async fn par_error(op: &TestOp, overrides: &Value) -> (StatusCode, String) {
    oauth_error(op.par(&op.request_object(&Pkce::new(), overrides)).await).await
}

// --- Sender-constrained access tokens (RFC 8705, ConnectID 4.2-3.1) --------

#[tokio::test]
async fn token_endpoint_requires_a_client_certificate() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let params = op.approve(&request_uri).await;

    // The public (non-alias) endpoint never sees a certificate.
    let response = op
        .rp
        .post(op.url("/token"))
        .form(&op.code_form(&params["code"], &pkce))
        .send()
        .await
        .unwrap();
    let (status, error) = oauth_error(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, "invalid_request");

    // Nor does the mTLS endpoint when the client presents none.
    let response = op
        .browser
        .post(op.mtls_url("/token"))
        .form(&op.code_form(&params["code"], &pkce))
        .send()
        .await
        .unwrap();
    assert_eq!(oauth_error(response).await.1, "invalid_request");
    op.stop().await;
}

#[tokio::test]
async fn access_token_only_works_with_the_certificate_it_is_bound_to() {
    let op = TestOp::start().await;
    let tokens = op.tokens(&json!({})).await;
    let access_token = tokens["access_token"].as_str().unwrap();

    let attempts: [(&str, &Client, String); 3] = [
        (
            "different certificate",
            &op.rp_other_cert,
            op.mtls_url("/userinfo"),
        ),
        ("no certificate", &op.browser, op.mtls_url("/userinfo")),
        ("public listener", &op.rp, op.url("/userinfo")),
    ];
    for (name, client, url) in attempts {
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        let challenge = response.headers()[WWW_AUTHENTICATE].to_str().unwrap();
        assert!(challenge.contains("invalid_token"), "{name}: {challenge}");
    }

    let ok = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    op.stop().await;
}

#[tokio::test]
async fn access_token_expires_within_ten_minutes() {
    let op = TestOp::start().await;
    let tokens = op.tokens(&json!({})).await;
    let expires_in = tokens["expires_in"].as_i64().unwrap();
    assert!(expires_in <= 600);
    op.clock.advance(expires_in);
    let response = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    op.stop().await;
}

// --- Authorization codes (FAPI 2.0 5.3.2.1-11, 5.3.2.2-9) ------------------

#[tokio::test]
async fn authorization_code_cannot_be_replayed() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let params = op.approve(&request_uri).await;

    let first: Value = op
        .exchange(&params["code"], &pkce)
        .await
        .json()
        .await
        .unwrap();
    let (status, error) = oauth_error(op.exchange(&params["code"], &pkce).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, "invalid_grant");

    // The replay revoked the token issued by the first exchange.
    let response = op
        .rp
        .get(op.mtls_url("/userinfo"))
        .bearer_auth(first["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    op.stop().await;
}

#[tokio::test]
async fn authorization_code_expires_after_sixty_seconds() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let params = op.approve(&request_uri).await;
    op.clock.advance(61);
    assert_eq!(
        oauth_error(op.exchange(&params["code"], &pkce).await)
            .await
            .1,
        "invalid_grant"
    );
    op.stop().await;
}

#[tokio::test]
async fn pkce_verifier_must_match() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let params = op.approve(&request_uri).await;
    let (status, error) = oauth_error(op.exchange(&params["code"], &Pkce::new()).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, "invalid_grant");
    op.stop().await;
}

// --- Pushed authorization requests (RFC 9126, FAPI 2.0 5.3.2.2) ------------

#[tokio::test]
async fn authorization_requests_must_be_pushed() {
    let op = TestOp::start().await;
    let direct = format!(
        "{}?client_id={CLIENT_ID}&response_type=code&scope=openid&state=xyz&redirect_uri={}",
        op.url("/authorize"),
        url::form_urlencoded::byte_serialize(REDIRECT_URI.as_bytes()).collect::<String>()
    );
    let response = op.browser.get(direct).send().await.unwrap();
    let params = redirect_params(&response);
    assert_eq!(params["error"], "invalid_request");
    assert_eq!(params["state"], "xyz");

    // An unregistered redirect_uri must never be redirected to.
    let evil = format!(
        "{}?client_id={CLIENT_ID}&response_type=code&redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
        op.url("/authorize")
    );
    let response = op.browser.get(evil).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response.headers().get(LOCATION).is_none(),
        "not an open redirector"
    );
    op.stop().await;
}

#[tokio::test]
async fn request_uri_is_single_use_and_expires() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    op.approve(&request_uri).await;
    let reused = op
        .browser
        .get(op.authorize_url(&request_uri))
        .send()
        .await
        .unwrap();
    assert_eq!(reused.status(), StatusCode::BAD_REQUEST);

    let request_uri = op.push(&pkce, &json!({})).await;
    op.clock.advance(600);
    let expired = op
        .browser
        .get(op.authorize_url(&request_uri))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    op.stop().await;
}

#[tokio::test]
async fn par_requires_client_authentication() {
    let op = TestOp::start().await;
    let request = op.request_object(&Pkce::new(), &json!({}));
    let response = op
        .rp
        .post(op.mtls_url("/par"))
        .form(&[("client_id", CLIENT_ID), ("request", request.as_str())])
        .send()
        .await
        .unwrap();
    let (status, error) = oauth_error(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error, "invalid_client");
    op.stop().await;
}

#[tokio::test]
async fn par_rejects_unsigned_requests() {
    let op = TestOp::start().await;
    let pkce = Pkce::new();
    let response = op
        .rp
        .post(op.mtls_url("/par"))
        .form(&[
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &op.assertion()),
            ("client_id", CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("code_challenge", &pkce.challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(oauth_error(response).await.1, "invalid_request");
    op.stop().await;
}

// --- Request objects (ConnectID 4.2-3.8 to 3.11) ---------------------------

#[tokio::test]
async fn request_object_lifetime_rules_are_enforced() {
    let op = TestOp::start().await;
    let now = op.now();
    let cases = [
        ("no exp", json!({"exp": null})),
        ("no nbf", json!({"nbf": null})),
        ("expired", json!({"nbf": now - 120, "exp": now - 60})),
        (
            "exp more than 10 minutes after nbf",
            json!({"exp": now + 601}),
        ),
        (
            "nbf more than 10 minutes old",
            json!({"nbf": now - 900, "exp": now + 60}),
        ),
        (
            "nbf far in the future",
            json!({"nbf": now + 120, "exp": now + 300}),
        ),
        (
            "wrong audience",
            json!({"aud": "https://not-this-op.example.com"}),
        ),
        ("wrong issuer", json!({"iss": "another-client"})),
    ];
    for (name, overrides) in cases {
        let (status, error) = par_error(&op, &overrides).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error, "invalid_request_object", "{name}");
    }

    // FAPI 2.0 5.3.2.1-13: 8 seconds of clock skew must be tolerated.
    op.push(&Pkce::new(), &json!({"nbf": now + 8})).await;
    // An array audience that includes the issuer is fine.
    op.push(
        &Pkce::new(),
        &json!({"aud": [op.issuer, "https://other.example.com"]}),
    )
    .await;
    op.stop().await;
}

#[tokio::test]
async fn request_object_must_be_signed_with_ps256_by_the_client() {
    let op = TestOp::start().await;
    let claims = op.request_claims(&Pkce::new(), &json!({}));

    let attacker = SigningKey::generate().unwrap();
    let forged = attacker.sign(None, &claims).unwrap();
    assert_eq!(
        oauth_error(op.par(&forged).await).await.1,
        "invalid_request_object"
    );

    let payload = b64url(claims.to_string());
    for alg in ["none", "RS256", "HS256"] {
        let header = b64url(json!({"alg": alg, "typ": "JWT"}).to_string());
        let token = format!("{header}.{payload}.c2lnbmF0dXJl");
        assert_eq!(
            oauth_error(op.par(&token).await).await.1,
            "invalid_request_object",
            "{alg}"
        );
    }

    // A valid signature over tampered claims.
    let good = op.request_object(&Pkce::new(), &json!({}));
    let mut parts: Vec<String> = good.split('.').map(str::to_owned).collect();
    parts[1] = b64url(
        op.request_claims(&Pkce::new(), &json!({"scope": "openid email"}))
            .to_string(),
    );
    assert_eq!(
        oauth_error(op.par(&parts.join(".")).await).await.1,
        "invalid_request_object"
    );
    op.stop().await;
}

#[tokio::test]
async fn authorization_parameters_are_validated_at_par() {
    let op = TestOp::start().await;
    let cases = [
        (
            json!({"response_type": "code id_token"}),
            "unsupported_response_type",
        ),
        (
            json!({"response_type": "token"}),
            "unsupported_response_type",
        ),
        (json!({"redirect_uri": null}), "invalid_request"),
        (
            json!({"redirect_uri": "https://evil.example.com/cb"}),
            "invalid_request",
        ),
        (json!({"code_challenge": null}), "invalid_request"),
        (json!({"code_challenge_method": "plain"}), "invalid_request"),
        (json!({"code_challenge_method": null}), "invalid_request"),
        (json!({"response_mode": "fragment"}), "invalid_request"),
        (json!({"scope": "openid accounts"}), "invalid_scope"),
        (json!({"client_id": "another-client"}), "invalid_request"),
        (json!({"purpose": "x".repeat(301)}), "invalid_request"),
        (
            json!({"request_uri": "urn:ietf:params:oauth:request_uri:nested"}),
            "invalid_request_object",
        ),
    ];
    for (overrides, expected) in cases {
        let (status, error) = par_error(&op, &overrides).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{overrides}");
        assert_eq!(error, expected, "{overrides}");
    }
    // Optional parameters really are optional, and long values are accepted.
    op.push(&Pkce::new(), &json!({"state": null, "nonce": null}))
        .await;
    op.push(
        &Pkce::new(),
        &json!({"nonce": "n".repeat(64), "purpose": "\u{1100}".repeat(300)}),
    )
    .await;
    op.stop().await;
}

// --- Purpose (OAuth 2 Purpose 3) --------------------------------------------

#[tokio::test]
async fn invalid_purpose_fails_with_the_specified_error() {
    let op = TestOp::start().await;
    for purpose in [
        json!("ab"),
        json!("x".repeat(301)),
        json!("   "),
        json!("two\nlines"),
        json!(42),
    ] {
        let response = op
            .par(&op.request_object(&Pkce::new(), &json!({"purpose": purpose})))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{purpose}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"], "invalid_request", "{purpose}");
        if purpose.is_string() {
            assert_eq!(body["error_description"], "invalid_purpose", "{purpose}");
        }
    }
    // The boundaries themselves are accepted, as is a request with no purpose.
    for purpose in [json!("abc"), json!("x".repeat(300)), Value::Null] {
        op.push(&Pkce::new(), &json!({"purpose": purpose})).await;
    }
    op.stop().await;
}

// --- Client authentication (ConnectID 4.2-3.4, FAPI 2.0 5.3.2.1-8) ---------

#[tokio::test]
async fn client_assertions_are_strictly_validated() {
    let op = TestOp::start().await;
    let now = op.now();
    let cases = [
        (
            "token endpoint as audience",
            json!({"aud": op.url("/token")}),
        ),
        (
            "PAR endpoint as audience",
            json!({"aud": op.mtls_url("/par")}),
        ),
        ("array audience", json!({"aud": [op.issuer]})),
        ("expired", json!({"exp": now - 300})),
        ("no exp", json!({"exp": null})),
        ("no sub", json!({"sub": null})),
        ("no jti", json!({"jti": null})),
        ("iat far in the future", json!({"iat": now + 120})),
        ("unknown client", json!({"iss": "ghost", "sub": "ghost"})),
    ];
    for (name, overrides) in cases {
        let response = op
            .rp
            .post(op.mtls_url("/par"))
            .form(&[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &op.assertion_with(&overrides)),
                ("request", &op.request_object(&Pkce::new(), &json!({}))),
            ])
            .send()
            .await
            .unwrap();
        let (status, error) = oauth_error(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(error, "invalid_client", "{name}");
    }
    op.stop().await;
}

#[tokio::test]
async fn client_assertion_cannot_be_replayed() {
    let op = TestOp::start().await;
    let assertion = op.assertion();
    let send = || async {
        op.rp
            .post(op.mtls_url("/par"))
            .form(&[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", assertion.as_str()),
                ("request", &op.request_object(&Pkce::new(), &json!({}))),
            ])
            .send()
            .await
            .unwrap()
    };
    assert_eq!(send().await.status(), StatusCode::CREATED);
    assert_eq!(oauth_error(send().await).await.1, "invalid_client");
    op.stop().await;
}

#[tokio::test]
async fn assertion_signed_by_another_key_is_rejected() {
    let op = TestOp::start().await;
    let attacker = SigningKey::generate().unwrap();
    let now = op.now();
    let assertion = attacker
        .sign(
            None,
            &json!({"iss": CLIENT_ID, "sub": CLIENT_ID, "aud": op.issuer, "jti": "x", "exp": now + 60}),
        )
        .unwrap();
    let response = op
        .rp
        .post(op.mtls_url("/par"))
        .form(&[
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
            ("request", &op.request_object(&Pkce::new(), &json!({}))),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(oauth_error(response).await.1, "invalid_client");
    op.stop().await;
}

// --- Grants and transport -------------------------------------------------

#[tokio::test]
async fn password_grant_is_rejected() {
    let op = TestOp::start().await;
    let response = op
        .rp
        .post(op.mtls_url("/token"))
        .form(&[
            ("grant_type", "password"),
            ("username", "demo"),
            ("password", "demo-password"),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &op.assertion()),
        ])
        .send()
        .await
        .unwrap();
    let (status, error) = oauth_error(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, "unsupported_grant_type");
    op.stop().await;
}

#[tokio::test]
async fn tls_1_2_and_1_3_are_both_served_and_hsts_is_set() {
    let op = TestOp::start().await;
    // This test is about protocol versions, not trust, so it skips
    // certificate verification rather than wiring up the generated cert.
    for version in [
        reqwest::tls::Version::TLS_1_2,
        reqwest::tls::Version::TLS_1_3,
    ] {
        let client = Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .tls_version_min(version)
            .tls_version_max(version)
            .build()
            .unwrap();
        let response = client.get(op.url("/healthz")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{version:?}");
        assert!(
            response.headers()["strict-transport-security"]
                .to_str()
                .unwrap()
                .contains("max-age="),
            "HSTS (FAPI 2.0 5.2.3)"
        );
    }
    op.stop().await;
}

#[tokio::test]
async fn plain_http_is_not_served() {
    let op = TestOp::start().await;
    let http_url = op.url("/healthz").replace("https://", "http://");
    let client = Client::builder().build().unwrap();
    assert!(
        client.get(http_url).send().await.is_err(),
        "the listener only speaks TLS"
    );
    op.stop().await;
}

#[tokio::test]
async fn server_shuts_down_cleanly() {
    let op = TestOp::start().await;
    let url = op.url("/healthz");
    let browser = op.browser.clone();
    assert_eq!(
        browser.get(&url).send().await.unwrap().status(),
        StatusCode::OK
    );
    op.stop().await;
    assert!(
        browser.get(&url).send().await.is_err(),
        "nothing is listening after shutdown"
    );
}
