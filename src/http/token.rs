//! Token endpoint: authorization code and refresh token grants.
//!
//! Every access token is bound to the TLS client certificate presented on
//! the request (RFC 8705 §3; ConnectID §4.2-3.1). A request without a
//! certificate cannot be issued a token.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::{Map, Value, json};

use super::{ConnInfo, OAuthForm, Params, authenticate_client, no_store};
use crate::authz::SCOPE_OPENID;
use crate::client::{Client, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN};
use crate::error::{ErrorCode, OAuthError};
use crate::id_token;
use crate::pkce;
use crate::state::AppState;
use crate::store::{AccessToken, CodeRedemption, Grant, RefreshToken};

pub async fn token(
    State(state): State<AppState>,
    Extension(conn): Extension<ConnInfo>,
    OAuthForm(params): OAuthForm,
) -> Result<Response, OAuthError> {
    let client = authenticate_client(&state, &params).await?;

    let thumbprint = conn.client_cert.map(|cert| cert.thumbprint).ok_or_else(|| {
        OAuthError::invalid_request(
            "a TLS client certificate is required: use the token endpoint from mtls_endpoint_aliases",
        )
    })?;

    let body = match params.get("grant_type") {
        Some(GRANT_AUTHORIZATION_CODE) => code_grant(&state, &client, &params, &thumbprint).await?,
        Some(GRANT_REFRESH_TOKEN) => refresh_grant(&state, &client, &params, &thumbprint).await?,
        Some(_) => {
            return Err(OAuthError::new(
                ErrorCode::UnsupportedGrantType,
                "grant_type must be authorization_code or refresh_token",
            ));
        }
        None => return Err(OAuthError::invalid_request("grant_type is required")),
    };
    Ok(no_store(Json(Value::Object(body)).into_response()))
}

async fn code_grant(
    state: &AppState,
    client: &Client,
    params: &Params,
    thumbprint: &str,
) -> Result<Map<String, Value>, OAuthError> {
    let code = params
        .get("code")
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    // A code issued under PKCE cannot be redeemed without its verifier, so a
    // missing one is a problem with the grant (RFC 7636 §4.6), as a wrong
    // one is.
    let verifier = params
        .get("code_verifier")
        .ok_or_else(|| OAuthError::invalid_grant("code_verifier is required"))?;
    let redirect_uri = params
        .get("redirect_uri")
        .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;

    let code = match state
        .store
        .redeem_code(code, &client.id, state.now())
        .await?
    {
        CodeRedemption::Valid(code) => code,
        CodeRedemption::Replayed => {
            tracing::warn!(client_id = %client.id, "authorization code replayed; grant revoked");
            return Err(OAuthError::invalid_grant(
                "authorization code has already been used",
            ));
        }
        CodeRedemption::Invalid => {
            return Err(OAuthError::invalid_grant(
                "authorization code is invalid or has expired",
            ));
        }
    };
    if code.redirect_uri != redirect_uri {
        return Err(OAuthError::invalid_grant(
            "redirect_uri does not match the authorization request",
        ));
    }
    if !pkce::verify(verifier, &code.code_challenge) {
        return Err(OAuthError::invalid_grant(
            "code_verifier does not match the code_challenge",
        ));
    }

    let mut body = issue_tokens(
        state,
        client,
        &code.grant,
        code.nonce.as_deref(),
        thumbprint,
    )
    .await?;
    if client.allows_refresh_tokens() {
        let refresh = state
            .store
            .issue_refresh_token(RefreshToken {
                grant: code.grant.clone(),
                expires_at: state.now() + state.security.refresh_token_ttl,
            })
            .await?;
        body.insert("refresh_token".to_owned(), refresh.into());
    }
    Ok(body)
}

async fn refresh_grant(
    state: &AppState,
    client: &Client,
    params: &Params,
    thumbprint: &str,
) -> Result<Map<String, Value>, OAuthError> {
    if !client.allows_refresh_tokens() {
        return Err(OAuthError::new(
            ErrorCode::UnauthorizedClient,
            "this client may not use the refresh_token grant",
        ));
    }
    let presented = params
        .get("refresh_token")
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let invalid = || OAuthError::invalid_grant("refresh token is invalid or has expired");
    let refresh = state
        .store
        .refresh_token(presented, state.now())
        .await?
        .ok_or_else(invalid)?;
    if refresh.grant.client_id != client.id {
        return Err(invalid());
    }

    // The scope may be narrowed for this access token, never widened
    // (RFC 6749 §6).
    let mut grant = refresh.grant;
    if let Some(scope) = params.get("scope") {
        let requested: Vec<String> = scope
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if requested.iter().any(|s| !grant.scope.contains(s)) {
            return Err(OAuthError::invalid_scope(
                "scope exceeds the original grant",
            ));
        }
        grant.scope = requested;
    }

    // The refresh token is not rotated (FAPI 2.0 §5.3.2.1-9); the client
    // keeps using the one it has.
    issue_tokens(state, client, &grant, None, thumbprint).await
}

/// Issue a certificate-bound access token and, for `OpenID` requests, an ID
/// token.
async fn issue_tokens(
    state: &AppState,
    client: &Client,
    grant: &Grant,
    nonce: Option<&str>,
    thumbprint: &str,
) -> Result<Map<String, Value>, OAuthError> {
    let expires_in = state.security.access_token_ttl;
    let access_token = state
        .store
        .issue_access_token(AccessToken {
            grant: grant.clone(),
            cert_thumbprint: thumbprint.to_owned(),
            expires_at: state.now() + expires_in,
        })
        .await?;

    let Value::Object(mut body) = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": grant.scope.join(" "),
    }) else {
        unreachable!("literal is an object");
    };

    if grant.scope.iter().any(|s| s == SCOPE_OPENID) {
        let user = state
            .users
            .find_by_subject(&grant.user_subject)
            .ok_or_else(|| OAuthError::invalid_grant("the user no longer exists"))?;
        let id_token = id_token::issue(state, client, &user, grant, nonce, &access_token)
            .map_err(OAuthError::server_error)?;
        body.insert("id_token".to_owned(), id_token.into());
    }
    tracing::info!(client_id = %client.id, "tokens issued");
    Ok(body)
}

#[cfg(test)]
pub(crate) mod test_support {
    use axum::body::Body;
    use axum::http::Response;
    use serde_json::Value;

    use crate::authz::test_support::VERIFIER;
    use crate::client_auth::ASSERTION_TYPE;
    use crate::http::PATH_TOKEN;
    use crate::http::authorize::test_support::approve;
    use crate::http::test_support::{CERT, Harness, json_body};

    pub async fn exchange(harness: &Harness, cert: Option<&str>, code: &str) -> Response<Body> {
        harness
            .post_form(
                cert,
                PATH_TOKEN,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("code_verifier", VERIFIER),
                    ("redirect_uri", "https://rp.example.com/cb"),
                    ("client_assertion_type", ASSERTION_TYPE),
                    ("client_assertion", &harness.assertion()),
                ],
            )
            .await
    }

    /// Run the whole flow and return the token response.
    pub async fn tokens(harness: &Harness, request_overrides: &Value) -> Value {
        let uri = harness.push(request_overrides).await;
        let code = approve(harness, &uri).await;
        let response = exchange(harness, Some(CERT), &code).await;
        assert_eq!(response.status(), 200);
        json_body(response).await
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::test_support::{exchange, tokens};
    use crate::authz::test_support::VERIFIER;
    use crate::client_auth::ASSERTION_TYPE;
    use crate::http::PATH_TOKEN;
    use crate::http::authorize::test_support::approve;
    use crate::http::test_support::{CERT, Harness, json_body};
    use crate::jose::{Jws, SigningAlg};
    use crate::state::test_support::ISSUER;

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
        use crate::http::authorize::test_support::approve_declining;
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
}
