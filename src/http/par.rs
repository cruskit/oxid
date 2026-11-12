//! Pushed authorization request endpoint (RFC 9126).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::{OAuthForm, authenticate_client, no_store};
use crate::authz::AuthorizationRequest;
use crate::error::OAuthError;
use crate::request_object;
use crate::state::AppState;

pub async fn pushed_authorization_request(
    State(state): State<AppState>,
    OAuthForm(params): OAuthForm,
) -> Result<Response, OAuthError> {
    // FAPI 2.0 §5.3.2.2-4: unauthenticated pushed requests are rejected.
    let client = authenticate_client(&state, &params).await?;

    // RFC 9126 §2.1: request_uri must not be provided here.
    if params.get("request_uri").is_some() {
        return Err(OAuthError::invalid_request(
            "request_uri must not be sent to this endpoint",
        ));
    }

    // ConnectID §4.2-3.8: a signed request object is mandatory. Parameters
    // sent beside it are ignored entirely (§4.2-3.9).
    let request_object = params
        .get("request")
        .ok_or_else(|| OAuthError::invalid_request("a signed request object is required"))?;

    let now = state.now();
    let claims =
        request_object::verify(request_object, &client, &state.issuer, &state.security, now)?;
    let request = AuthorizationRequest::from_params(&client, &claims)?;

    let expires_in = state.security.request_uri_ttl;
    let request_uri = state
        .store
        .push_request(request, request_object.to_owned(), now + expires_in)
        .await?;
    tracing::info!(client_id = %client.id, "pushed authorization request accepted");

    let body = Json(json!({ "request_uri": request_uri, "expires_in": expires_in }));
    Ok(no_store((StatusCode::CREATED, body).into_response()))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use crate::client_auth::ASSERTION_TYPE;
    use crate::http::PATH_PAR;
    use crate::http::test_support::{CERT, Harness, json_body};
    use crate::store::REQUEST_URI_PREFIX;

    async fn push(harness: &Harness, fields: &[(&str, &str)]) -> (StatusCode, Value) {
        let response = harness.post_form(Some(CERT), PATH_PAR, fields).await;
        let status = response.status();
        (status, json_body(response).await)
    }

    async fn push_request(harness: &Harness, overrides: &Value) -> (StatusCode, Value) {
        push(
            harness,
            &[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &harness.assertion()),
                ("request", &harness.request_object(overrides)),
            ],
        )
        .await
    }

    #[tokio::test]
    async fn accepts_a_valid_pushed_request() {
        let harness = Harness::new();
        let (status, body) = push_request(&harness, &json!({})).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            body["request_uri"]
                .as_str()
                .unwrap()
                .starts_with(REQUEST_URI_PREFIX)
        );
        let expires_in = body["expires_in"].as_i64().unwrap();
        assert!(expires_in > 0 && expires_in < 600, "FAPI 2.0 5.3.2.2-12");
    }

    #[tokio::test]
    async fn response_is_not_cacheable() {
        let harness = Harness::new();
        let response = harness
            .post_form(
                Some(CERT),
                PATH_PAR,
                &[
                    ("client_assertion_type", ASSERTION_TYPE),
                    ("client_assertion", &harness.assertion()),
                    ("request", &harness.request_object(&json!({}))),
                ],
            )
            .await;
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    #[tokio::test]
    async fn rejects_unauthenticated_requests() {
        let harness = Harness::new();
        let (status, body) = push(
            &harness,
            &[("request", &harness.request_object(&json!({})))],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn rejects_replayed_client_assertions() {
        let harness = Harness::new();
        let assertion = harness.assertion();
        let fields = [
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
            ("request", &harness.request_object(&json!({}))),
        ];
        assert_eq!(push(&harness, &fields).await.0, StatusCode::CREATED);
        let (status, body) = push(&harness, &fields).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn rejects_unsigned_parameters_without_a_request_object() {
        let harness = Harness::new();
        let (status, body) = push(
            &harness,
            &[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &harness.assertion()),
                ("client_id", "rp"),
                ("response_type", "code"),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("scope", "openid"),
                ("code_challenge", crate::authz::test_support::CHALLENGE),
                ("code_challenge_method", "S256"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn rejects_request_uri_as_a_form_parameter() {
        let harness = Harness::new();
        let (status, body) = push(
            &harness,
            &[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &harness.assertion()),
                ("request", &harness.request_object(&json!({}))),
                ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn parameters_outside_the_request_object_are_ignored() {
        let harness = Harness::new();
        let response = harness
            .post_form(
                Some(CERT),
                PATH_PAR,
                &[
                    ("client_assertion_type", ASSERTION_TYPE),
                    ("client_assertion", &harness.assertion()),
                    ("request", &harness.request_object(&json!({"state": null}))),
                    ("state", "outside"),
                    ("nonce", "outside"),
                    ("redirect_uri", "https://evil.example.com/cb"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let uri = json_body(response).await["request_uri"]
            .as_str()
            .unwrap()
            .to_owned();
        let pushed = harness
            .state
            .store
            .peek_request(&uri, harness.state.now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pushed.request.state, None,
            "state outside the object is not used"
        );
        assert_eq!(pushed.request.nonce.as_deref(), Some("n-1"));
        assert_eq!(pushed.request.redirect_uri, "https://rp.example.com/cb");
    }

    #[tokio::test]
    async fn invalid_request_objects_and_parameters_map_to_the_right_errors() {
        let harness = Harness::new();
        let now = harness.state.now();
        let cases = [
            (json!({"exp": now + 3600}), "invalid_request_object"),
            (json!({"nbf": now - 900}), "invalid_request_object"),
            (
                json!({"aud": "https://other.example.com"}),
                "invalid_request_object",
            ),
            (json!({"exp": null}), "invalid_request_object"),
            (
                json!({"response_type": "code id_token"}),
                "unsupported_response_type",
            ),
            (
                json!({"redirect_uri": "https://evil.example.com/cb"}),
                "invalid_request",
            ),
            (json!({"redirect_uri": null}), "invalid_request"),
            (json!({"code_challenge": null}), "invalid_request"),
            (json!({"code_challenge_method": "plain"}), "invalid_request"),
            (json!({"scope": "openid payments"}), "invalid_scope"),
            (json!({"purpose": "x".repeat(301)}), "invalid_request"),
            (
                json!({"request_uri": "urn:ietf:params:oauth:request_uri:x"}),
                "invalid_request_object",
            ),
        ];
        for (overrides, expected) in cases {
            let (status, body) = push_request(&harness, &overrides).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{overrides}");
            assert_eq!(body["error"], expected, "{overrides}");
        }
    }

    #[tokio::test]
    async fn only_post_is_allowed() {
        let harness = Harness::new();
        let response = harness.get(Some(CERT), PATH_PAR).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
