//! `UserInfo` endpoint (OpenID Connect Core §5.3).
//!
//! Also the resource endpoint ConnectID §4.2-3.3 requires for conformance
//! testing: it only honours access tokens presented over the mutual TLS
//! connection they are bound to (RFC 8705 §3).

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::Value;

use super::{ConnInfo, no_store};
use crate::authz::SCOPE_OPENID;
use crate::id_token;
use crate::state::AppState;
use crate::util::ct_eq;

/// A bearer-token error response (RFC 6750 §3).
fn bearer_error(status: StatusCode, error: Option<(&str, &str)>) -> Response {
    let challenge = match error {
        Some((code, description)) => {
            format!("Bearer error=\"{code}\", error_description=\"{description}\"")
        }
        None => "Bearer".to_owned(),
    };
    let mut response = no_store(status.into_response());
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn invalid_token(description: &str) -> Response {
    bearer_error(
        StatusCode::UNAUTHORIZED,
        Some(("invalid_token", description)),
    )
}

/// The token from an `Authorization: Bearer` header. The scheme name is
/// case-insensitive (RFC 9110 §11.1).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

pub async fn userinfo(
    State(state): State<AppState>,
    Extension(conn): Extension<ConnInfo>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return bearer_error(StatusCode::UNAUTHORIZED, None);
    };
    let access = match state.store.access_token(token, state.now()).await {
        Ok(Some(access)) => access,
        Ok(None) => return invalid_token("the access token is invalid or has expired"),
        Err(error) => return crate::error::OAuthError::from(error).into_response(),
    };

    // Proof of possession: the caller must hold the certificate the token
    // was issued to.
    let bound = conn
        .client_cert
        .is_some_and(|cert| ct_eq(cert.thumbprint, &access.cert_thumbprint));
    if !bound {
        return invalid_token("the access token is bound to a different client certificate");
    }

    let grant = &access.grant;
    if !grant.scope.iter().any(|s| s == SCOPE_OPENID) {
        return bearer_error(
            StatusCode::FORBIDDEN,
            Some(("insufficient_scope", "the openid scope is required")),
        );
    }
    let (Some(client), Some(user)) = (
        state.clients.get(&grant.client_id),
        state.users.find_by_subject(&grant.user_subject),
    ) else {
        return invalid_token("the access token is no longer valid");
    };

    let claims = id_token::userinfo(&state, &client, &user, grant);
    no_store(Json(Value::Object(claims)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::json;

    use super::*;
    use crate::http::PATH_USERINFO;
    use crate::http::test_support::{CERT, Harness, json_body};
    use crate::http::token::test_support::tokens;
    use crate::jose::{Jws, SigningAlg};

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
        let id_token =
            Jws::parse(body["id_token"].as_str().unwrap(), &[SigningAlg::PS256]).unwrap();

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
}
