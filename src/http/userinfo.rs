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

pub(super) async fn userinfo(
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

    let claims = id_token::userinfo(&state.issuer_context(), &client, &user, grant);
    no_store(Json(Value::Object(claims)).into_response())
}

#[cfg(test)]
mod tests;
