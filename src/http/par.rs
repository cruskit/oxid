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

pub(super) async fn pushed_authorization_request(
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
mod tests;
