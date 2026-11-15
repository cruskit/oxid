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
use crate::client::{Client, GrantType};
use crate::error::{ErrorCode, OAuthError};
use crate::id_token;
use crate::pkce;
use crate::state::AppState;
use crate::store::{AccessToken, CodeRedemption, Grant, RefreshToken};

pub(super) async fn token(
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

    let grant_type = params.get("grant_type").map(str::parse::<GrantType>);
    let body = match grant_type {
        Some(Ok(GrantType::AuthorizationCode)) => {
            code_grant(&state, &client, &params, &thumbprint).await?
        }
        Some(Ok(GrantType::RefreshToken)) => {
            refresh_grant(&state, &client, &params, &thumbprint).await?
        }
        Some(Err(_)) => {
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
        let id_token = id_token::issue(&state.issuer_context(), client, &user, grant, nonce, &access_token)
            .map_err(OAuthError::server_error)?;
        body.insert("id_token".to_owned(), id_token.into());
    }
    tracing::info!(client_id = %client.id, "tokens issued");
    Ok(body)
}

#[cfg(test)]
mod tests;
