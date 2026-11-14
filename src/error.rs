//! OAuth 2.0 error responses for the back-channel endpoints.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Error codes from RFC 6749, RFC 9101, RFC 9126 and OpenID Connect Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    InvalidRequestObject,
    AccessDenied,
    LoginRequired,
    ConsentRequired,
    InteractionRequired,
    AccountSelectionRequired,
    ServerError,
    TemporarilyUnavailable,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
            Self::AccountSelectionRequired => "account_selection_required",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// An error returned to the client as `{"error": ..., "error_description": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {description}", code.as_str())]
pub struct OAuthError {
    pub code: ErrorCode,
    pub description: String,
}

impl OAuthError {
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidClient, description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidGrant, description)
    }

    pub fn invalid_request_object(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequestObject, description)
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidScope, description)
    }

    /// An internal failure. The detail is logged, never sent to the client.
    pub fn server_error(detail: impl std::fmt::Display) -> Self {
        tracing::error!(%detail, "internal error");
        Self::new(ErrorCode::ServerError, "internal server error")
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.code.as_str(),
            "error_description": self.description,
        }));
        let mut response = (self.code.status(), body).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }
}

#[cfg(test)]
mod tests;
