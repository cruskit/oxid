//! OAuth 2.0 error responses for the back-channel endpoints.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Error codes from RFC 6749, RFC 9101, RFC 9126 and OpenID Connect Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorCode {
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
    pub(crate) fn as_str(self) -> &'static str {
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
            // Listed, not matched by a wildcard, so that a new code has to
            // be given its status deliberately.
            Self::InvalidRequest
            | Self::InvalidGrant
            | Self::UnauthorizedClient
            | Self::UnsupportedGrantType
            | Self::UnsupportedResponseType
            | Self::InvalidScope
            | Self::InvalidRequestObject
            | Self::AccessDenied
            | Self::LoginRequired
            | Self::ConsentRequired
            | Self::InteractionRequired
            | Self::AccountSelectionRequired => StatusCode::BAD_REQUEST,
        }
    }
}

/// Any error, boxed, as a cause kept for the log.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An error and every source under it, as one line: `outer: inner: root`.
pub(crate) struct Report<'a>(pub &'a (dyn std::error::Error + 'static));

impl std::fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(error) = source {
            write!(f, ": {error}")?;
            source = error.source();
        }
        Ok(())
    }
}

/// An error returned to the client as `{"error": ..., "error_description": ...}`.
///
/// Building one has no side effects. A `server_error` carries its cause,
/// which is logged once, when the error becomes the HTTP response, and
/// never sent.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{}: {description}", code.as_str())]
pub(crate) struct OAuthError {
    pub code: ErrorCode,
    pub description: String,
    #[source]
    cause: Option<std::sync::Arc<dyn std::error::Error + Send + Sync>>,
}

/// Equal when the client would see the same error; the cause is not
/// compared.
impl PartialEq for OAuthError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.description == other.description
    }
}

impl Eq for OAuthError {}

impl OAuthError {
    pub(crate) fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
            cause: None,
        }
    }

    pub(crate) fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, description)
    }

    pub(crate) fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidClient, description)
    }

    pub(crate) fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidGrant, description)
    }

    pub(crate) fn invalid_request_object(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequestObject, description)
    }

    pub(crate) fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidScope, description)
    }

    /// An internal failure. The cause is logged when the response is
    /// built, and never sent to the client.
    pub(crate) fn server_error(cause: impl Into<BoxError>) -> Self {
        Self {
            cause: Some(std::sync::Arc::from(cause.into())),
            ..Self::new(ErrorCode::ServerError, "internal server error")
        }
    }
}

impl IntoResponse for OAuthError {
    /// The one place a protocol endpoint's internal failure is logged.
    fn into_response(self) -> Response {
        if let Some(cause) = &self.cause {
            tracing::error!(error = %Report(cause.as_ref()), "internal error");
        }
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
