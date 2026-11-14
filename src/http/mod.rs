//! HTTP routing, shared extractors and response headers.

use std::collections::HashMap;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, Request};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use tracing::Instrument;
use uuid::Uuid;

use crate::error::OAuthError;
use crate::state::AppState;
use crate::tls::ClientCert;

mod authorize;
mod ci;
mod discovery;
pub(crate) mod page;
mod par;
mod theme;
mod token;
mod userinfo;

pub const PATH_DISCOVERY: &str = "/.well-known/openid-configuration";
pub const PATH_OAUTH_METADATA: &str = "/.well-known/oauth-authorization-server";
pub const PATH_JWKS: &str = "/jwks";
pub const PATH_PAR: &str = "/par";
pub const PATH_AUTHORIZE: &str = "/authorize";
pub const PATH_DECISION: &str = "/authorize/decision";
pub const PATH_TOKEN: &str = "/token";
pub const PATH_USERINFO: &str = "/userinfo";
pub const PATH_HEALTH: &str = "/healthz";
/// The theme's logo, when it has one.
pub const PATH_THEME_LOGO: &str = "/theme/logo";
/// The theme's logo for dark mode, when it has one of its own.
pub const PATH_THEME_LOGO_DARK: &str = "/theme/logo-dark";
/// What the `ci` experience offers. Served only under that experience.
pub const PATH_CI: &str = "/ci";
/// Where a client chooses the `ci` experience's response to a request.
pub const PATH_CI_RESPONSE: &str = "/ci/response";

pub static X_FAPI_INTERACTION_ID: HeaderName = HeaderName::from_static("x-fapi-interaction-id");

/// Largest request body accepted. Request objects with claims requests are a
/// few kilobytes; this leaves generous headroom while bounding memory.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Per-connection facts, attached to every request by the server.
#[derive(Debug, Clone, Default)]
pub struct ConnInfo {
    /// The TLS client certificate, if the client presented one. Always
    /// `None` on the public listener, which never asks for one.
    pub client_cert: Option<ClientCert>,
}

pub fn router(state: AppState) -> Router {
    // The endpoints of the `ci` experience do not exist under any other.
    let ci = if state.experience.kind() == crate::experience::Kind::Ci {
        Router::new()
            .route(PATH_CI, get(ci::options))
            .route(PATH_CI_RESPONSE, post(ci::plan_response))
    } else {
        Router::new()
    };
    Router::new()
        .merge(ci)
        .route(PATH_DISCOVERY, get(discovery::metadata))
        .route(PATH_OAUTH_METADATA, get(discovery::metadata))
        .route(PATH_JWKS, get(discovery::jwks))
        .route(PATH_PAR, post(par::pushed_authorization_request))
        .route(PATH_AUTHORIZE, get(authorize::authorize))
        .route(PATH_DECISION, post(authorize::decision))
        .route(PATH_TOKEN, post(token::token))
        .route(
            PATH_USERINFO,
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route(PATH_HEALTH, get(|| async { "ok" }))
        .route(PATH_THEME_LOGO, get(theme::logo))
        .route(PATH_THEME_LOGO_DARK, get(theme::logo_dark))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(common_headers))
        .with_state(state)
}

/// Whether a client-supplied interaction id is safe to echo and log.
fn is_valid_interaction_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Applies to every response:
///
/// * `x-fapi-interaction-id`: echoed if the client sent one, otherwise a new
///   UUID (ConnectID §4.2-3.12), and recorded in the request's log span
///   (§4.2-3.13).
/// * transport and content security headers (FAPI 2.0 §5.2.3).
async fn common_headers(request: Request, next: Next) -> Response {
    let interaction_id = request
        .headers()
        .get(&X_FAPI_INTERACTION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| is_valid_interaction_id(v))
        .map_or_else(|| Uuid::new_v4().to_string(), str::to_owned);

    let span = tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        interaction_id = %interaction_id,
    );
    let mut response = async {
        let response = next.run(request).await;
        tracing::info!(status = response.status().as_u16(), "handled");
        response
    }
    .instrument(span)
    .await;

    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&interaction_id) {
        headers.insert(X_FAPI_INTERACTION_ID.clone(), value);
    }
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Request parameters, with duplicates rejected.
///
/// RFC 6749 §3.1/§3.2: parameters must not be included more than once.
#[derive(Debug, Clone, Default)]
pub struct Params(HashMap<String, String>);

impl Params {
    pub fn parse(encoded: &[u8]) -> Result<Self, OAuthError> {
        let mut map = HashMap::new();
        for (name, value) in url::form_urlencoded::parse(encoded) {
            if map.insert(name.to_string(), value.into_owned()).is_some() {
                return Err(OAuthError::invalid_request(format!(
                    "parameter '{name}' is included more than once"
                )));
            }
        }
        Ok(Self(map))
    }

    /// Whether the parameter was sent at all, even with an empty value.
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// The parameter's value. An empty value is treated as absent
    /// (RFC 6749 §3.1).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// Extracts a form-encoded body, reporting problems as OAuth errors rather
/// than axum's plain-text rejections.
#[derive(Debug)]
pub struct OAuthForm(pub Params);

impl<S: Send + Sync> FromRequest<S> for OAuthForm {
    type Rejection = OAuthError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_form = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|mime| {
                mime.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
        if !is_form {
            return Err(OAuthError::invalid_request(
                "Content-Type must be application/x-www-form-urlencoded",
            ));
        }
        let body = Bytes::from_request(request, state)
            .await
            .map_err(|_| OAuthError::invalid_request("request body could not be read"))?;
        Params::parse(&body).map(Self)
    }
}

/// Mark a response as uncacheable (RFC 6749 §5.1).
pub fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Authenticate the client making a back-channel request, including replay
/// protection for its assertion.
pub async fn authenticate_client(
    state: &AppState,
    params: &Params,
) -> Result<std::sync::Arc<crate::client::Client>, OAuthError> {
    use crate::client_auth::{self, Credentials};

    let now = state.now();
    let authenticated = client_auth::authenticate(
        Credentials {
            client_id: params.get("client_id"),
            client_assertion_type: params.get("client_assertion_type"),
            client_assertion: params.get("client_assertion"),
        },
        state.clients.as_ref(),
        &state.issuer,
        state.security.clock_skew,
        now,
    )?;
    if !state
        .store
        .record_jti(
            &authenticated.client.id,
            &authenticated.jti,
            authenticated.expires_at,
            now,
        )
        .await?
    {
        return Err(OAuthError::invalid_client(
            "client assertion has already been used",
        ));
    }
    Ok(authenticated.client)
}

#[cfg(test)]
mod tests;
