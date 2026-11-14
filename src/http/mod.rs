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
pub(crate) mod test_support {
    use axum::body::Body;
    use axum::http::{Request, Response, StatusCode};
    use axum::{Extension, Router};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::keys::test_support::shared_key;
    use crate::state::test_support::{ISSUER, state_with};
    use crate::util::{ManualClock, random_token};

    pub const CERT: &str = "client-cert-thumbprint";

    /// A router plus the handles needed to drive it in-process.
    pub struct Harness {
        pub state: AppState,
        pub clock: std::sync::Arc<ManualClock>,
        router: Router,
    }

    impl Harness {
        /// A provider using the `login` experience.
        pub fn new() -> Self {
            Self::with_experience(crate::experience::Kind::Login)
        }

        pub fn with_experience(kind: crate::experience::Kind) -> Self {
            Self::from_state(state_with(kind))
        }

        /// A provider using the `login` experience, with the given theme.
        pub fn with_theme(theme: crate::theme::Theme) -> Self {
            Self::themed(crate::experience::Kind::Login, theme)
        }

        /// A provider with the given experience and theme.
        pub fn themed(kind: crate::experience::Kind, theme: crate::theme::Theme) -> Self {
            Self::from_state(crate::state::test_support::state_from(
                kind,
                crate::config::CiConfig::default(),
                theme,
            ))
        }

        /// A provider using the `ci` experience, which holds its default
        /// response back for `response_delay` seconds.
        pub fn ci(response_delay: i64) -> Self {
            Self::from_state(crate::state::test_support::state_with_ci(
                crate::experience::Kind::Ci,
                crate::config::CiConfig { response_delay },
            ))
        }

        fn from_state((state, clock): (AppState, std::sync::Arc<ManualClock>)) -> Self {
            Self {
                router: router(state.clone()),
                state,
                clock,
            }
        }

        /// Send a request as if over a connection presenting `cert`.
        pub async fn send(&self, cert: Option<&str>, request: Request<Body>) -> Response<Body> {
            let conn = ConnInfo {
                client_cert: cert.map(|t| ClientCert {
                    thumbprint: t.to_owned(),
                }),
            };
            self.router
                .clone()
                .layer(Extension(conn))
                .oneshot(request)
                .await
                .unwrap()
        }

        pub async fn post_form(
            &self,
            cert: Option<&str>,
            path: &str,
            fields: &[(&str, &str)],
        ) -> Response<Body> {
            let body: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish();
            let request = Request::post(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            self.send(cert, request).await
        }

        pub async fn get(&self, cert: Option<&str>, path: &str) -> Response<Body> {
            self.send(cert, Request::get(path).body(Body::empty()).unwrap())
                .await
        }

        /// A fresh, valid client assertion for client `rp`.
        pub fn assertion(&self) -> String {
            let now = self.state.now();
            shared_key()
                .sign(
                    Some("JWT"),
                    &json!({
                        "iss": "rp", "sub": "rp", "aud": ISSUER,
                        "jti": random_token(16), "iat": now, "exp": now + 60,
                    }),
                )
                .unwrap()
        }

        /// A signed request object for client `rp` with `overrides` applied.
        pub fn request_object(&self, overrides: &Value) -> String {
            let mut claims = crate::request_object::test_support::valid_claims(self.state.now());
            for (name, value) in overrides.as_object().into_iter().flatten() {
                if value.is_null() {
                    claims.as_object_mut().unwrap().remove(name);
                } else {
                    claims[name] = value.clone();
                }
            }
            shared_key()
                .sign(Some("oauth-authz-req+jwt"), &claims)
                .unwrap()
        }

        /// Push a request and return its `request_uri`.
        pub async fn push(&self, overrides: &Value) -> String {
            let response = self
                .post_form(
                    Some(CERT),
                    PATH_PAR,
                    &[
                        ("client_assertion_type", crate::client_auth::ASSERTION_TYPE),
                        ("client_assertion", &self.assertion()),
                        ("request", &self.request_object(overrides)),
                    ],
                )
                .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            json_body(response).await["request_uri"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    }

    pub async fn body_text(response: Response<Body>) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    pub async fn json_body(response: Response<Body>) -> Value {
        serde_json::from_str(&body_text(response).await).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    use super::test_support::Harness;
    use super::*;

    #[test]
    fn params_reject_duplicates_and_treat_empty_as_absent() {
        let params = Params::parse(b"a=1&b=&c=x%20y").unwrap();
        assert_eq!(params.get("a"), Some("1"));
        assert_eq!(params.get("b"), None);
        assert_eq!(params.get("c"), Some("x y"));
        assert_eq!(params.get("missing"), None);
        assert!(Params::parse(b"a=1&a=2").is_err());
    }

    #[test]
    fn interaction_id_validation() {
        assert!(is_valid_interaction_id(
            "c770aef3-6784-41f7-8e0e-ff5f97bddb3a"
        ));
        assert!(!is_valid_interaction_id(""));
        assert!(!is_valid_interaction_id("has space"));
        assert!(!is_valid_interaction_id("line\nbreak"));
        assert!(!is_valid_interaction_id(&"a".repeat(129)));
    }

    #[tokio::test]
    async fn interaction_id_is_echoed_or_generated() {
        let harness = Harness::new();
        let request = Request::get(PATH_HEALTH)
            .header(
                &X_FAPI_INTERACTION_ID,
                "c770aef3-6784-41f7-8e0e-ff5f97bddb3a",
            )
            .body(Body::empty())
            .unwrap();
        let response = harness.send(None, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[&X_FAPI_INTERACTION_ID],
            "c770aef3-6784-41f7-8e0e-ff5f97bddb3a"
        );

        let generated = harness.get(None, PATH_HEALTH).await;
        let id = generated.headers()[&X_FAPI_INTERACTION_ID]
            .to_str()
            .unwrap();
        assert!(Uuid::parse_str(id).is_ok(), "{id}");
    }

    #[tokio::test]
    async fn security_headers_are_set_on_every_response() {
        let response = Harness::new().get(None, "/does-not-exist").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let headers = response.headers();
        assert!(
            headers[header::STRICT_TRANSPORT_SECURITY]
                .to_str()
                .unwrap()
                .contains("max-age=")
        );
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert!(headers.contains_key(&X_FAPI_INTERACTION_ID));
    }

    #[tokio::test]
    async fn non_form_bodies_get_an_oauth_error() {
        let harness = Harness::new();
        let request = Request::post(PATH_TOKEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = harness.send(None, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            test_support::json_body(response).await["error"],
            "invalid_request"
        );
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let harness = Harness::new();
        let big = "a".repeat(MAX_BODY_BYTES + 1);
        let response = harness.post_form(None, PATH_TOKEN, &[("x", &big)]).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
