//! The router driven in-process, and the browser and token legs of the
//! authorization code flow.

use std::collections::HashMap;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use axum::{Extension, Router};
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;

use super::state::{ISSUER, state_with};
use super::{VERIFIER, shared_key, valid_claims};
use crate::client_auth::ASSERTION_TYPE;
use crate::experience::login::LOGIN_COOKIE;
use crate::http::page::CSRF_COOKIE;
use crate::http::{ConnInfo, PATH_AUTHORIZE, PATH_DECISION, PATH_PAR, PATH_TOKEN, router};
use crate::state::AppState;
use crate::tls::ClientCert;
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
        Self::from_state(crate::testing::state::state_from(
            kind,
            crate::config::CiConfig::default(),
            theme,
        ))
    }

    /// A provider using the `ci` experience, which holds its default
    /// response back for `response_delay` seconds.
    pub fn ci(response_delay: i64) -> Self {
        Self::from_state(crate::testing::state::state_with_ci(
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
        let mut claims = valid_claims(self.state.now());
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
                    ("client_assertion_type", ASSERTION_TYPE),
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

pub fn authorize_path(request_uri: &str) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "rp")
        .append_pair("request_uri", request_uri)
        .finish();
    format!("{PATH_AUTHORIZE}?{query}")
}

/// The value of the cookie `name` among a response's `Set-Cookie`s.
pub fn set_cookie(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.strip_prefix(&format!("{name}=")))
        .and_then(|rest| rest.split(';').next())
        .map(str::to_owned)
}

/// Load the login page and return the CSRF token it issued.
pub async fn open_login(harness: &Harness, request_uri: &str) -> String {
    let response = harness.get(None, &authorize_path(request_uri)).await;
    let csrf = set_cookie(&response, CSRF_COOKIE);
    assert_eq!(response.status(), 200, "{}", body_text(response).await);
    csrf.unwrap()
}

/// Post a form with the given `Cookie` header.
pub async fn submit_with(
    harness: &Harness,
    cookies: Option<&str>,
    fields: &[(&str, &str)],
) -> Response<Body> {
    let body: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    let mut request = Request::post(PATH_DECISION)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookies) = cookies {
        request = request.header(header::COOKIE, cookies);
    }
    harness
        .send(None, request.body(Body::from(body)).unwrap())
        .await
}

/// Post a form from a browser holding only the CSRF cookie.
pub async fn submit(
    harness: &Harness,
    csrf_cookie: Option<&str>,
    fields: &[(&str, &str)],
) -> Response<Body> {
    let cookies = csrf_cookie.map(|csrf| format!("other=1; {CSRF_COOKIE}={csrf}"));
    submit_with(harness, cookies.as_deref(), fields).await
}

/// Query parameters of a redirect response's `Location`.
pub fn redirect_params(response: &Response<Body>) -> (String, HashMap<String, String>) {
    assert_eq!(response.status(), 303);
    let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let params = location.query_pairs().into_owned().collect();
    let mut base = location;
    base.set_query(None);
    (base.to_string(), params)
}

fn checkboxes(html: &str, only_ticked: bool) -> Vec<String> {
    super::html::Page::parse(html).checkboxes(only_ticked)
}

/// Names of the checkboxes on a consent page: the voluntary claims.
pub fn offered(html: &str) -> Vec<String> {
    checkboxes(html, false)
}

/// Names of the checkboxes that are ticked when the page loads.
pub fn ticked(html: &str) -> Vec<String> {
    checkboxes(html, true)
}

/// A browser that has signed in and is looking at the consent page.
pub struct SignedIn {
    pub csrf: String,
    /// The `Cookie` header the browser sends.
    pub cookies: String,
    /// The consent page.
    pub html: String,
}

/// Load the login page and sign in as the demo user.
pub async fn sign_in(harness: &Harness, request_uri: &str) -> SignedIn {
    let csrf = open_login(harness, request_uri).await;
    let fields = [
        ("csrf", csrf.as_str()),
        ("client_id", "rp"),
        ("request_uri", request_uri),
        ("username", crate::user::DEMO_USERNAME),
        ("password", crate::user::DEMO_PASSWORD),
        ("action", "sign-in"),
    ];
    let response = submit(harness, Some(&csrf), &fields).await;
    assert_eq!(response.status(), 200);
    let login = set_cookie(&response, LOGIN_COOKIE).expect("signing in sets a cookie");
    SignedIn {
        cookies: format!("{CSRF_COOKIE}={csrf}; {LOGIN_COOKIE}={login}"),
        csrf,
        html: body_text(response).await,
    }
}

/// Submit the consent page with the `share` checkboxes turned on.
pub async fn consent(
    harness: &Harness,
    request_uri: &str,
    browser: &SignedIn,
    share: &[String],
    action: &str,
) -> Response<Body> {
    let mut fields = vec![
        ("csrf", browser.csrf.as_str()),
        ("client_id", "rp"),
        ("request_uri", request_uri),
        ("action", action),
    ];
    fields.extend(share.iter().map(|field| (field.as_str(), "1")));
    submit_with(harness, Some(&browser.cookies), &fields).await
}

/// Run the browser leg for a pushed request, sharing everything offered,
/// and return the code.
pub async fn approve(harness: &Harness, request_uri: &str) -> String {
    approve_declining(harness, request_uri, &[]).await
}

/// As [`approve`], but leaving the `declined` claims turned off.
pub async fn approve_declining(harness: &Harness, request_uri: &str, declined: &[&str]) -> String {
    let browser = sign_in(harness, request_uri).await;
    let share: Vec<String> = offered(&browser.html)
        .into_iter()
        .filter(|field| !declined.iter().any(|d| *field == format!("share_{d}")))
        .collect();
    let response = consent(harness, request_uri, &browser, &share, "approve").await;
    redirect_params(&response)
        .1
        .remove("code")
        .expect("code in redirect")
}

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
