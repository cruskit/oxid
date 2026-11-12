//! Pluggable user experiences for the authorization endpoint.
//!
//! The protocol work of the authorization endpoint (finding the pushed
//! request, CSRF protection, single use of the `request_uri`, issuing the
//! code, building the redirect) is the same whatever the user sees. What
//! varies is the interaction in between: how the user is identified, what
//! they are shown and what they decide. That part is an [`Experience`].
//!
//! An experience is a state machine over HTML forms. The endpoint calls
//! [`Experience::start`] when the browser arrives and [`Experience::submit`]
//! for every form post, until a submission produces a final
//! [`Decision::Approve`] or [`Decision::Deny`]. Which experience runs is
//! chosen in the server configuration ([`Kind`]).
//!
//! To add an experience: implement the trait in a new submodule, add a
//! variant to [`Kind`], and construct it in [`build`].

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::HeaderMap;
use serde::Deserialize;

use crate::authz::AuthorizationRequest;
use crate::client::Client;
use crate::error::ErrorCode;
use crate::id_token::ClaimEdits;
use crate::state::AppState;
use crate::store::PushedRequest;
use crate::user::UserStore;
use crate::util::html_escape;

pub mod login;
pub mod technical;

/// The experiences that can be selected in configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Technical debugging: inspect the request, pick a customer, edit the
    /// response or return an error. No authentication. Development only.
    #[default]
    Technical,
    /// Sign in with a username and password, then consent.
    Login,
}

impl Kind {
    pub const ALL: &[Self] = &[Self::Technical, Self::Login];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Technical => "technical",
            Self::Login => "login",
        }
    }
}

impl std::str::FromStr for Kind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| {
                let known: Vec<&str> = Self::ALL.iter().map(|kind| kind.as_str()).collect();
                format!(
                    "unknown experience '{value}' (expected one of: {})",
                    known.join(", ")
                )
            })
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Construct the experience selected in configuration.
pub fn build(kind: Kind, users: Arc<dyn UserStore>) -> Arc<dyn Experience> {
    match kind {
        Kind::Technical => Arc::new(technical::Technical::new(users)),
        Kind::Login => Arc::new(login::Login::new(users)),
    }
}

/// Everything an experience may need to know about the request in hand.
#[derive(Debug)]
pub struct Interaction<'a> {
    pub state: &'a AppState,
    pub client: &'a Client,
    pub request_uri: &'a str,
    /// The pushed request, including the request object as it was received.
    pub pushed: &'a PushedRequest,
    /// CSRF token to embed in forms; [`Interaction::form_open`] does this.
    pub csrf: &'a str,
    /// The browser's request headers, for reading cookies.
    pub headers: &'a HeaderMap,
}

impl Interaction<'_> {
    pub fn request(&self) -> &AuthorizationRequest {
        &self.pushed.request
    }

    /// The value of a cookie the browser sent.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        cookie(self.headers, name)
    }

    /// An opening `<form>` tag that posts back to this experience, with the
    /// hidden fields the endpoint needs to route and verify the submission.
    pub fn form_open(&self) -> String {
        format!(
            "<form method=\"post\" action=\"{action}\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"client_id\" value=\"{client_id}\">\
             <input type=\"hidden\" name=\"request_uri\" value=\"{request_uri}\">",
            action = crate::http::PATH_DECISION,
            csrf = html_escape(self.csrf),
            client_id = html_escape(&self.client.id),
            request_uri = html_escape(self.request_uri),
        )
    }
}

/// The value of the cookie `name` in a request's headers.
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// A `Set-Cookie` value for a cookie scoped to this origin. The `__Host-`
/// prefix requires `Secure` and `Path=/`, which are always set here.
pub fn host_cookie(name: &str, value: &str, max_age_seconds: Option<i64>) -> String {
    let base = format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax");
    match max_age_seconds {
        Some(max_age) => format!("{base}; Max-Age={max_age}"),
        None => base,
    }
}

/// A page shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub title: String,
    /// The page body, as HTML. The experience is responsible for escaping
    /// anything it interpolates.
    pub body: String,
    /// Extra CSS for this page, appended to the shared styles.
    pub style: &'static str,
    /// JavaScript for this page, if it has any. It is served inline under a
    /// per-response nonce; nothing else on the page can run script.
    pub script: Option<&'static str>,
}

/// The user's approval of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Internal subject of the user the response is about.
    pub user_subject: String,
    /// Claims the user agreed to share. Nothing else is released.
    pub shared_claims: BTreeSet<String>,
    /// Voluntary claims the user declined, for the consent record.
    pub declined: Vec<String>,
    /// Changes to apply to the ID token claims when it is issued. Only the
    /// technical experience uses this.
    pub id_token_edits: Option<ClaimEdits>,
    /// The transaction identifier to use, if the experience has already
    /// shown one to the user. Otherwise one is generated.
    pub txn: Option<String>,
}

/// What a form submission leads to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Show another page; the interaction continues.
    Page(Page),
    /// Issue an authorization code.
    Approve(Approval),
    /// Return an OAuth error to the client.
    Deny {
        code: ErrorCode,
        description: String,
    },
}

/// The result of one step: a decision, plus any cookies to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub decision: Decision,
    /// `Set-Cookie` header values, e.g. from [`host_cookie`].
    pub set_cookies: Vec<String>,
}

impl From<Decision> for Step {
    fn from(decision: Decision) -> Self {
        Self {
            decision,
            set_cookies: Vec::new(),
        }
    }
}

impl From<Page> for Step {
    fn from(page: Page) -> Self {
        Decision::Page(page).into()
    }
}

/// A boxed future, so that [`Experience`] can be used as a trait object.
pub type StepFuture<'a> = Pin<Box<dyn Future<Output = Step> + Send + 'a>>;

/// Form fields submitted by the browser.
pub type Form = crate::http::Params;

/// One way of interacting with the user at the authorization endpoint.
pub trait Experience: Send + Sync + Debug {
    /// The name used to select this experience in configuration.
    fn kind(&self) -> Kind;

    /// The first page, shown when the browser arrives with a valid request.
    fn start<'a>(&'a self, interaction: &'a Interaction<'a>) -> StepFuture<'a>;

    /// Handle a form submission. The endpoint has already verified the CSRF
    /// token and that the request is still pending.
    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, form: &'a Form) -> StepFuture<'a>;
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use axum::http::header;

    use super::*;

    #[test]
    fn kinds_parse_from_their_configuration_names() {
        for kind in Kind::ALL {
            assert_eq!(kind.as_str().parse::<Kind>().unwrap(), *kind);
            assert_eq!(kind.to_string(), kind.as_str());
            let from_toml: Kind = serde_json::from_value(serde_json::json!(kind.as_str())).unwrap();
            assert_eq!(from_toml, *kind);
        }
        let err = "wizard".parse::<Kind>().unwrap_err();
        assert!(err.contains("technical") && err.contains("login"), "{err}");
    }

    #[test]
    fn technical_is_the_default_experience() {
        assert_eq!(Kind::default(), Kind::Technical);
    }

    #[test]
    fn cookie_parsing_finds_the_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-oxid-csrf=tok; b=2"),
        );
        assert_eq!(cookie(&headers, "__Host-oxid-csrf"), Some("tok"));
        assert_eq!(cookie(&headers, "a"), Some("1"));
        assert_eq!(cookie(&headers, "missing"), None);
    }

    #[test]
    fn host_cookies_are_secure_and_origin_bound() {
        let session = host_cookie("__Host-x", "v", None);
        assert_eq!(
            session,
            "__Host-x=v; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
        assert!(host_cookie("__Host-x", "v", Some(60)).ends_with("; Max-Age=60"));
    }
}
