//! Pluggable user experiences for the authorization endpoint.
//!
//! The protocol work of the authorization endpoint (finding the pushed
//! request, CSRF protection, single use of the `request_uri`, issuing the
//! code, building the redirect) is the same whatever the user sees. What
//! varies is the interaction in between: how the user is identified, what
//! they are shown and what they decide. That part is an [`Experience`].
//!
//! The endpoint also owns the user's session: the time they have, once their
//! browser has arrived, to get through the experience. When it runs out the
//! endpoint shows the expiry page itself, whatever the experience.
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
use crate::store::{PushedRequest, Session};
use crate::user::UserStore;
use crate::util::html_escape;

pub mod ci;
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
    /// No user at all: the request is answered automatically, with a
    /// response the client may choose. No authentication. Automated testing
    /// only.
    Ci,
}

impl Kind {
    pub const ALL: &[Self] = &[Self::Technical, Self::Login, Self::Ci];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Technical => "technical",
            Self::Login => "login",
            Self::Ci => "ci",
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
        Kind::Ci => Arc::new(ci::Ci::new(users)),
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
    /// The user's session for this request: how long they have left, and
    /// whether they have signed in.
    pub session: &'a Session,
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
        form_open(self.csrf, &self.client.id, self.request_uri)
    }
}

/// An opening `<form>` tag that posts to the decision endpoint with the
/// hidden fields it needs to route and verify the submission.
pub fn form_open(csrf: &str, client_id: &str, request_uri: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"client_id\" value=\"{client_id}\">\
         <input type=\"hidden\" name=\"request_uri\" value=\"{request_uri}\">",
        action = crate::http::PATH_DECISION,
        csrf = html_escape(csrf),
        client_id = html_escape(client_id),
        request_uri = html_escape(request_uri),
    )
}

/// A length of time in words, for telling the user how long they have.
pub fn duration_text(seconds: i64) -> String {
    let (count, unit) = if seconds % 60 == 0 {
        (seconds / 60, "minute")
    } else {
        (seconds, "second")
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural}")
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
    /// Use the full width of the window instead of the narrow card that
    /// suits pages for end users.
    pub wide: bool,
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

/// An error an experience can return to the client instead of a success,
/// when it is asked to simulate one.
#[derive(Debug, Clone, Copy)]
pub struct ErrorCondition {
    pub code: ErrorCode,
    /// What this condition simulates.
    pub label: &'static str,
    /// The default `error_description`.
    pub description: &'static str,
}

/// The predefined error conditions, in the order they are offered.
pub const ERROR_CONDITIONS: &[ErrorCondition] = &[
    ErrorCondition {
        code: ErrorCode::AccessDenied,
        label: "The user did not consent",
        description: "the user denied the request",
    },
    ErrorCondition {
        code: ErrorCode::LoginRequired,
        label: "The user could not be authenticated",
        description: "the user must authenticate",
    },
    ErrorCondition {
        code: ErrorCode::ConsentRequired,
        label: "Consent is needed and was not given",
        description: "the user's consent is required",
    },
    ErrorCondition {
        code: ErrorCode::InteractionRequired,
        label: "User interaction is needed",
        description: "user interaction is required",
    },
    ErrorCondition {
        code: ErrorCode::AccountSelectionRequired,
        label: "The user must choose an account",
        description: "the user must select an account",
    },
    ErrorCondition {
        code: ErrorCode::InvalidRequest,
        label: "The request is malformed",
        description: "the request is invalid",
    },
    ErrorCondition {
        code: ErrorCode::InvalidScope,
        label: "The requested scope is not allowed",
        description: "the requested scope is invalid",
    },
    ErrorCondition {
        code: ErrorCode::UnauthorizedClient,
        label: "The client may not make this request",
        description: "the client is not authorized to request a code",
    },
    ErrorCondition {
        code: ErrorCode::ServerError,
        label: "The provider failed unexpectedly",
        description: "the authorization server encountered an unexpected condition",
    },
    ErrorCondition {
        code: ErrorCode::TemporarilyUnavailable,
        label: "The provider is overloaded or under maintenance",
        description: "the authorization server is temporarily unavailable",
    },
];

/// The predefined error condition with this error code.
pub fn error_condition(code: &str) -> Option<&'static ErrorCondition> {
    ERROR_CONDITIONS
        .iter()
        .find(|condition| condition.code.as_str() == code)
}

/// Longest `error_description` accepted from whoever chooses the response.
pub const MAX_ERROR_DESCRIPTION: usize = 500;

/// RFC 6749 §4.1.2.1: `error_description` is printable ASCII without `"` or
/// `\`.
pub fn is_error_description(text: &str) -> bool {
    text.bytes()
        .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Every claim that can be released for the request: what a user who agreed
/// to everything would share.
pub fn everything_requested(interaction: &Interaction<'_>) -> BTreeSet<String> {
    let request = interaction.request();
    request
        .claims
        .consentable(interaction.client, &request.scope)
        .into_iter()
        .map(|item| item.name)
        .collect()
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
        assert!(
            err.contains("technical") && err.contains("login") && err.contains("ci"),
            "{err}"
        );
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
    fn durations_read_naturally() {
        assert_eq!(duration_text(300), "5 minutes");
        assert_eq!(duration_text(60), "1 minute");
        assert_eq!(duration_text(90), "90 seconds");
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
