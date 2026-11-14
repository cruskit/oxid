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
//! An experience is a state machine over HTML forms. Its pages are the
//! templates in `templates/<experience>/`, each rendered from a struct in
//! the experience's module that holds exactly what the page shows. The
//! templates escape what they are given, and take their colours, name and
//! logo from the [`Theme`](crate::theme::Theme).
//!
//! An experience drives the pages like this. The endpoint calls
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

use askama::Template;
use axum::http::HeaderMap;
use serde::Deserialize;

use crate::cookie::SetCookie;
use crate::authz::AuthorizationRequest;
use crate::client::Client;
use crate::error::ErrorCode;
use crate::id_token::ClaimEdits;
use crate::state::AppState;
use crate::store::{PushedRequest, Session};
use crate::theme::Theme;
use crate::user::UserStore;

pub(crate) mod ci;
pub(crate) mod login;
pub(crate) mod technical;

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

    /// Every name, for messages.
    fn names() -> String {
        Self::ALL
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Technical => "technical",
            Self::Login => "login",
            Self::Ci => "ci",
        }
    }
}

/// An experience name that is not one of [`Kind::ALL`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown experience '{name}' (expected one of: {known})", known = Kind::names())]
pub struct UnknownExperience {
    name: String,
}

impl std::str::FromStr for Kind {
    type Err = UnknownExperience;

    fn from_str(value: &str) -> Result<Self, UnknownExperience> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| UnknownExperience {
                name: value.to_owned(),
            })
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Construct the experience selected in configuration.
pub(crate) fn build(kind: Kind, users: Arc<dyn UserStore>) -> Arc<dyn Experience> {
    match kind {
        Kind::Technical => Arc::new(technical::Technical::new(users)),
        Kind::Login => Arc::new(login::Login::new(users)),
        Kind::Ci => Arc::new(ci::Ci::new(users)),
    }
}

/// Everything an experience may need to know about the request in hand.
#[derive(Debug)]
pub(crate) struct Interaction<'a> {
    pub state: &'a AppState,
    pub client: &'a Client,
    pub request_uri: &'a str,
    /// The pushed request, including the request object as it was received.
    pub pushed: &'a PushedRequest,
    /// The user's session for this request: how long they have left, and
    /// whether they have signed in.
    pub session: &'a Session,
    /// CSRF token to embed in forms; [`Interaction::form`] carries it.
    pub csrf: &'a str,
    /// The browser's request headers, for reading cookies.
    pub headers: &'a HeaderMap,
}

impl Interaction<'_> {
    pub(crate) fn request(&self) -> &AuthorizationRequest {
        &self.pushed.request
    }

    /// The value of a cookie the browser sent.
    pub(crate) fn cookie(&self, name: &str) -> Option<&str> {
        crate::cookie::get(self.headers, name)
    }

    /// Where a form on a page of this experience posts to. A template with
    /// this in its `form` field opens the form with
    /// `{% include "form_open.html" %}`.
    pub(crate) fn form(&self) -> FormTarget<'_> {
        FormTarget::new(self.csrf, &self.client.id, self.request_uri)
    }

    /// The name, logo and colours the pages are shown with.
    pub(crate) fn theme(&self) -> &Theme {
        &self.state.theme
    }
}

/// What `templates/form_open.html` needs to open a form that posts to the
/// decision endpoint: the hidden fields that route and verify the
/// submission.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FormTarget<'a> {
    pub action: &'static str,
    pub csrf: &'a str,
    pub client_id: &'a str,
    pub request_uri: &'a str,
}

impl<'a> FormTarget<'a> {
    pub(crate) fn new(csrf: &'a str, client_id: &'a str, request_uri: &'a str) -> Self {
        Self {
            action: crate::http::PATH_DECISION,
            csrf,
            client_id,
            request_uri,
        }
    }
}

/// Render a template to HTML. The templates are compiled into the binary and
/// checked at build time, so rendering fails only if a value cannot be
/// written.
pub(crate) fn render(template: &impl Template) -> askama::Result<String> {
    template.render()
}

/// A length of time in words, for telling the user how long they have.
pub(crate) fn duration_text(seconds: i64) -> String {
    let (count, unit) = if seconds % 60 == 0 {
        (seconds / 60, "minute")
    } else {
        (seconds, "second")
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural}")
}

/// A page shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page {
    pub title: String,
    /// The page body, as HTML: a template of the experience, rendered with
    /// [`render`]. Templates escape what they interpolate.
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
pub(crate) struct Approval {
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
pub(crate) enum Decision {
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
pub(crate) struct Step {
    pub decision: Decision,
    /// Cookies to set.
    pub set_cookies: Vec<SetCookie>,
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
pub(crate) struct ErrorCondition {
    pub code: ErrorCode,
    /// What this condition simulates.
    pub label: &'static str,
    /// The default `error_description`.
    pub description: &'static str,
}

/// The predefined error conditions, in the order they are offered.
pub(crate) const ERROR_CONDITIONS: &[ErrorCondition] = &[
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
pub(crate) fn error_condition(code: &str) -> Option<&'static ErrorCondition> {
    ERROR_CONDITIONS
        .iter()
        .find(|condition| condition.code.as_str() == code)
}

/// Longest `error_description` accepted from whoever chooses the response.
pub(crate) const MAX_ERROR_DESCRIPTION: usize = 500;

/// RFC 6749 §4.1.2.1: `error_description` is printable ASCII without `"` or
/// `\`.
pub(crate) fn is_error_description(text: &str) -> bool {
    text.bytes()
        .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Every claim that can be released for the request: what a user who agreed
/// to everything would share.
pub(crate) fn everything_requested(interaction: &Interaction<'_>) -> BTreeSet<String> {
    let request = interaction.request();
    request
        .claims
        .consentable(interaction.client, &request.scope)
        .into_iter()
        .map(|item| item.name)
        .collect()
}

/// Why an experience could not take its step. The endpoint logs it and
/// sends the browser back to the client with `server_error`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExperienceError {
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error("a page could not be rendered")]
    Render(#[from] askama::Error),
    /// The provider's own data does not allow the step, for example a
    /// stored choice that names a user who no longer exists.
    #[error("{0}")]
    Inconsistent(&'static str),
}

/// What an experience's step produces.
pub(crate) type StepResult = Result<Step, ExperienceError>;

/// A boxed future, so that [`Experience`] can be used as a trait object.
pub(crate) type StepFuture<'a> = Pin<Box<dyn Future<Output = StepResult> + Send + 'a>>;

/// Form fields submitted by the browser.
pub(crate) type Form = crate::http::Params;

/// One way of interacting with the user at the authorization endpoint.
pub(crate) trait Experience: Send + Sync + Debug {
    /// The name used to select this experience in configuration.
    fn kind(&self) -> Kind;

    /// The first page, shown when the browser arrives with a valid request.
    fn start<'a>(&'a self, interaction: &'a Interaction<'a>) -> StepFuture<'a>;

    /// Handle a form submission. The endpoint has already verified the CSRF
    /// token and that the request is still pending.
    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, form: &'a Form) -> StepFuture<'a>;
}

#[cfg(test)]
mod tests;
