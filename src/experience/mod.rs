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
use std::sync::Arc;

use askama::Template;

use crate::epoch::Seconds;
use crate::cookie::SetCookie;
use crate::error::ErrorCode;
use crate::id_token::ClaimEdits;
use crate::user::UserStore;

pub(crate) mod ci;
mod interaction;
pub(crate) mod login;
pub(crate) mod technical;

pub(crate) use interaction::Interaction;

crate::wire::wire_enum! {
    /// The experiences that can be selected in configuration.
    #[derive(Default)]
    pub enum Kind ("experience") {
        /// Technical debugging: inspect the request, pick a customer, edit the
        /// response or return an error. No authentication. Development only.
        #[default]
        Technical = "technical",
        /// Sign in with a username and password, then consent.
        Login = "login",
        /// No user at all: the request is answered automatically, with a
        /// response the client may choose. No authentication. Automated
        /// testing only.
        Ci = "ci",
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
pub(crate) fn duration_text(length: Seconds) -> String {
    let seconds = length.get();
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
/// The error condition chosen when none is: the user did not consent.
pub(crate) const DEFAULT_ERROR_CONDITION: ErrorCondition = ErrorCondition {

        code: ErrorCode::AccessDenied,
        label: "The user did not consent",
        description: "the user denied the request",
};

pub(crate) const ERROR_CONDITIONS: &[ErrorCondition] = &[
    DEFAULT_ERROR_CONDITION,
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

/// Form fields submitted by the browser.
pub(crate) type Form = crate::http::Params;

/// One way of interacting with the user at the authorization endpoint.
#[async_trait::async_trait]
pub(crate) trait Experience: Send + Sync + Debug {
    /// The name used to select this experience in configuration.
    fn kind(&self) -> Kind;

    /// The first page, shown when the browser arrives with a valid request.
    async fn start(&self, interaction: &Interaction<'_>) -> StepResult;

    /// Handle a form submission. The endpoint has already verified the CSRF
    /// token and that the request is still pending.
    async fn submit(&self, interaction: &Interaction<'_>, form: &Form) -> StepResult;
}

#[cfg(test)]
mod tests;
