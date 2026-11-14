//! What every page at the authorization endpoint shares: the document
//! shell around the content, its content security policy, the error page,
//! and the CSRF cookie that every form relies on.

use askama::Template;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use url::Url;

use super::no_store;
use crate::cookie::{SameSite, SetCookie};
use crate::experience::render;
use crate::state::AppState;
use crate::theme::Theme;
use crate::util::random_token;

/// Double-submit CSRF cookie. The `__Host-` prefix pins it to this origin,
/// `Secure` and path `/` (RFC 6265bis §4.1.3.2).
pub(crate) const CSRF_COOKIE: &str = "__Host-oxid-csrf";

/// Content security policy for every page, before `form-action`, `img-src`
/// and `script-src` are added by [`content_security_policy`].
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     frame-ancestors 'none'; base-uri 'none'";

/// The policy for one page.
///
/// Forms post to this origin only. But the final post of an interaction is
/// answered with a redirect to the client's redirect URI, and browsers apply
/// `form-action` to that redirect as well (CSP3 §6.3.1; Chromium enforces
/// it). A page of an interaction therefore also names the origin of the
/// redirect URI of the request being decided, `redirect_to`, or the browser
/// blocks the authorization response. That URI is an exact match for one
/// the client registered, checked when the request was pushed.
///
/// A page loads nothing but the theme's logo, if the theme has one
/// (`logo`), and that comes from this origin.
fn content_security_policy(
    redirect_to: Option<&str>,
    nonce: Option<&str>,
    logo: bool,
) -> HeaderValue {
    let mut policy = format!("{CONTENT_SECURITY_POLICY}; form-action 'self'");
    let origin = redirect_to
        .and_then(|uri| Url::parse(uri).ok())
        .map(|uri| uri.origin())
        .filter(url::Origin::is_tuple)
        .map(|origin| origin.ascii_serialization());
    if let Some(origin) = origin {
        policy.push(' ');
        policy.push_str(&origin);
    }
    if logo {
        policy.push_str("; img-src 'self'");
    }
    if let Some(nonce) = nonce {
        policy.push_str("; script-src 'nonce-");
        policy.push_str(nonce);
        policy.push('\'');
    }
    HeaderValue::from_str(&policy).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
    })
}

/// Styles shared by every page: the base, and the card that pages for end
/// users sit in. They are written in terms of the theme's colours.
const STYLE: &str = include_str!("../../templates/shell.css");

/// The page shell, `templates/shell.html`: the document around a page's
/// content, carrying the theme.
#[derive(Template)]
#[template(path = "shell.html")]
struct ShellTemplate<'a> {
    theme: &'a Theme,
    title: &'a str,
    /// The page's content, already rendered from its own template.
    body: &'a str,
    base_style: &'static str,
    /// Extra CSS, after the shared styles.
    style: &'a str,
    wide: bool,
    /// The nonce the scripts run under.
    nonce: &'a str,
    scripts: Vec<&'a str>,
    /// Replace the page after a while; the template writes the timer.
    reload: Option<Reload<'a>>,
}

/// Replace the page with `url` after `after_ms` milliseconds.
struct Reload<'a> {
    url: &'a str,
    after_ms: i64,
}

/// One HTML page.
pub(super) struct Shell<'a> {
    pub status: StatusCode,
    pub title: &'a str,
    pub body: &'a str,
    /// Extra CSS, after the shared styles.
    pub style: &'a str,
    pub script: Option<&'a str>,
    /// Where a form on the page may end up redirecting to; see
    /// [`content_security_policy`].
    pub redirect_to: Option<&'a str>,
    /// Replace the page with `url` after this many seconds.
    pub refresh: Option<(i64, String)>,
    pub wide: bool,
}

impl Shell<'_> {
    pub(super) fn render(&self, theme: &Theme) -> Response {
        // A page's own script runs under a nonce; nothing else can. The nonce
        // is unguessable, so markup injected into the page could not carry it.
        let nonce = random_token(16);
        // The reload is a script timer, not a `<meta>` refresh: scripted
        // browsers, such as the conformance suite's, follow those at once.
        let reload = self.refresh.as_ref().map(|(after, url)| Reload {
            url,
            after_ms: after.saturating_mul(1000),
        });
        let scripts: Vec<&str> = self.script.into_iter().collect();
        let policy = content_security_policy(
            self.redirect_to,
            (!scripts.is_empty() || reload.is_some()).then_some(nonce.as_str()),
            theme.has_logo(),
        );
        let html = render(&ShellTemplate {
            theme,
            title: self.title,
            body: self.body,
            base_style: STYLE,
            style: self.style,
            wide: self.wide,
            nonce: &nonce,
            scripts,
            reload,
        });
        let mut response = no_store((self.status, Html(html)).into_response());
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
        response
    }
}

/// The error page: `templates/error.html`.
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    message: &'a str,
}

/// An error shown to the user because it is not safe to redirect.
pub(super) fn error_page(state: &AppState, status: StatusCode, message: &str) -> Response {
    tracing::info!(message, "authorization request rejected with an error page");
    Shell {
        status,
        title: "Request error",
        body: &render(&ErrorTemplate { message }),
        style: "",
        script: None,
        redirect_to: None,
        refresh: None,
        wide: false,
    }
    .render(&state.theme)
}

pub(super) fn is_csrf_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The CSRF cookie. Only this origin's own forms need it, so it is never
/// sent on a request another site starts.
pub(super) fn csrf_cookie(csrf: &str) -> SetCookie {
    SetCookie::host(CSRF_COOKIE, csrf, SameSite::Strict)
}
