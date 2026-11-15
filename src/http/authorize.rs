//! Authorization endpoint: the browser-facing half of the code flow.
//!
//! This module does the protocol work that is the same for every user
//! experience, and hands the interaction itself to the configured
//! [`Experience`](crate::experience::Experience).
//!
//! Only `request_uri` values issued by the PAR endpoint are accepted
//! (FAPI 2.0 §5.3.2.2-3). A `request_uri` is consumed when the interaction
//! reaches a decision, not when the page is loaded, so a reload does not
//! strand the user (§5.3.2.2 note 3).
//!
//! Two clocks apply. The `request_uri` lifetime limits how long the browser
//! may take to *arrive* (RFC 9126 §2.2). Arriving in time starts the user's
//! session, and from then on only the session (`security.session_ttl`)
//! limits how long they may take to sign in, read and decide. A user whose
//! session runs out is told so, and can go back to the client, which gets
//! `access_denied` by the usual error redirect.
//!
//! Failures are reported in one of two ways. When the request cannot be tied
//! to a registered redirect URI the user sees an error page and is *not*
//! redirected (the provider must not be an open redirector, §5.3.2.1-7).
//! Otherwise the error goes back to the client's redirect URI.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use url::Url;
use uuid::Uuid;

use super::page::{CSRF_COOKIE, Shell, csrf_cookie, error_page, is_csrf_token};
use crate::epoch::{Seconds, Timestamp};
use crate::cookie::{self, SetCookie};
use super::{Params, no_store};
use crate::client::Client;
use crate::error::{ErrorCode, Report};
use crate::experience::{
    Approval, Decision, FormTarget, Interaction, Page, StepResult, duration_text, render,
};
use crate::state::AppState;
use crate::store::{
    AuthorizationCode, ConsentOutcome, ConsentRecord, Grant, PushedRequest, StoreError,
    StoreResult, Visit,
};
use crate::util::{ct_eq, random_token};

/// Why the endpoint answers with its own error page rather than going on.
#[derive(Debug, thiserror::Error)]
enum AuthorizeError {
    /// The request cannot be used, and cannot safely be tied to a redirect
    /// URI, so the user is told why instead (FAPI 2.0 §5.3.2.1-7).
    #[error("{message}")]
    Rejected {
        status: StatusCode,
        message: &'static str,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("a page could not be rendered")]
    Render(#[from] askama::Error),
    /// Something the provider itself holds is unusable.
    #[error("{0}")]
    Internal(&'static str),
}

/// What the user is told about an internal failure. The detail is logged,
/// never shown.
const INTERNAL_FAILURE: &str =
    "The server could not complete the request. Please try again from the application.";

/// The message for a `request_uri` that is not, or no longer, usable.
const UNUSABLE_REQUEST_URI: &str =
    "The request_uri is invalid, has expired, or has already been used.";

impl AuthorizeError {
    fn bad_request(message: &'static str) -> Self {
        Self::Rejected {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    /// The one place the endpoint logs a failure and shows it.
    fn into_page(self, state: &AppState) -> Response {
        match self {
            Self::Rejected { status, message } => {
                tracing::info!(message, "authorization request rejected with an error page");
                error_page(state, status, message)
            }
            Self::Store(_) | Self::Render(_) | Self::Internal(_) => {
                tracing::error!(error = %Report(&self), "authorization endpoint failed");
                error_page(state, StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_FAILURE)
            }
        }
    }
}

/// The endpoint's response, whichever way it went.
fn respond(state: &AppState, result: Result<Response, AuthorizeError>) -> Response {
    result.unwrap_or_else(|error| error.into_page(state))
}

/// The `action` of the button on the session expiry page.
const ACTION_RETURN_EXPIRED: &str = "session-expired-return";

/// The session expiry page: `templates/session_expired.html`.
#[derive(Template)]
#[template(path = "session_expired.html")]
struct SessionExpiredTemplate<'a> {
    form: FormTarget<'a>,
    client_name: &'a str,
    /// How long the user had, in words.
    limit: String,
}

/// The `error_description` sent to the client when a user goes back to it
/// from the session expiry page.
const SESSION_TIMEOUT_DESCRIPTION: &str =
    "session timeout: the user did not complete the request in time";

/// Tell the user their session ran out, and offer the way back to the
/// client. The button posts to the decision endpoint, which answers with the
/// usual error redirect ([`return_expired`]).
fn session_expired_page(
    state: &AppState,
    client: &Client,
    request_uri: &str,
    pushed: &PushedRequest,
    csrf: &str,
) -> Result<Response, AuthorizeError> {
    let body = render(&SessionExpiredTemplate {
        form: FormTarget::new(csrf, &client.id, request_uri),
        client_name: &client.name,
        limit: duration_text(state.security.session_ttl),
    })?;
    let mut response = Shell {
        status: StatusCode::BAD_REQUEST,
        title: "Session expired",
        body: &body,
        style: "",
        script: None,
        redirect_to: Some(&pushed.request.redirect_uri),
        refresh: None,
        wide: false,
    }
    .render(&state.theme)?;
    cookie::set(&mut response, &[csrf_cookie(csrf)]);
    Ok(response)
}

/// Send a user whose session expired back to the client: `access_denied`,
/// by the same redirect as any other refusal. The request is consumed.
async fn return_expired(
    state: &AppState,
    client: &Client,
    request_uri: &str,
) -> Result<Response, AuthorizeError> {
    let now = state.now();
    let pushed = state
        .store
        .take_request(request_uri, now)
        .await?
        .ok_or(AuthorizeError::bad_request(UNUSABLE_REQUEST_URI))?;
    let request = pushed.request;
    tracing::info!(client_id = %client.id, "session expired; returning the user to the client");
    record_decision(
        state,
        client,
        request.purpose.as_deref(),
        None,
        now,
        ConsentOutcome::Denied,
    )
    .await?;
    redirect_error(
        state,
        &request.redirect_uri,
        request.state.as_deref(),
        ErrorCode::AccessDenied,
        SESSION_TIMEOUT_DESCRIPTION,
    )
}

/// Redirect the browser back to the client with `params` plus the `iss`
/// parameter (RFC 9207). 303 is used so the POST is never replayed
/// (FAPI 2.0 §5.3.2.2-10/11).
fn redirect_to_client(
    state: &AppState,
    redirect_uri: &str,
    params: &[(&str, &str)],
) -> Result<Response, AuthorizeError> {
    // Registered redirect URIs are checked when clients load, so this is
    // not expected to fail.
    let invalid = || AuthorizeError::Internal("a registered redirect URI is invalid");
    let mut url = Url::parse(redirect_uri).map_err(|_| invalid())?;
    url.query_pairs_mut()
        .extend_pairs(params)
        .append_pair("iss", &state.issuer);
    let location = HeaderValue::from_str(url.as_str()).map_err(|_| invalid())?;
    let mut response = no_store(StatusCode::SEE_OTHER.into_response());
    response.headers_mut().insert(header::LOCATION, location);
    Ok(response)
}

fn redirect_error(
    state: &AppState,
    redirect_uri: &str,
    client_state: Option<&str>,
    code: ErrorCode,
    description: &str,
) -> Result<Response, AuthorizeError> {
    let mut params = vec![("error", code.as_str()), ("error_description", description)];
    if let Some(client_state) = client_state {
        params.push(("state", client_state));
    }
    redirect_to_client(state, redirect_uri, &params)
}

/// The authorization endpoint URL for a request, as the client sent the
/// browser to it.
fn authorize_path(client_id: &str, request_uri: &str) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("request_uri", request_uri)
        .finish();
    format!("{}?{query}", super::PATH_AUTHORIZE)
}

/// Render an experience's page, setting the CSRF cookie its form relies on.
///
/// The page reloads itself when the session ends, which replaces it with the
/// session expiry page: the user is told, rather than finding out when they
/// submit the form.
fn experience_page(
    state: &AppState,
    page: &Page,
    interaction: &Interaction<'_>,
    cookies: &[SetCookie],
) -> Result<Response, AuthorizeError> {
    let remaining = interaction.session.expires_at - state.now();
    let mut response = Shell {
        status: StatusCode::OK,
        title: &page.title,
        body: &page.body,
        style: page.style,
        script: page.script,
        redirect_to: Some(&interaction.request().redirect_uri),
        refresh: Some((
            remaining.max(Seconds::new(1)),
            authorize_path(&interaction.client.id, interaction.request_uri),
        )),
        wide: page.wide,
    }
    .render(&state.theme)?;
    cookie::set(&mut response, &[csrf_cookie(interaction.csrf)]);
    cookie::set(&mut response, cookies);
    Ok(response)
}

/// The pushed request named by the browser's parameters, or why there is
/// none. `arriving` is whether the browser is loading the authorization
/// endpoint, which may start the user's session, as opposed to submitting a
/// form from within one.
async fn load_request(
    state: &AppState,
    client_id: Option<&str>,
    request_uri: Option<&str>,
    arriving: bool,
) -> Result<(std::sync::Arc<Client>, String, Visit), AuthorizeError> {
    let bad = AuthorizeError::bad_request;

    let client_id = client_id.ok_or(bad("The client_id parameter is missing."))?;
    let client = state
        .clients
        .get(client_id)
        .ok_or(bad("The client is not registered."))?;
    let request_uri = request_uri.ok_or(bad(
        "A pushed authorization request is required: the request_uri parameter is missing.",
    ))?;
    let now = state.now();
    let visit = if arriving {
        state.store.arrive(request_uri, now).await?
    } else {
        state.store.resume(request_uri, now).await?
    }
    .ok_or(bad(UNUSABLE_REQUEST_URI))?;
    let (Visit::Active(pushed, _) | Visit::Expired(pushed)) = &visit;
    // RFC 9126 §4: a request_uri is only usable by the client that pushed it.
    if pushed.request.client_id != client.id {
        return Err(bad("The request_uri was not issued to this client."));
    }
    Ok((client, request_uri.to_owned(), visit))
}

/// `GET /authorize`
pub(super) async fn authorize(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let result = arrive(&state, query.as_deref(), &headers).await;
    respond(&state, result)
}

async fn arrive(
    state: &AppState,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Result<Response, AuthorizeError> {
    let params = Params::parse(query.unwrap_or_default().as_bytes()).map_err(|_| {
        AuthorizeError::bad_request("A request parameter was sent more than once.")
    })?;

    // A request without PAR. If it names a redirect URI registered to the
    // client we can safely say so via redirect; otherwise show a page.
    if params.get("request_uri").is_none()
        && let Some(client) = params.get("client_id").and_then(|id| state.clients.get(id))
        && let Some(redirect_uri) = params.get("redirect_uri")
        && client.has_redirect_uri(redirect_uri)
    {
        return redirect_error(
            state,
            redirect_uri,
            params.get("state"),
            ErrorCode::InvalidRequest,
            "authorization requests must be sent via the pushed authorization request endpoint",
        );
    }

    let (client, request_uri, visit) = load_request(
        state,
        params.get("client_id"),
        params.get("request_uri"),
        true,
    )
    .await?;

    let csrf = cookie::get(headers, CSRF_COOKIE)
        .filter(|v| is_csrf_token(v))
        .map_or_else(|| random_token(32), str::to_owned);
    let (pushed, session) = match visit {
        Visit::Active(pushed, session) => (pushed, session),
        Visit::Expired(pushed) => {
            return session_expired_page(state, &client, &request_uri, &pushed, &csrf);
        }
    };
    let interaction = Interaction::new(
        state,
        &client,
        &request_uri,
        &pushed,
        &session,
        &csrf,
        headers,
    );
    let step = state.experience.start(&interaction).await;
    conclude(state, &interaction, step).await
}

/// `POST /authorize/decision`: a form submitted from an experience's page,
/// or from the session expiry page.
pub(super) async fn decision(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let result = decide(&state, &headers, &body).await;
    respond(&state, result)
}

async fn decide(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, AuthorizeError> {
    let params = Params::parse(body)
        .map_err(|_| AuthorizeError::bad_request("A form field was sent more than once."))?;

    // Double-submit check: the form value must match the cookie this origin
    // set, which a cross-site attacker can neither read nor set.
    let csrf_ok = match (cookie::get(headers, CSRF_COOKIE), params.get("csrf")) {
        (Some(cookie), Some(form)) => is_csrf_token(cookie) && ct_eq(cookie, form),
        _ => false,
    };
    if !csrf_ok {
        return Err(AuthorizeError::Rejected {
            status: StatusCode::FORBIDDEN,
            message: "This form could not be verified. Please start again from the application.",
        });
    }
    let csrf = params.get("csrf").unwrap_or_default();

    let (client, request_uri, visit) = load_request(
        state,
        params.get("client_id"),
        params.get("request_uri"),
        false,
    )
    .await?;
    let (pushed, session) = match visit {
        Visit::Active(pushed, session) => (pushed, session),
        // Too late to decide anything: whatever was submitted, the only way
        // on is back to the client with an error.
        Visit::Expired(_) if params.get("action") == Some(ACTION_RETURN_EXPIRED) => {
            return return_expired(state, &client, &request_uri).await;
        }
        Visit::Expired(pushed) => {
            return session_expired_page(state, &client, &request_uri, &pushed, csrf);
        }
    };
    let interaction = Interaction::new(
        state,
        &client,
        &request_uri,
        &pushed,
        &session,
        csrf,
        headers,
    );
    let step = state.experience.submit(&interaction, &params).await;
    conclude(state, &interaction, step).await
}

/// Turn an experience's step into the HTTP response, completing the
/// protocol side of a final decision.
///
/// An experience that fails is the one case where the endpoint does not
/// show its error page: the request is real and its redirect URI is known,
/// so the browser goes back to the client with `server_error`, as RFC 6749
/// §4.1.2.1 provides. The failure is logged here, once.
async fn conclude(
    state: &AppState,
    interaction: &Interaction<'_>,
    step: StepResult,
) -> Result<Response, AuthorizeError> {
    let request = interaction.request();
    let now = state.now();
    let step = step.unwrap_or_else(|error| {
        tracing::error!(
            error = %Report(&error),
            client_id = %interaction.client.id,
            experience = %state.experience.kind(),
            "the experience failed"
        );
        Decision::Deny {
            code: ErrorCode::ServerError,
            description: "internal server error".to_owned(),
        }
        .into()
    });
    let mut response = match step.decision {
        Decision::Page(page) => {
            return experience_page(state, &page, interaction, &step.set_cookies);
        }
        Decision::Deny { code, description } => {
            // Only the caller that consumes the request records the
            // decision. If a concurrent request got there first, it has
            // been recorded once already; this browser is still sent back
            // with the error.
            if state
                .store
                .take_request(interaction.request_uri, now)
                .await?
                .is_some()
            {
                record_decision(
                    state,
                    interaction.client,
                    request.purpose.as_deref(),
                    None,
                    now,
                    ConsentOutcome::Denied,
                )
                .await?;
            }
            redirect_error(
                state,
                &request.redirect_uri,
                request.state.as_deref(),
                code,
                &description,
            )?
        }
        Decision::Approve(approval) => {
            // One-time use is enforced here, at the point of authorization.
            // A request whose sign-in attempts ran out cannot be approved,
            // even by a sign-in that raced the last failure.
            let pushed = state
                .store
                .take_request(interaction.request_uri, now)
                .await?
                .filter(|pushed| !pushed.is_exhausted())
                .ok_or(AuthorizeError::bad_request(UNUSABLE_REQUEST_URI))?;
            let request = pushed.request;
            let txn = record_decision(
                state,
                interaction.client,
                request.purpose.as_deref(),
                Some(&approval),
                now,
                ConsentOutcome::Approved,
            )
            .await?;
            let code = AuthorizationCode {
                grant: Grant {
                    id: random_token(16),
                    client_id: interaction.client.id.clone(),
                    user_subject: approval.user_subject,
                    scope: request.scope,
                    claims: request.claims,
                    shared_claims: approval.shared_claims,
                    auth_time: now,
                    txn,
                    purpose: request.purpose,
                    id_token_edits: approval.id_token_edits,
                },
                redirect_uri: request.redirect_uri.clone(),
                code_challenge: request.code_challenge,
                nonce: request.nonce,
                expires_at: now + state.security.authorization_code_ttl,
            };
            let code = state.store.create_code(code).await?;
            let mut out = vec![("code", code.as_str())];
            if let Some(client_state) = &request.state {
                out.push(("state", client_state));
            }
            redirect_to_client(state, &request.redirect_uri, &out)?
        }
    };
    cookie::set(&mut response, &step.set_cookies);
    Ok(response)
}

/// Record the outcome of a transaction, with the purpose the client gave
/// (OAuth 2 Purpose §5), and return the transaction's identifier.
async fn record_decision(
    state: &AppState,
    client: &Client,
    purpose: Option<&str>,
    approval: Option<&Approval>,
    now: Timestamp,
    outcome: ConsentOutcome,
) -> StoreResult<String> {
    let txn = approval
        .and_then(|a| a.txn.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let claims: Vec<String> = approval
        .map(|a| a.shared_claims.iter().cloned().collect())
        .unwrap_or_default();
    let declined: Vec<String> = approval.map(|a| a.declined.clone()).unwrap_or_default();
    tracing::info!(
        %txn,
        client_id = %client.id,
        experience = %state.experience.kind(),
        purpose = purpose.unwrap_or_default(),
        shared = %claims.join(" "),
        declined = %declined.join(" "),
        ?outcome,
        "authorization request decided"
    );
    state
        .store
        .record_consent(ConsentRecord {
            txn: txn.clone(),
            client_id: client.id.clone(),
            user_subject: approval.map(|a| a.user_subject.clone()),
            purpose: purpose.map(str::to_owned),
            claims,
            declined,
            decided_at: now,
            outcome,
        })
        .await?;
    Ok(txn)
}

#[cfg(test)]
mod tests;
