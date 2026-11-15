//! Endpoints of the `ci` experience (`crate::experience::ci`), which exist
//! only when that experience is selected.
//!
//! * `POST /ci/response`: a client chooses the response to a request it has
//!   pushed.
//! * `GET /ci`: what there is to choose from.
//!
//! Choosing a response is something only the client that pushed the request
//! may do, so the endpoint authenticates the client exactly as the pushed
//! authorization request endpoint does: `private_key_jwt` (ConnectID
//! §4.2-3.4), with the same audience and replay rules. A client assertion
//! can be used once, so the client makes a fresh one for this call.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::{OAuthForm, PATH_CI_RESPONSE, Params, authenticate_client, no_store};
use crate::epoch::{Seconds, Timestamp};
use crate::client::Client;
use crate::error::{ErrorCode, OAuthError};
use crate::experience::ci::default_user;
use crate::experience::{
    DEFAULT_ERROR_CONDITION, ERROR_CONDITIONS, MAX_ERROR_DESCRIPTION, error_condition, is_error_description,
};
use crate::state::AppState;
use crate::store::{PlannedResponse, PushedRequest, Visit};
use crate::user::User;

crate::wire::wire_enum! {
    /// The responses a client can choose.
    enum Outcome ("outcome") {
        Success = "success",
        Error = "error",
        Abandon = "abandon",
    }
}

/// The body of `GET /ci`.
#[derive(Debug, Serialize)]
struct Options {
    response_endpoint: String,
    response_delay: Seconds,
    outcomes: &'static [Outcome],
    default_user: Option<String>,
    users: Vec<OptionUser>,
    errors: Vec<OptionError>,
}

#[derive(Debug, Serialize)]
struct OptionUser {
    username: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct OptionError {
    error: ErrorCode,
    error_description: &'static str,
    meaning: &'static str,
}

/// `GET /ci`: the choices the response endpoint offers. Nothing here is
/// secret from anyone who may use a provider running this experience.
pub(super) async fn options(State(state): State<AppState>) -> Response {
    let body = Options {
        response_endpoint: state.url(PATH_CI_RESPONSE),
        response_delay: state.ci.response_delay,
        outcomes: Outcome::ALL,
        default_user: default_user(state.users.as_ref()).map(|user| user.username.clone()),
        users: state
            .users
            .list()
            .iter()
            .map(|user| OptionUser {
                username: user.username.clone(),
                name: user.display_name(),
            })
            .collect(),
        errors: ERROR_CONDITIONS
            .iter()
            .map(|condition| OptionError {
                error: condition.code,
                error_description: condition.description,
                meaning: condition.label,
            })
            .collect(),
    };
    no_store(Json(body).into_response())
}

/// The body of a `POST /ci/response` answer: the response that will be
/// given.
#[derive(Debug, Serialize)]
struct Chosen<'a> {
    request_uri: &'a str,
    outcome: Outcome,
    #[serde(flatten)]
    details: ChosenDetails,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ChosenDetails {
    Success {
        user: String,
        claims: BTreeSet<String>,
        declined: Vec<String>,
    },
    Error {
        error: ErrorCode,
        error_description: String,
    },
    Abandon {},
}

/// `POST /ci/response`: set the response to one pushed request.
///
/// Form parameters, beside the client authentication:
///
/// * `request_uri` (required): the request, which this client pushed and
///   which has not been answered yet.
/// * `outcome`: `success` (the default), `error`, or `abandon`: the user
///   leaves without deciding, so the next visit gets a page instead of a
///   redirect and the request stays pending. That holds for one visit; the
///   one after is answered as if nothing had been chosen. It takes no other
///   parameters.
/// * For a success:
///   * `user`: the username, or the subject, of the user to respond as.
///     Defaults to the first configured user.
///   * `voluntary_claims`: the names, separated by spaces, of the voluntary
///     claims to share. Those left out are declined. Absent means all of
///     them; present but empty means none. Essential claims are always
///     shared.
/// * For an error:
///   * `error`: one of the predefined error codes (`GET /ci` lists them).
///     Defaults to `access_denied`.
///   * `error_description`: replaces that error's default description.
///
/// A parameter that does not apply to the outcome is refused rather than
/// ignored: in a test, a response that is quietly not the one asked for is
/// worse than an error. Setting a response again replaces the earlier one.
pub(super) async fn plan_response(
    State(state): State<AppState>,
    OAuthForm(params): OAuthForm,
) -> Result<Response, OAuthError> {
    let client = authenticate_client(&state, &params).await?;
    let now = state.now();

    let request_uri = params
        .get("request_uri")
        .ok_or_else(|| OAuthError::invalid_request("request_uri is required"))?;
    let pushed = pending_request(&state, &client, request_uri, now)
        .await?
        .ok_or_else(|| {
            OAuthError::invalid_request(
                "request_uri is unknown, has expired, or has already been answered",
            )
        })?;

    let outcome = match params.get("outcome") {
        None => Outcome::Success,
        Some(text) => text
            .parse()
            .map_err(|error: crate::wire::UnknownName| OAuthError::invalid_request(error.to_string()))?,
    };
    let refuse_others = |names: &[&str]| -> Result<(), OAuthError> {
        match names.iter().find(|name| params.contains(name)) {
            Some(name) => Err(OAuthError::invalid_request(format!(
                "{name} does not apply to outcome={outcome}"
            ))),
            None => Ok(()),
        }
    };
    let (plan, details) = match outcome {
        Outcome::Success => {
            refuse_others(&["error", "error_description"])?;
            success(&state, &client, &pushed, &params)?
        }
        Outcome::Error => {
            refuse_others(&["user", "voluntary_claims"])?;
            error(&params)?
        }
        Outcome::Abandon => {
            refuse_others(&["user", "voluntary_claims", "error", "error_description"])?;
            (PlannedResponse::Abandon, ChosenDetails::Abandon {})
        }
    };

    // Long enough for the browser to arrive and the session to run its
    // course, whenever in the life of the request this was called.
    let kept_until = now + state.security.request_uri_ttl + state.security.session_ttl;
    state
        .store
        .plan_response(request_uri, &plan, kept_until)
        .await?;
    tracing::info!(client_id = %client.id, %outcome, "ci: the client chose the response");

    let body = Chosen {
        request_uri,
        outcome,
        details,
    };
    Ok(no_store(Json(body).into_response()))
}

/// The pushed request `request_uri` names, if `client` pushed it and it can
/// still be answered: its browser has yet to arrive in time, or is within
/// its session.
async fn pending_request(
    state: &AppState,
    client: &Client,
    request_uri: &str,
    now: Timestamp,
) -> Result<Option<PushedRequest>, OAuthError> {
    let pushed = match state.store.resume(request_uri, now).await? {
        Some(Visit::Active(pushed, _)) => Some(*pushed),
        Some(Visit::Expired(_)) => None,
        // No browser has arrived yet.
        None => state
            .store
            .peek_request(request_uri, now)
            .await?
            .filter(|pushed| pushed.expires_at > now),
    };
    // RFC 9126 §4: a request_uri belongs to the client that pushed it. Another
    // client is told no more than if it did not exist.
    Ok(pushed.filter(|pushed| pushed.request.client_id == client.id))
}

fn find_user(state: &AppState, name: &str) -> Option<std::sync::Arc<User>> {
    state
        .users
        .list()
        .iter()
        .find(|user| user.username == name || user.subject == name)
        .cloned()
}

fn success(
    state: &AppState,
    client: &Client,
    pushed: &PushedRequest,
    params: &Params,
) -> Result<(PlannedResponse, ChosenDetails), OAuthError> {
    let user = match params.get("user") {
        Some(name) => find_user(state, name)
            .ok_or_else(|| OAuthError::invalid_request(format!("user '{name}' does not exist")))?,
        None => default_user(state.users.as_ref())
            .ok_or_else(|| OAuthError::server_error("no users are configured"))?,
    };

    let request = &pushed.request;
    let items = request.claims.consentable(client, &request.scope);
    let chosen: Option<BTreeSet<&str>> = params.contains("voluntary_claims").then(|| {
        params
            .get("voluntary_claims")
            .unwrap_or_default()
            .split_ascii_whitespace()
            .collect()
    });
    for name in chosen.iter().flatten() {
        match items.iter().find(|item| item.name == *name) {
            Some(item) if !item.essential => {}
            Some(_) => {
                return Err(OAuthError::invalid_request(format!(
                    "voluntary_claims: '{name}' was requested as essential, so it is always shared"
                )));
            }
            None => {
                return Err(OAuthError::invalid_request(format!(
                    "voluntary_claims: '{name}' is not a claim this request can be given"
                )));
            }
        }
    }
    let shared_claims = crate::claims::shared_claims(&items, |name| {
        chosen.as_ref().is_none_or(|chosen| chosen.contains(name))
    });
    let declined: Vec<String> = items
        .into_iter()
        .map(|item| item.name)
        .filter(|name| !shared_claims.contains(name))
        .collect();

    let body = ChosenDetails::Success {
        user: user.username.clone(),
        claims: shared_claims.clone(),
        declined: declined.clone(),
    };
    let plan = PlannedResponse::Success {
        user_subject: user.subject.clone(),
        shared_claims,
        declined,
    };
    Ok((plan, body))
}

fn error(params: &Params) -> Result<(PlannedResponse, ChosenDetails), OAuthError> {
    let condition = match params.get("error") {
        Some(code) => error_condition(code).ok_or_else(|| {
            let known: Vec<&str> = ERROR_CONDITIONS
                .iter()
                .map(|condition| condition.code.as_str())
                .collect();
            OAuthError::invalid_request(format!(
                "error '{code}' is not one of: {}",
                known.join(", ")
            ))
        })?,
        None => &DEFAULT_ERROR_CONDITION,
    };
    let description = match params.get("error_description") {
        // RFC 6749 §4.1.2.1 limits what an error_description may contain.
        Some(text) if text.len() <= MAX_ERROR_DESCRIPTION && is_error_description(text) => text,
        Some(_) => {
            return Err(OAuthError::invalid_request(format!(
                "error_description must be at most {MAX_ERROR_DESCRIPTION} printable ASCII \
                 characters, without double quotes or backslashes"
            )));
        }
        None => condition.description,
    };
    let body = ChosenDetails::Error {
        error: condition.code,
        error_description: description.to_owned(),
    };
    let plan = PlannedResponse::Error {
        error: condition.code,
        description: description.to_owned(),
    };
    Ok((plan, body))
}

#[cfg(test)]
mod tests;
