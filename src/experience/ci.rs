//! The `ci` experience: no user, no pages. For automated tests of a relying
//! party, where nobody is there to click through a login. There is no
//! authentication, so it must never face real users.
//!
//! The browser (or `curl`) that arrives at the authorization endpoint is
//! answered with the redirect back to the client, as if a user had been
//! there and decided. What they "decided" is, by default, to approve: the
//! first configured user shares every claim that was requested.
//!
//! The client can choose a different response for a request it pushed: which
//! user, a success or one of the predefined errors, and which voluntary
//! claims are shared. It does that at the response endpoint
//! (`crate::http::ci`), authenticating as it does to push the request. To
//! leave it time to do so, the default response is held back for
//! `ci.response_delay` seconds from the browser's arrival. A request whose
//! response has been chosen is answered as soon as the choice is seen.
//!
//! Besides a success or an error, the client can choose that the user
//! *abandons* the visit: the browser gets a page instead of a redirect, and
//! the request stays pending, as when a real user looks at a login page and
//! closes it. That applies to one visit; the next is answered as usual.
//!
//! The choice is kept in the store, not in this process, so it reaches the
//! waiting request wherever that is running: on AWS Lambda the two are
//! handled by different instances of the function.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::{
    Approval, Decision, Experience, Form, Interaction, Kind, Page, Step, StepFuture,
    error_condition, everything_requested,
};
use crate::error::ErrorCode;
use crate::store::PlannedResponse;
use crate::user::{User, UserStore};
use crate::util::html_escape;

/// How often a waiting request looks for a response chosen by the client.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub struct Ci {
    users: Arc<dyn UserStore>,
}

/// The user a response is about when the client does not name one.
pub fn default_user(users: &dyn UserStore) -> Option<Arc<User>> {
    users.list().into_iter().next()
}

fn server_error(error: &dyn std::fmt::Display, what: &str) -> Step {
    tracing::error!(%error, "{what}");
    Decision::Deny {
        code: ErrorCode::ServerError,
        description: "internal server error".to_owned(),
    }
    .into()
}

impl Experience for Ci {
    fn kind(&self) -> Kind {
        Kind::Ci
    }

    fn start<'a>(&'a self, interaction: &'a Interaction<'a>) -> StepFuture<'a> {
        Box::pin(self.respond(interaction))
    }

    /// There are no forms. Anything posted gets the same answer as arriving.
    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, _form: &'a Form) -> StepFuture<'a> {
        Box::pin(self.respond(interaction))
    }
}

impl Ci {
    pub fn new(users: Arc<dyn UserStore>) -> Self {
        Self { users }
    }

    /// Wait for the client to choose a response, for as long as is left of
    /// the delay, then give the chosen response or the default one.
    ///
    /// The delay runs from when the session started, that is from the
    /// browser's first arrival, so a retry does not wait all over again.
    async fn respond(&self, interaction: &Interaction<'_>) -> Step {
        let state = interaction.state;
        let arrived = interaction.session.expires_at - state.security.session_ttl;
        let left = (arrived + state.ci.response_delay - state.now()).max(0);
        let deadline = Instant::now() + Duration::from_secs(left.unsigned_abs());
        loop {
            match state
                .store
                .planned_response(interaction.request_uri, state.now())
                .await
            {
                Ok(Some(PlannedResponse::Abandon)) => {
                    // One visit only: the next one is answered as usual.
                    return match state
                        .store
                        .clear_planned_response(interaction.request_uri)
                        .await
                    {
                        Ok(()) => abandoned_page(interaction).into(),
                        Err(error) => server_error(&error, "could not clear the planned response"),
                    };
                }
                Ok(Some(plan)) => return self.planned(interaction, plan),
                Ok(None) => {}
                Err(error) => return server_error(&error, "could not read the planned response"),
            }
            let now = Instant::now();
            if now >= deadline {
                return self.default_response(interaction);
            }
            tokio::time::sleep((deadline - now).min(POLL_INTERVAL)).await;
        }
    }

    /// Nobody chose: the first user shares everything that was requested.
    fn default_response(&self, interaction: &Interaction<'_>) -> Step {
        let Some(user) = default_user(self.users.as_ref()) else {
            return server_error(&"no users are configured", "cannot answer the request");
        };
        tracing::info!(
            client_id = %interaction.client.id,
            user = %user.username,
            "ci: giving the default response"
        );
        Decision::Approve(Approval {
            user_subject: user.subject.clone(),
            shared_claims: everything_requested(interaction),
            declined: Vec::new(),
            id_token_edits: None,
            txn: None,
        })
        .into()
    }

    /// The response the client chose. It was checked when it was set.
    fn planned(&self, interaction: &Interaction<'_>, plan: PlannedResponse) -> Step {
        let client_id = &interaction.client.id;
        match plan {
            PlannedResponse::Success {
                user_subject,
                shared_claims,
                declined,
            } => {
                let Some(user) = self.users.find_by_subject(&user_subject) else {
                    return server_error(&"the chosen user no longer exists", "ci");
                };
                tracing::info!(
                    %client_id,
                    user = %user.username,
                    "ci: giving the success response the client chose"
                );
                Decision::Approve(Approval {
                    user_subject,
                    shared_claims,
                    declined,
                    id_token_edits: None,
                    txn: None,
                })
                .into()
            }
            // Handled by the caller, which has to clear it.
            PlannedResponse::Abandon => abandoned_page(interaction).into(),
            PlannedResponse::Error { error, description } => {
                let Some(condition) = error_condition(&error) else {
                    return server_error(&"the chosen error is not a known one", "ci");
                };
                tracing::info!(%client_id, %error, "ci: giving the error response the client chose");
                Decision::Deny {
                    code: condition.code,
                    description,
                }
                .into()
            }
        }
    }
}

/// What the browser gets when the client chose that the user abandons the
/// visit: a page, and no redirect.
fn abandoned_page(interaction: &Interaction<'_>) -> Page {
    tracing::info!(
        client_id = %interaction.client.id,
        "ci: giving no response, as the client chose"
    );
    Page {
        title: "No response".to_owned(),
        body: format!(
            "<h1 id=\"abandoned\">No response was sent</h1>\
             <p class=\"lead\"><strong id=\"client-name\">{}</strong> asked oxID to act as a \
             user who leaves without deciding. The request is still pending: opening this \
             address again answers it.</p>",
            html_escape(&interaction.client.name)
        ),
        style: "",
        script: None,
        wide: false,
    }
}
