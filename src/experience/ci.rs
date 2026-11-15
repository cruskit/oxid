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

use askama::Template;
use tokio::time::Instant;

use super::{
    Approval, Decision, Experience, ExperienceError, Form, Interaction, Kind, Page,
    StepResult, everything_requested, render,
};
use crate::store::PlannedResponse;
use crate::theme::Theme;
use crate::user::{User, UserStore};

/// How often a waiting request looks for a response chosen by the client.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub(crate) struct Ci {
    users: Arc<dyn UserStore>,
}

/// The user a response is about when the client does not name one.
pub(crate) fn default_user(users: &dyn UserStore) -> Option<Arc<User>> {
    users.list().first().cloned()
}

#[async_trait::async_trait]
impl Experience for Ci {
    fn kind(&self) -> Kind {
        Kind::Ci
    }

    async fn start(&self, interaction: &Interaction<'_>) -> StepResult {
        self.respond(interaction).await
    }

    /// There are no forms. Anything posted gets the same answer as arriving.
    async fn submit(&self, interaction: &Interaction<'_>, _form: &Form) -> StepResult {
        self.respond(interaction).await
    }
}

impl Ci {
    pub(crate) fn new(users: Arc<dyn UserStore>) -> Self {
        Self { users }
    }

    /// Wait for the client to choose a response, for as long as is left of
    /// the delay, then give the chosen response or the default one.
    ///
    /// The delay runs from when the session started, that is from the
    /// browser's first arrival, so a retry does not wait all over again.
    async fn respond(&self, interaction: &Interaction<'_>) -> StepResult {
        let arrived = interaction.session.expires_at - interaction.session_ttl();
        // Negative once the delay has passed, which `to_std` makes zero.
        let left = (arrived + interaction.ci_response_delay()) - interaction.now();
        let deadline = Instant::now() + left.to_std();
        loop {
            match interaction.store().planned_response().await?
            {
                Some(PlannedResponse::Abandon) => {
                    // One visit only: the next one is answered as usual.
                    interaction.store().clear_planned_response().await?;
                    return Ok(abandoned_page(interaction)?.into());
                }
                Some(plan) => return self.planned(interaction, plan),
                None => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return self.default_response(interaction);
            }
            tokio::time::sleep((deadline - now).min(POLL_INTERVAL)).await;
        }
    }

    /// Nobody chose: the first user shares everything that was requested.
    fn default_response(&self, interaction: &Interaction<'_>) -> StepResult {
        let user = default_user(self.users.as_ref())
            .ok_or(ExperienceError::Inconsistent("no users are configured"))?;
        tracing::info!(
            client_id = %interaction.client.id,
            user = %user.username,
            "ci: giving the default response"
        );
        Ok(Decision::Approve(Approval {
            user_subject: user.subject.clone(),
            shared_claims: everything_requested(interaction),
            declined: Vec::new(),
            id_token_edits: None,
            txn: None,
        })
        .into())
    }

    /// The response the client chose. It was checked when it was set.
    fn planned(&self, interaction: &Interaction<'_>, plan: PlannedResponse) -> StepResult {
        let client_id = &interaction.client.id;
        Ok(match plan {
            PlannedResponse::Success {
                user_subject,
                shared_claims,
                declined,
            } => {
                let user = self
                    .users
                    .find_by_subject(&user_subject)
                    .ok_or(ExperienceError::Inconsistent("the chosen user no longer exists"))?;
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
            PlannedResponse::Abandon => abandoned_page(interaction)?.into(),
            PlannedResponse::Error { error, description } => {
                tracing::info!(%client_id, %error, "ci: giving the error response the client chose");
                Decision::Deny {
                    code: error,
                    description,
                }
                .into()
            }
        })
    }
}

/// The page of an abandoned visit: `templates/ci/abandoned.html`.
#[derive(Template)]
#[template(path = "ci/abandoned.html")]
struct AbandonedTemplate<'a> {
    theme: &'a Theme,
    client_name: &'a str,
}

/// What the browser gets when the client chose that the user abandons the
/// visit: a page, and no redirect.
fn abandoned_page(interaction: &Interaction<'_>) -> askama::Result<Page> {
    tracing::info!(
        client_id = %interaction.client.id,
        "ci: giving no response, as the client chose"
    );
    let template = AbandonedTemplate {
        theme: interaction.theme(),
        client_name: &interaction.client.name,
    };
    Ok(Page {
        title: "No response".to_owned(),
        body: render(&template)?,
        style: "",
        script: None,
        wide: false,
    })
}
