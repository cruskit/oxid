//! The `login` experience: the user signs in with a username and password
//! and consents on a single page.
//!
//! The page shows the client, the purpose it gave, and every claim that
//! would be released. Voluntary claims have a checkbox; essential ones do
//! not, and can only be refused by cancelling.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;

use super::{Approval, Decision, Experience, Form, Interaction, Kind, Page, Step, StepFuture};
use crate::claims::{self, ConsentItem};
use crate::error::ErrorCode;
use crate::user::UserStore;
use crate::util::html_escape;

/// Prefix of the consent form's per-claim checkboxes: `share_<claim>`.
const SHARE_FIELD_PREFIX: &str = "share_";

const STYLE: &str = "ul.claims{list-style:none;padding:0}ul.claims li{margin:.4rem 0}\
ul.claims label{display:inline;margin:0}.required{color:#555;font-size:.85em}";

#[derive(Debug)]
pub struct Login {
    users: Arc<dyn UserStore>,
}

impl Login {
    pub fn new(users: Arc<dyn UserStore>) -> Self {
        Self { users }
    }
}

impl Experience for Login {
    fn kind(&self) -> Kind {
        Kind::Login
    }

    fn start<'a>(&'a self, interaction: &'a Interaction<'a>) -> StepFuture<'a> {
        Box::pin(async move { login_page(interaction, None, &BTreeSet::new()).into() })
    }

    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, form: &'a Form) -> StepFuture<'a> {
        Box::pin(async move {
            match form.get("action") {
                Some("deny") => Decision::Deny {
                    code: ErrorCode::AccessDenied,
                    description: "the user denied the request".to_owned(),
                }
                .into(),
                Some("approve") => self.approve(interaction, form).await,
                _ => login_page(
                    interaction,
                    Some("Choose whether to continue or cancel."),
                    &BTreeSet::new(),
                )
                .into(),
            }
        })
    }
}

impl Login {
    async fn approve(&self, interaction: &Interaction<'_>, form: &Form) -> Step {
        let username = form.get("username").unwrap_or_default().to_owned();
        let password = form.get("password").unwrap_or_default().to_owned();
        let users = Arc::clone(&self.users);
        // Password hashing is CPU-bound; keep it off the async workers.
        let user = tokio::task::spawn_blocking(move || users.authenticate(&username, &password))
            .await
            .ok()
            .flatten();

        let (shared, declined) = user_selection(interaction, form);
        let Some(user) = user else {
            if interaction
                .state
                .store
                .record_failed_login(interaction.request_uri)
            {
                return login_page(
                    interaction,
                    Some("The username or password is incorrect."),
                    &declined.into_iter().collect(),
                )
                .into();
            }
            tracing::warn!(client_id = %interaction.client.id, "too many failed sign-in attempts");
            return Decision::Deny {
                code: ErrorCode::AccessDenied,
                description: "too many failed sign-in attempts".to_owned(),
            }
            .into();
        };

        Decision::Approve(Approval {
            user_subject: user.subject.clone(),
            shared_claims: shared,
            declined,
            id_token_edits: None,
            txn: None,
        })
        .into()
    }
}

/// What the user chose on the consent form: the claims they agreed to share
/// and the voluntary ones they unticked. Essential claims are always shared,
/// whatever was submitted, and only claims that were offered count.
fn user_selection(interaction: &Interaction<'_>, form: &Form) -> (BTreeSet<String>, Vec<String>) {
    let request = interaction.request();
    let items: Vec<ConsentItem> = request
        .claims
        .consentable(interaction.client, &request.scope);
    let shared = claims::shared_claims(&items, |name| {
        form.get(&format!("{SHARE_FIELD_PREFIX}{name}")).is_some()
    });
    let declined = items
        .into_iter()
        .map(|item| item.name)
        .filter(|name| !shared.contains(name))
        .collect();
    (shared, declined)
}

fn login_page(
    interaction: &Interaction<'_>,
    error: Option<&str>,
    // Voluntary claims to show unticked, when the page is shown again.
    declined: &BTreeSet<String>,
) -> Page {
    let client = interaction.client;
    let request = interaction.request();
    let mut body = String::new();
    let _ = write!(
        body,
        "<h1>Sign in to continue to <span id=\"client-name\">{}</span></h1>",
        html_escape(&client.name)
    );
    if let Some(error) = error {
        let _ = write!(
            body,
            "<p id=\"error\" class=\"error\">{}</p>",
            html_escape(error)
        );
    }
    if let Some(purpose) = &request.purpose {
        let _ = write!(
            body,
            "<p>Why this is being requested:</p><p id=\"purpose\" class=\"box\">{}</p>",
            html_escape(purpose)
        );
    }

    body.push_str(&interaction.form_open());

    // Only what can actually be released is listed. `txn` is technical and
    // is not shown (ConnectID identity assurance §5.3.2). Essential claims
    // have no checkbox: they can only be refused by cancelling.
    let requested = request.claims.consentable(client, &request.scope);
    if requested.is_empty() {
        body.push_str(
            "<p id=\"requested-none\">This application will confirm that you signed in. \
             No personal details will be shared.</p>",
        );
    } else {
        body.push_str(
            "<p>If you continue, this will be shared:</p><ul id=\"requested\" class=\"claims\">",
        );
        for item in &requested {
            let name = html_escape(&item.name);
            let label = html_escape(&item.label);
            if item.essential {
                let _ = write!(
                    body,
                    "<li data-claim=\"{name}\" data-essential=\"true\">{label} \
                     <span class=\"required\">(required)</span></li>"
                );
            } else {
                let checked = if declined.contains(&item.name) {
                    ""
                } else {
                    " checked"
                };
                let _ = write!(
                    body,
                    "<li data-claim=\"{name}\"><label>\
                     <input type=\"checkbox\" id=\"share-{name}\" \
                     name=\"{SHARE_FIELD_PREFIX}{name}\" value=\"1\"{checked}>{label}</label></li>"
                );
            }
        }
        body.push_str("</ul>");
        if requested.iter().any(|item| !item.essential) {
            body.push_str(
                "<p id=\"optional-hint\">Untick anything optional that you do not want to share.</p>",
            );
        }
        if requested.iter().any(|item| item.essential) {
            body.push_str(
                "<p id=\"required-hint\">Required items are needed by the application. \
                 If you do not want to share them, cancel.</p>",
            );
        }
    }

    body.push_str(
        "<label for=\"username\">Username</label>\
         <input id=\"username\" name=\"username\" autocomplete=\"username\" autofocus>\
         <label for=\"password\">Password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\">\
         <button id=\"approve\" type=\"submit\" name=\"action\" value=\"approve\">Sign in and allow</button>\
         <button id=\"deny\" type=\"submit\" name=\"action\" value=\"deny\" formnovalidate>Cancel</button>\
         </form>",
    );

    Page {
        title: "Sign in".to_owned(),
        body,
        style: STYLE,
        script: None,
    }
}
