//! The `login` experience: what an end user of an identity provider sees.
//!
//! There are two pages:
//!
//! 1. **Log in.** Says which client is asking, and takes a username and
//!    password. Nothing about what is being requested is shown to someone
//!    who has not signed in.
//! 2. **Consent.** Shows the client, the purpose it gave, and every claim
//!    that would be released together with the value that would be shared.
//!    Essential claims cannot be refused one by one, only by cancelling.
//!    Voluntary claims are off until the user turns them on.
//!
//! Signing in is remembered in the user's session for this request, tied to
//! a secret in a cookie, so that only the browser that signed in can
//! consent.

use std::collections::BTreeSet;
use std::sync::Arc;

use askama::Template;
use serde_json::{Map, Value};

use super::{
    Approval, Decision, Experience, Form, FormTarget, Interaction, Kind, Page, Step, StepFuture,
    duration_text, host_cookie, render,
};
use crate::claims::{self, ConsentItem};
use crate::error::ErrorCode;
use crate::theme::Theme;
use crate::user::{User, UserStore};
use crate::util::random_token;

/// Prefix of the consent form's per-claim checkboxes: `share_<claim>`. The
/// consent template writes the same prefix.
const SHARE_FIELD_PREFIX: &str = "share_";

/// Holds the secret that ties a signed-in session to this browser.
pub const LOGIN_COOKIE: &str = "__Host-oxid-login";

// The `action` values of the buttons in the templates.
const ACTION_SIGN_IN: &str = "sign-in";
const ACTION_APPROVE: &str = "approve";
const ACTION_DENY: &str = "deny";
/// Shows the consent page again with every voluntary claim turned on.
const ACTION_SHARE_ALL: &str = "share-all";

/// The styles of both pages.
const STYLE: &str = include_str!("../../templates/login/login.css");

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
        // A reload after signing in comes back to the consent page.
        Box::pin(async move {
            match self.signed_in(interaction) {
                Some(user) => consent_page(interaction, &user, false).into(),
                None => login_page(interaction, None).into(),
            }
        })
    }

    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, form: &'a Form) -> StepFuture<'a> {
        Box::pin(async move {
            match (form.get("action"), self.signed_in(interaction)) {
                (Some(ACTION_DENY), _) => Step {
                    decision: Decision::Deny {
                        code: ErrorCode::AccessDenied,
                        description: "the user denied the request".to_owned(),
                    },
                    set_cookies: vec![forget_browser()],
                },
                (Some(ACTION_SIGN_IN), _) => self.sign_in(interaction, form).await,
                (Some(ACTION_APPROVE), Some(user)) => approve(interaction, form, &user),
                (Some(ACTION_SHARE_ALL), Some(user)) => {
                    consent_page(interaction, &user, true).into()
                }
                // Consent is only ever taken from the browser that signed in.
                (Some(ACTION_APPROVE), None) => {
                    login_page(interaction, Some("Log in to continue.")).into()
                }
                (_, Some(user)) => consent_page(interaction, &user, false).into(),
                (_, None) => login_page(interaction, None).into(),
            }
        })
    }
}

impl Login {
    /// The user who signed in during this session, if this is the browser
    /// they did it from.
    fn signed_in(&self, interaction: &Interaction<'_>) -> Option<Arc<User>> {
        let signed_in = interaction.session.signed_in.as_ref()?;
        let secret = interaction.cookie(LOGIN_COOKIE)?;
        if !signed_in.is_browser(secret) {
            return None;
        }
        self.users.find_by_subject(&signed_in.user_subject)
    }

    async fn sign_in(&self, interaction: &Interaction<'_>, form: &Form) -> Step {
        let server_error = |error: &dyn std::fmt::Display, what: &str| -> Step {
            tracing::error!(%error, "{what}");
            Decision::Deny {
                code: ErrorCode::ServerError,
                description: "internal server error".to_owned(),
            }
            .into()
        };
        let store = &interaction.state.store;

        let username = form.get("username").unwrap_or_default().to_owned();
        let password = form.get("password").unwrap_or_default().to_owned();
        let users = Arc::clone(&self.users);
        // Password hashing is CPU-bound; keep it off the async workers.
        let user = tokio::task::spawn_blocking(move || users.authenticate(&username, &password))
            .await
            .ok()
            .flatten();

        let Some(user) = user else {
            return match store.record_failed_login(interaction.request_uri).await {
                Ok(true) => {
                    login_page(interaction, Some("The username or password is incorrect.")).into()
                }
                Ok(false) => {
                    tracing::warn!(
                        client_id = %interaction.client.id,
                        "too many failed sign-in attempts"
                    );
                    Decision::Deny {
                        code: ErrorCode::AccessDenied,
                        description: "too many failed sign-in attempts".to_owned(),
                    }
                    .into()
                }
                Err(error) => server_error(&error, "could not record a failed sign-in"),
            };
        };

        let secret = random_token(32);
        let session = interaction.session;
        if let Err(error) = store
            .sign_in(interaction.request_uri, session, &user.subject, &secret)
            .await
        {
            return server_error(&error, "could not record a sign-in");
        }
        let remaining = (session.expires_at - interaction.state.now()).max(1);
        Step {
            decision: Decision::Page(consent_page(interaction, &user, false)),
            set_cookies: vec![host_cookie(LOGIN_COOKIE, &secret, Some(remaining))],
        }
    }
}

/// A `Set-Cookie` value that removes the sign-in cookie.
fn forget_browser() -> String {
    host_cookie(LOGIN_COOKIE, "", Some(0))
}

fn approve(interaction: &Interaction<'_>, form: &Form, user: &User) -> Step {
    let (shared, declined) = user_selection(interaction, form);
    Step {
        decision: Decision::Approve(Approval {
            user_subject: user.subject.clone(),
            shared_claims: shared,
            declined,
            id_token_edits: None,
            txn: None,
        }),
        set_cookies: vec![forget_browser()],
    }
}

/// What the user chose on the consent form: the claims they agreed to share
/// and the voluntary ones they left off. Essential claims are always shared,
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

/// The login page: `templates/login/login.html`.
#[derive(Template)]
#[template(path = "login/login.html")]
struct LoginTemplate<'a> {
    theme: &'a Theme,
    form: FormTarget<'a>,
    client_name: &'a str,
    /// The first letter or digit of the client's name, for its avatar.
    client_initial: String,
    /// Why the page is being shown again, if it is.
    error: Option<&'a str>,
}

/// The first page. It names the client and says only that it wants
/// information shared; what and why is for the signed-in user to see.
fn login_page(interaction: &Interaction<'_>, error: Option<&str>) -> Page {
    let name = &interaction.client.name;
    let template = LoginTemplate {
        theme: interaction.theme(),
        form: interaction.form(),
        client_name: name,
        client_initial: name
            .chars()
            .find(|c| c.is_alphanumeric())
            .map(|c| c.to_uppercase().collect())
            .unwrap_or_default(),
        error,
    };
    Page {
        title: "Log in".to_owned(),
        body: render(&template),
        style: STYLE,
        script: None,
        wide: false,
    }
}

/// The consent page: `templates/login/consent.html`.
#[derive(Template)]
#[template(path = "login/consent.html")]
struct ConsentTemplate<'a> {
    theme: &'a Theme,
    form: FormTarget<'a>,
    client_name: &'a str,
    /// The signed-in user's name.
    user_name: String,
    /// Why the client is asking, in its own words.
    purpose: Option<&'a str>,
    /// Essential claims: shared if the user continues at all.
    required: Vec<ClaimRow>,
    /// Voluntary claims: shared only if the user turns them on.
    optional: Vec<ClaimRow>,
    /// How long the user has, in words.
    limit: String,
}

impl ConsentTemplate<'_> {
    /// Whether the request asks for no claims at all: a plain login.
    fn nothing_requested(&self) -> bool {
        self.required.is_empty() && self.optional.is_empty()
    }

    /// The middle of the sentence that says what the client wants.
    fn asking(&self) -> String {
        if self.nothing_requested() {
            format!("is asking you to log in with {}", self.theme.name)
        } else {
            "is asking you to share your information".to_owned()
        }
    }

    /// Whether "Turn all on" has anything to turn on.
    fn can_share_all(&self) -> bool {
        self.optional.iter().any(|row| row.value.is_some())
    }
}

/// One claim on the consent page: what it is and the value to be shared.
#[derive(Debug, PartialEq, Eq)]
struct ClaimRow {
    /// The claim's name, as in the request.
    name: String,
    /// What the claim is, in words.
    label: String,
    /// The value that would be shared. `None` when the user has no value
    /// for the claim, in which case nothing is released for it.
    value: Option<ClaimValue>,
    /// For a voluntary claim, whether its switch starts on.
    on: bool,
}

impl ClaimRow {
    fn new(item: &ConsentItem, value: Option<&Value>, on: bool) -> Self {
        Self {
            name: item.name.clone(),
            label: item.label.clone(),
            value: value.map(|value| ClaimValue::of(&item.name, value)),
            on,
        }
    }
}

/// A claim value as the user should read it. The value shown is the value
/// shared; only its presentation differs from the JSON.
#[derive(Debug, PartialEq, Eq)]
enum ClaimValue {
    /// One line of text.
    Text(String),
    /// A structured claim, one line per member.
    Members(Vec<Member>),
}

/// One member of a structured claim.
#[derive(Debug, PartialEq, Eq)]
struct Member {
    label: String,
    text: String,
}

impl ClaimValue {
    fn of(name: &str, value: &Value) -> Self {
        match value {
            Value::Object(members) if name == "address" => {
                Self::Text(claims::one_line_address(value).unwrap_or_else(|| members_text(members)))
            }
            Value::Object(members) => Self::Members(
                members
                    .iter()
                    .map(|(key, member)| Member {
                        label: member_label(key),
                        text: scalar_text(member),
                    })
                    .collect(),
            ),
            other => Self::Text(scalar_text(other)),
        }
    }
}

/// The second page: who is asking, why, and exactly what would be shared.
/// Voluntary claims are off unless the user asked for them all (`all_on`).
fn consent_page(interaction: &Interaction<'_>, user: &User, all_on: bool) -> Page {
    let client = interaction.client;
    let request = interaction.request();

    // Only what can actually be released is listed. `txn` is technical and
    // is not shown (ConnectID identity assurance §5.3.2).
    let requested = request.claims.consentable(client, &request.scope);
    let values =
        request
            .claims
            .shareable_values(user, client, &request.scope, interaction.state.now());
    let rows = |essential: bool| -> Vec<ClaimRow> {
        requested
            .iter()
            .filter(|item| item.essential == essential)
            .map(|item| ClaimRow::new(item, values.get(&item.name), all_on && !essential))
            .collect()
    };

    let template = ConsentTemplate {
        theme: interaction.theme(),
        form: interaction.form(),
        client_name: &client.name,
        user_name: user.display_name(),
        purpose: request.purpose.as_deref(),
        required: rows(true),
        optional: rows(false),
        limit: duration_text(interaction.state.security.session_ttl),
    };
    Page {
        title: format!("Share with {}", client.name),
        body: render(&template),
        style: STYLE,
        script: None,
        wide: false,
    }
}

fn members_text(members: &Map<String, Value>) -> String {
    members
        .values()
        .map(scalar_text)
        .collect::<Vec<_>>()
        .join(", ")
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "Yes".to_owned(),
        Value::Bool(false) => "No".to_owned(),
        Value::Array(items) => items.iter().map(scalar_text).collect::<Vec<_>>().join(", "),
        Value::Object(members) => members_text(members),
        other => other.to_string(),
    }
}

/// A readable name for a member of a structured claim.
fn member_label(key: &str) -> String {
    let known = match key {
        "beneficiary_name" => "Account name",
        "account_bsb" => "BSB",
        "account_number" | "account_number_international" => "Account number",
        "payid" => "PayID",
        "payid_type" => "PayID type",
        "bic_swift_code" => "BIC / SWIFT",
        "beneficiary_residential_address" => "Address",
        _ => {
            let text = key.replace('_', " ");
            let mut chars = text.chars();
            return chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            });
        }
    };
    known.to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn text(value: &str) -> ClaimValue {
        ClaimValue::Text(value.to_owned())
    }

    #[test]
    fn values_are_shown_as_text() {
        assert_eq!(ClaimValue::of("given_name", &json!("A<b>")), text("A<b>"));
        assert_eq!(ClaimValue::of("over18", &json!(true)), text("Yes"));
        assert_eq!(ClaimValue::of("over65", &json!(false)), text("No"));
        assert_eq!(
            ClaimValue::of(
                "address",
                &json!({"street_address": "1 Main St", "locality": "Sydney",
                        "region": "NSW", "postal_code": "2000"})
            ),
            text("1 Main St, Sydney, NSW 2000")
        );
        assert_eq!(
            ClaimValue::of(
                "beneficiary_account_au",
                &json!({"account_bsb": "123-456", "some_thing": "<x>"})
            ),
            ClaimValue::Members(vec![
                Member {
                    label: "BSB".to_owned(),
                    text: "123-456".to_owned()
                },
                Member {
                    label: "Some thing".to_owned(),
                    text: "<x>".to_owned()
                },
            ])
        );
    }

    #[test]
    fn the_consent_template_escapes_what_it_shows() {
        let item = |name: &str, essential: bool| ConsentItem {
            name: name.to_owned(),
            label: format!("Label of {name}"),
            essential,
        };
        let theme = Theme::default();
        let template = ConsentTemplate {
            theme: &theme,
            form: FormTarget::new("c\"srf", "rp", "urn:x"),
            client_name: "R&P <b>",
            user_name: "Al <i>".to_owned(),
            purpose: Some("see <this>"),
            required: vec![ClaimRow::new(
                &item("beneficiary_account_au", true),
                Some(&json!({"account_bsb": "<1>"})),
                false,
            )],
            optional: vec![
                ClaimRow::new(&item("given_name", false), Some(&json!("A<b>")), true),
                ClaimRow::new(&item("email", false), None, true),
            ],
            limit: "5 minutes".to_owned(),
        };
        let html = render(&template);
        for raw in ["<b>", "<i>", "<this>", "<1>", "c\"srf"] {
            assert!(!html.contains(raw), "{raw} in {html}");
        }
        assert!(html.contains("<em>BSB:</em> &#60;1&#62;"), "{html}");
        assert!(html.contains("name=\"share_given_name\" value=\"1\" checked>"));
        // A claim the user has no value for is listed, without a switch.
        assert!(html.contains("id=\"value-email\">Not on file"));
        assert!(!html.contains("share_email"));
        assert!(html.contains("id=\"share-all\""));
    }
}
