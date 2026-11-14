//! The `technical` experience: full visibility of, and control over, the
//! authorization flow. For development, debugging and testing relying
//! parties. There is no authentication, so it must never face real users.
//!
//! Everything is on one page:
//!
//! - **Request.** The request's parameters, and the request object decoded
//!   or, on demand, as the original JWT.
//! - **Response.** A choice of predefined customers, with the one used on
//!   the last flow preselected, and a choice of outcome. For a success, the
//!   ID token claims as they are about to be issued, as editable JSON. For
//!   an error, a predefined error condition with an editable description.
//!
//! The page works as a plain HTML form. A small script improves it: choosing
//! another customer swaps in that customer's claims without a round trip,
//! and the JSON is checked as it is typed. If the script does not run and a
//! different customer is submitted than the claims were generated for, the
//! page is shown again with that customer's claims rather than sending a
//! mismatched response.
//!
//! Edits to the ID token are stored as a difference from what was shown
//! ([`ClaimEdits`]), so claims the user leaves alone, such as `iat`, `exp`
//! and `at_hash`, still get their real values when the token is issued.

use std::sync::Arc;

use askama::Template;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{
    Approval, Decision, ERROR_CONDITIONS, ErrorCondition, Experience, Form, FormTarget,
    Interaction, Kind, MAX_ERROR_DESCRIPTION, Page, Step, StepFuture, error_condition,
    everything_requested, host_cookie, is_error_description, render,
};
use crate::id_token::{self, ClaimEdits};
use crate::store::Grant;
use crate::user::{User, UserStore};
use crate::util::b64url;

/// Remembers the customer used on the last completed flow.
pub const CUSTOMER_COOKIE: &str = "__Host-oxid-customer";
const CUSTOMER_COOKIE_MAX_AGE: i64 = 365 * 24 * 60 * 60;

/// The `outcome` form value for an error response. Anything else, such as
/// the template's `success`, is a successful one.
const OUTCOME_ERROR: &str = "error";

/// The styles of the page.
const STYLE: &str = include_str!("../../templates/technical/technical.css");

/// Progressive enhancement for the page. Written in plain ES5 so that it
/// also runs in the conformance suite's scripted browser.
const SCRIPT: &str = include_str!("../../templates/technical/technical.js");

/// The page: `templates/technical/page.html`.
#[derive(Template)]
#[template(path = "technical/page.html")]
struct PageTemplate<'a> {
    form: FormTarget<'a>,
    client_name: &'a str,
    /// Why the page is being shown again, if something was wrong.
    error: Option<&'a str>,
    /// Something the user should know about what the page now shows.
    notice: Option<&'a str>,
    /// The request's parameters, one per row.
    request_rows: Vec<RequestRow<'a>>,
    /// The request object's header and payload, pretty-printed.
    request_header: String,
    request_payload: String,
    /// The request object as it was received.
    request_object: &'a str,
    customers: Vec<Customer>,
    /// Whether the selected customer is the one used on the last flow.
    remembered_is_selected: bool,
    /// Whether the error outcome is chosen, rather than success.
    error_outcome: bool,
    /// The transaction identifier the claims were generated with.
    txn: &'a str,
    /// The claims as generated, and the customer they were generated for.
    base: &'a str,
    base_customer: &'a str,
    /// The claims as shown in the editor, and its height in rows.
    claims_text: &'a str,
    claims_rows: usize,
    conditions: Vec<Condition>,
    error_description: &'a str,
    redirect_uri: &'a str,
    issuer: &'a str,
    /// JSON for the page's script, safe to put in a `<script>` block.
    data: String,
}

/// One parameter of the request.
struct RequestRow<'a> {
    label: &'static str,
    /// The `id` of the element holding the value.
    id: &'static str,
    value: std::borrow::Cow<'a, str>,
}

/// A customer who can be chosen for the response.
struct Customer {
    subject: String,
    display_name: String,
    username: String,
    /// Everything known about the customer, as pretty-printed JSON.
    attributes: String,
    selected: bool,
}

/// An error condition that can be chosen for the response.
struct Condition {
    code: &'static str,
    label: &'static str,
    selected: bool,
}

#[derive(Debug)]
pub struct Technical {
    users: Arc<dyn UserStore>,
}

/// Subjects are arbitrary strings, so the cookie carries an encoded form.
fn cookie_value(user: &User) -> String {
    b64url(user.subject.as_bytes())
}

fn remember(user: &User) -> String {
    host_cookie(
        CUSTOMER_COOKIE,
        &cookie_value(user),
        Some(CUSTOMER_COOKIE_MAX_AGE),
    )
}

/// What the page should show: the selections so far and any message.
#[derive(Debug, Default)]
struct View<'a> {
    /// Subject of the selected customer.
    customer: Option<String>,
    error_outcome: bool,
    error_code: Option<&'a str>,
    error_description: Option<&'a str>,
    /// The transaction identifier already shown, to keep it stable.
    txn: Option<&'a str>,
    /// The claims generated for the selected customer, when the page is
    /// shown again after a failed submission.
    base: Option<&'a str>,
    /// The text in the claims editor, when it differs from `base`.
    claims_text: Option<&'a str>,
    error: Option<String>,
    notice: Option<String>,
}

impl Experience for Technical {
    fn kind(&self) -> Kind {
        Kind::Technical
    }

    fn start<'a>(&'a self, interaction: &'a Interaction<'a>) -> StepFuture<'a> {
        Box::pin(async move { self.page(interaction, &View::default()).into() })
    }

    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, form: &'a Form) -> StepFuture<'a> {
        Box::pin(async move { self.handle(interaction, form) })
    }
}

impl Technical {
    pub fn new(users: Arc<dyn UserStore>) -> Self {
        Self { users }
    }

    fn customer(&self, subject: &str) -> Option<Arc<User>> {
        self.users
            .list()
            .into_iter()
            .find(|user| user.subject == subject)
    }

    /// The customer used on the last flow, if the browser's cookie names one
    /// that still exists.
    fn remembered(&self, interaction: &Interaction<'_>) -> Option<Arc<User>> {
        let remembered = interaction.cookie(CUSTOMER_COOKIE)?;
        self.users
            .list()
            .into_iter()
            .find(|user| cookie_value(user) == remembered)
    }

    fn handle(&self, interaction: &Interaction<'_>, form: &Form) -> Step {
        let subject = form.get("customer").unwrap_or_default();
        let error_outcome = form.get("outcome") == Some(OUTCOME_ERROR);
        let view = View {
            customer: self.customer(subject).map(|user| user.subject.clone()),
            error_outcome,
            error_code: form.get("error"),
            error_description: form.get("error_description"),
            ..View::default()
        };
        let again = |view: View<'_>, error: &str| -> Step {
            self.page(
                interaction,
                &View {
                    error: Some(error.to_owned()),
                    ..view
                },
            )
            .into()
        };

        if form.get("action") != Some("send") {
            return again(view, "Choose a response and send it.");
        }

        if error_outcome {
            return match form.get("error").and_then(error_condition) {
                Some(condition) => deny(condition, form.get("error_description")),
                None => again(view, "Choose one of the listed error conditions."),
            };
        }

        let Some(user) = self.customer(subject) else {
            return again(view, "Choose one of the listed customers.");
        };

        // The claims must have been generated for the customer being sent.
        // Without the page's script, changing the customer does not update
        // them, so show that customer's claims instead of sending.
        if form.get("base_customer") != Some(subject) {
            let notice = format!(
                "The claims have been regenerated for {}. Review them and send again.",
                user.display_name()
            );
            return self
                .page(
                    interaction,
                    &View {
                        notice: Some(notice),
                        ..view
                    },
                )
                .into();
        }

        let txn = form.get("txn").unwrap_or_default();
        let base_text = form.get("base").unwrap_or_default();
        let base = serde_json::from_str::<Value>(base_text).ok();
        let (Some(Value::Object(base)), true) = (base, Uuid::parse_str(txn).is_ok()) else {
            return again(
                view,
                "The page was incomplete. The claims have been regenerated.",
            );
        };

        let text = form.get("id_token").unwrap_or_default();
        let keep_text = |error: String| -> Step {
            self.page(
                interaction,
                &View {
                    customer: Some(user.subject.clone()),
                    txn: Some(txn),
                    base: Some(base_text),
                    claims_text: Some(text),
                    error: Some(error),
                    ..View::default()
                },
            )
            .into()
        };
        let edited = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(edited)) => edited,
            Ok(_) => return keep_text("The ID token claims must be a JSON object.".to_owned()),
            Err(error) => {
                return keep_text(format!("The ID token claims are not valid JSON: {error}"));
            }
        };

        let edits = ClaimEdits::between(&base, &edited);
        if !edits.is_empty() {
            tracing::warn!(
                client_id = %interaction.client.id,
                changed = %edits.set.keys().cloned().collect::<Vec<_>>().join(" "),
                removed = %edits.remove.iter().cloned().collect::<Vec<_>>().join(" "),
                "ID token claims were edited by hand"
            );
        }
        Step {
            decision: Decision::Approve(Approval {
                user_subject: user.subject.clone(),
                shared_claims: everything_requested(interaction),
                declined: Vec::new(),
                id_token_edits: (!edits.is_empty()).then_some(edits),
                txn: Some(txn.to_owned()),
            }),
            set_cookies: vec![remember(&user)],
        }
    }

    /// The whole experience: request on one side, response on the other.
    fn page(&self, interaction: &Interaction<'_>, view: &View<'_>) -> Page {
        let client = interaction.client;
        let request = interaction.request();
        let users = self.users.list();
        let remembered = self.remembered(interaction);
        let selected = view
            .customer
            .as_deref()
            .and_then(|subject| users.iter().find(|user| user.subject == subject))
            .or(remembered.as_ref())
            .or_else(|| users.first());
        let selected_subject = selected.map(|user| user.subject.as_str());

        // One transaction identifier for the page, and every customer's
        // claims generated with it, so the script can switch between them.
        let txn = view
            .txn
            .map_or_else(|| Uuid::new_v4().to_string(), str::to_owned);
        let previews: Map<String, Value> = users
            .iter()
            .map(|user| {
                let claims = Value::Object(preview(interaction, user, &txn));
                (user.subject.clone(), pretty(&claims).into())
            })
            .collect();
        let base = view.base.map_or_else(
            || {
                selected_subject
                    .and_then(|subject| previews.get(subject))
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_owned()
            },
            str::to_owned,
        );
        let claims_text = view.claims_text.unwrap_or(&base);

        let error_code = view
            .error_code
            .and_then(error_condition)
            .unwrap_or(&ERROR_CONDITIONS[0]);
        let error_description = view
            .error_description
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .unwrap_or(error_code.description);

        let mut request_rows = vec![
            RequestRow {
                label: "Client",
                id: "client-id",
                value: client.id.as_str().into(),
            },
            RequestRow {
                label: "Profile",
                id: "client-profile",
                value: format!("{:?}", client.profile).to_lowercase().into(),
            },
            RequestRow {
                label: "Redirect URI",
                id: "redirect-uri",
                value: request.redirect_uri.as_str().into(),
            },
            RequestRow {
                label: "Scope",
                id: "scope",
                value: request.scope.join(" ").into(),
            },
        ];
        if let Some(purpose) = &request.purpose {
            request_rows.push(RequestRow {
                label: "Purpose",
                id: "purpose",
                value: purpose.as_str().into(),
            });
        }
        let (request_header, request_payload) = decode_jwt(&interaction.pushed.request_object);

        // Data for the script. It is JSON in a non-executed block; `<` is
        // escaped so no value can close the block.
        let data = json!({
            "previews": previews,
            "errors": ERROR_CONDITIONS
                .iter()
                .map(|c| (c.code.as_str().to_owned(), Value::from(c.description)))
                .collect::<Map<String, Value>>(),
            "remembered": remembered.as_ref().map(|user| user.subject.clone()),
            "redirect_uri": request.redirect_uri,
            "state": request.state,
            "issuer": interaction.state.issuer,
        });

        let template = PageTemplate {
            form: interaction.form(),
            client_name: &client.name,
            error: view.error.as_deref(),
            notice: view.notice.as_deref(),
            request_rows,
            request_header,
            request_payload,
            request_object: &interaction.pushed.request_object,
            customers: users
                .iter()
                .map(|user| Customer {
                    subject: user.subject.clone(),
                    display_name: user.display_name(),
                    username: user.username.clone(),
                    attributes: pretty(&attributes(user)),
                    selected: selected_subject == Some(user.subject.as_str()),
                })
                .collect(),
            remembered_is_selected: remembered.is_some()
                && remembered.as_ref().map(|user| user.subject.as_str()) == selected_subject,
            error_outcome: view.error_outcome,
            txn: &txn,
            base: &base,
            base_customer: selected_subject.unwrap_or_default(),
            claims_text,
            claims_rows: claims_text.lines().count().clamp(14, 34) + 1,
            conditions: ERROR_CONDITIONS
                .iter()
                .map(|condition| Condition {
                    code: condition.code.as_str(),
                    label: condition.label,
                    selected: condition.code == error_code.code,
                })
                .collect(),
            error_description,
            redirect_uri: &request.redirect_uri,
            issuer: &interaction.state.issuer,
            data: data.to_string().replace('<', "\\u003c"),
        };

        Page {
            title: "Authorization request".to_owned(),
            body: render(&template),
            style: STYLE,
            script: Some(SCRIPT),
            wide: true,
        }
    }
}

/// The ID token claims as they would be issued for `user`.
fn preview(interaction: &Interaction<'_>, user: &User, txn: &str) -> Map<String, Value> {
    let request = interaction.request();
    let grant = Grant {
        id: String::new(),
        client_id: interaction.client.id.clone(),
        user_subject: user.subject.clone(),
        scope: request.scope.clone(),
        claims: request.claims.clone(),
        shared_claims: everything_requested(interaction),
        auth_time: interaction.state.now(),
        txn: txn.to_owned(),
        purpose: request.purpose.clone(),
        id_token_edits: None,
    };
    id_token::preview(
        interaction.state,
        interaction.client,
        user,
        &grant,
        request.nonce.as_deref(),
    )
}

/// In this experience nothing is declined: every claim that can be released
/// is, and the user removes what they do not want by editing the response.
fn deny(condition: &ErrorCondition, description: Option<&str>) -> Step {
    let description = description
        .map(str::trim)
        .filter(|text| {
            !text.is_empty() && text.len() <= MAX_ERROR_DESCRIPTION && is_error_description(text)
        })
        .unwrap_or(condition.description);
    Decision::Deny {
        code: condition.code,
        description: description.to_owned(),
    }
    .into()
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// The header and payload of a compact JWS, pretty-printed. Parts that do
/// not decode are described rather than hidden: this page is for debugging.
fn decode_jwt(token: &str) -> (String, String) {
    let part = |index: usize| -> String {
        let Some(encoded) = token.split('.').nth(index) else {
            return "(missing)".to_owned();
        };
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        decoded.map_or_else(|| "(not valid base64url JSON)".to_owned(), |v| pretty(&v))
    };
    (part(0), part(1))
}

/// Everything known about a customer, for display.
fn attributes(user: &User) -> Value {
    let mut out = json!({
        "username": user.username,
        "subject": user.subject,
        "claims": user.claims,
    });
    if let Some(account) = &user.bank_account {
        out["bank_account"] = json!({
            "beneficiary_name": account.beneficiary_name,
            "bsb": account.bsb,
            "account_number": account.account_number,
            "payid": account.payid,
            "payid_type": account.payid_type.map(crate::user::PayIdType::as_str),
            "bic_swift_code": account.bic_swift_code,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_jwt_for_display() {
        let header = b64url(br#"{"alg":"PS256","kid":"k1"}"#);
        let payload = b64url(br#"{"iss":"rp","scope":"openid"}"#);
        let (h, p) = decode_jwt(&format!("{header}.{payload}.sig"));
        assert!(h.contains("\"alg\": \"PS256\""), "{h}");
        assert!(p.contains("\"scope\": \"openid\""), "{p}");

        let (h, p) = decode_jwt("not-a-jwt");
        assert_eq!(h, "(not valid base64url JSON)");
        assert_eq!(p, "(missing)");
    }

    #[test]
    fn error_conditions_are_distinct_and_well_formed() {
        let mut codes: Vec<&str> = ERROR_CONDITIONS.iter().map(|c| c.code.as_str()).collect();
        assert_eq!(
            codes[0], "access_denied",
            "the deny shortcut uses the first"
        );
        for condition in ERROR_CONDITIONS {
            assert!(is_error_description(condition.description));
            assert!(error_condition(condition.code.as_str()).is_some());
        }
        codes.sort_unstable();
        let total = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), total);
        assert!(error_condition("success").is_none());
        assert!(error_condition("made_up").is_none());
    }

    #[test]
    fn custom_error_descriptions_must_be_safe() {
        let condition = &ERROR_CONDITIONS[0];
        let description = |input: Option<&str>| match deny(condition, input).decision {
            Decision::Deny { description, .. } => description,
            other => panic!("{other:?}"),
        };
        assert_eq!(description(Some("custom reason")), "custom reason");
        assert_eq!(description(Some("  padded  ")), "padded");
        assert_eq!(description(None), condition.description);
        assert_eq!(description(Some("   ")), condition.description);
        assert_eq!(description(Some("quote \" here")), condition.description);
        assert_eq!(description(Some("line\nbreak")), condition.description);
        assert_eq!(description(Some("caf\u{e9}")), condition.description);
        assert_eq!(description(Some(&"x".repeat(501))), condition.description);
    }
}
