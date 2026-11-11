//! The `technical` experience: full visibility of, and control over, the
//! authorization flow. For development, debugging and testing relying
//! parties. There is no authentication, so it must never face real users.
//!
//! The flow has two pages:
//!
//! 1. **Request.** Shows the request object decoded (and, on demand, as the
//!    original JWT), a choice of predefined customers with the last one used
//!    preselected, and a choice of outcome: success or a predefined error.
//!    Shortcut buttons send an unedited success or an `access_denied`
//!    straight away.
//! 2. **Response.** For success, shows the ID token claims as they are about
//!    to be issued, as editable JSON. For an error, shows the error response
//!    with an editable description. Sending completes the flow.
//!
//! Edits to the ID token are stored as a difference from what was shown
//! ([`ClaimEdits`]), so claims the user leaves alone, such as `iat`, `exp`
//! and `at_hash`, still get their real values when the token is issued.

use std::fmt::Write as _;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{
    Approval, Decision, Experience, Form, Interaction, Kind, Page, Step, StepFuture, host_cookie,
};
use crate::error::ErrorCode;
use crate::id_token::{self, ClaimEdits};
use crate::store::Grant;
use crate::user::{User, UserStore};
use crate::util::{b64url, html_escape};

/// Remembers the customer used on the last completed flow.
pub const CUSTOMER_COOKIE: &str = "__Host-oxid-customer";
const CUSTOMER_COOKIE_MAX_AGE: i64 = 365 * 24 * 60 * 60;

/// The `outcome` form value for a successful response.
const OUTCOME_SUCCESS: &str = "success";

const STYLE: &str = "body{max-width:60rem}pre,textarea{font-family:ui-monospace,monospace;\
font-size:.85rem}pre{background:#f4f4f4;padding:.8rem;border-radius:.3rem;overflow-x:auto;\
white-space:pre-wrap;word-break:break-word}textarea{width:100%;box-sizing:border-box;\
padding:.5rem}select{width:100%;padding:.5rem}h2{font-size:1.1rem;margin-top:2rem}\
details{margin:.6rem 0}summary{cursor:pointer}.muted{color:#555;font-size:.9em}\
.banner{background:#fff3cd;border:1px solid #e0c060;padding:.6rem .8rem;border-radius:.3rem}\
dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{font-weight:600}dd{margin:0}";

/// An error the user can choose to return instead of a success.
#[derive(Debug, Clone, Copy)]
pub struct ErrorCondition {
    pub code: ErrorCode,
    /// What this condition simulates.
    pub label: &'static str,
    /// The default `error_description`, which the user can change.
    pub description: &'static str,
}

/// The predefined error conditions, in the order they are offered.
pub const ERROR_CONDITIONS: &[ErrorCondition] = &[
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

fn error_condition(code: &str) -> Option<&'static ErrorCondition> {
    ERROR_CONDITIONS
        .iter()
        .find(|condition| condition.code.as_str() == code)
}

#[derive(Debug)]
pub struct Technical {
    users: Arc<dyn UserStore>,
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

    /// The customer to preselect: the one named by the cookie from the last
    /// flow, if they still exist, otherwise the first.
    fn preselected(&self, interaction: &Interaction<'_>) -> Option<String> {
        let users = self.users.list();
        let remembered = interaction.cookie(CUSTOMER_COOKIE);
        users
            .iter()
            .find(|user| remembered == Some(cookie_value(user).as_str()))
            .or_else(|| users.first())
            .map(|user| user.subject.clone())
    }
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

impl Experience for Technical {
    fn kind(&self) -> Kind {
        Kind::Technical
    }

    fn start<'a>(&'a self, interaction: &'a Interaction<'a>) -> StepFuture<'a> {
        Box::pin(async move {
            let selected = self.preselected(interaction);
            self.request_page(interaction, selected.as_deref(), OUTCOME_SUCCESS, None)
                .into()
        })
    }

    fn submit<'a>(&'a self, interaction: &'a Interaction<'a>, form: &'a Form) -> StepFuture<'a> {
        Box::pin(async move { self.handle(interaction, form) })
    }
}

impl Technical {
    fn handle(&self, interaction: &Interaction<'_>, form: &Form) -> Step {
        let subject = form.get("customer").unwrap_or_default();
        let outcome = form.get("outcome").unwrap_or(OUTCOME_SUCCESS);
        let first_page = |error: &str| -> Step {
            let selected = self
                .customer(subject)
                .map(|user| user.subject.clone())
                .or_else(|| self.preselected(interaction));
            self.request_page(interaction, selected.as_deref(), outcome, Some(error))
                .into()
        };

        match form.get("action") {
            // Shortcut: access_denied, without visiting the response page.
            Some("deny") => deny(&ERROR_CONDITIONS[0], None),
            // Shortcut: an unedited success for the selected customer.
            Some("approve") => match self.customer(subject) {
                Some(user) => approve(interaction, &user, None, None),
                None => first_page("Choose a customer."),
            },
            Some("preview") => {
                if outcome == OUTCOME_SUCCESS {
                    match self.customer(subject) {
                        Some(user) => {
                            let txn = Uuid::new_v4().to_string();
                            let base = preview(interaction, &user, &txn);
                            let text = pretty(&Value::Object(base.clone()));
                            response_page(interaction, &user, &txn, &base, &text, None).into()
                        }
                        None => first_page("Choose a customer."),
                    }
                } else {
                    match error_condition(outcome) {
                        Some(condition) => {
                            error_page(interaction, condition, condition.description).into()
                        }
                        None => first_page("Choose an outcome."),
                    }
                }
            }
            Some("send") => self.send(interaction, form, &first_page),
            Some("send_error") => match error_condition(outcome) {
                Some(condition) => deny(condition, form.get("error_description")),
                None => first_page("Choose an outcome."),
            },
            // "back", or anything unrecognised: return to the first page
            // keeping the selections.
            _ => {
                let selected = self
                    .customer(subject)
                    .map(|user| user.subject.clone())
                    .or_else(|| self.preselected(interaction));
                self.request_page(interaction, selected.as_deref(), outcome, None)
                    .into()
            }
        }
    }

    /// Send the (possibly edited) ID token claims from the response page.
    fn send(
        &self,
        interaction: &Interaction<'_>,
        form: &Form,
        first_page: &dyn Fn(&str) -> Step,
    ) -> Step {
        let Some(user) = self.customer(form.get("customer").unwrap_or_default()) else {
            return first_page("Choose a customer.");
        };
        let txn = form.get("txn").unwrap_or_default();
        let base = form
            .get("base")
            .and_then(|text| serde_json::from_str::<Value>(text).ok());
        let (Some(Value::Object(base)), true) = (base, Uuid::parse_str(txn).is_ok()) else {
            return first_page("The response page was incomplete. Start again.");
        };

        let text = form.get("id_token").unwrap_or_default();
        let edited = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(edited)) => edited,
            Ok(_) => {
                let error = "The ID token claims must be a JSON object.";
                return response_page(interaction, &user, txn, &base, text, Some(error)).into();
            }
            Err(error) => {
                let error = format!("The ID token claims are not valid JSON: {error}");
                return response_page(interaction, &user, txn, &base, text, Some(&error)).into();
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
        approve(
            interaction,
            &user,
            (!edits.is_empty()).then_some(edits),
            Some(txn.to_owned()),
        )
    }

    /// Page 1: the request, the customer and the outcome.
    fn request_page(
        &self,
        interaction: &Interaction<'_>,
        selected: Option<&str>,
        outcome: &str,
        error: Option<&str>,
    ) -> Page {
        let client = interaction.client;
        let request = interaction.request();
        let mut body = String::new();
        let _ = write!(
            body,
            "<h1>Authorization request from <span id=\"client-name\">{}</span></h1>{BANNER}",
            html_escape(&client.name),
        );
        if let Some(error) = error {
            let _ = write!(
                body,
                "<p id=\"error\" class=\"error\">{}</p>",
                html_escape(error)
            );
        }

        // --- The request ---
        body.push_str("<h2>Request</h2><dl>");
        let mut row = |name: &str, id: &str, value: &str| {
            let _ = write!(
                body,
                "<dt>{name}</dt><dd id=\"{id}\">{}</dd>",
                html_escape(value)
            );
        };
        row("Client", "client-id", &client.id);
        row(
            "Profile",
            "client-profile",
            &format!("{:?}", client.profile).to_lowercase(),
        );
        row("Redirect URI", "redirect-uri", &request.redirect_uri);
        row("Scope", "scope", &request.scope.join(" "));
        if let Some(purpose) = &request.purpose {
            row("Purpose", "purpose", purpose);
        }
        body.push_str("</dl>");

        let (header, payload) = decode_jwt(&interaction.pushed.request_object);
        let _ = write!(
            body,
            "<p>Request object, decoded:</p>\
             <p class=\"muted\">Header</p><pre id=\"request-header\">{}</pre>\
             <p class=\"muted\">Payload</p><pre id=\"request-payload\">{}</pre>\
             <details id=\"request-original\"><summary>Show the original encoded JWT</summary>\
             <textarea id=\"request-encoded\" rows=\"8\" readonly>{}</textarea></details>",
            html_escape(&header),
            html_escape(&payload),
            html_escape(&interaction.pushed.request_object),
        );

        // --- The customer ---
        body.push_str(&interaction.form_open());
        let users = self.users.list();
        body.push_str(
            "<h2>Customer</h2><label for=\"customer\">Generate the response for</label>\
             <select id=\"customer\" name=\"customer\">",
        );
        for user in &users {
            let _ = write!(
                body,
                "<option value=\"{}\"{}>{} ({})</option>",
                html_escape(&user.subject),
                if selected == Some(user.subject.as_str()) {
                    " selected"
                } else {
                    ""
                },
                html_escape(&user.display_name()),
                html_escape(&user.username),
            );
        }
        body.push_str("</select>");
        for user in &users {
            let _ = write!(
                body,
                "<details class=\"customer\" data-customer=\"{}\">\
                 <summary>Attributes of {} ({})</summary><pre>{}</pre></details>",
                html_escape(&user.subject),
                html_escape(&user.display_name()),
                html_escape(&user.username),
                html_escape(&pretty(&attributes(user))),
            );
        }

        // --- The outcome ---
        body.push_str(
            "<h2>Outcome</h2><label for=\"outcome\">Respond with</label>\
             <select id=\"outcome\" name=\"outcome\">",
        );
        let selected_attr = |value: &str| if outcome == value { " selected" } else { "" };
        let _ = write!(
            body,
            "<option value=\"{OUTCOME_SUCCESS}\"{}>Success: authorization code and ID token</option>",
            selected_attr(OUTCOME_SUCCESS)
        );
        for condition in ERROR_CONDITIONS {
            let code = condition.code.as_str();
            let _ = write!(
                body,
                "<option value=\"{code}\"{}>Error: {code} ({})</option>",
                selected_attr(code),
                html_escape(condition.label),
            );
        }
        body.push_str(
            "</select>\
             <button id=\"preview\" type=\"submit\" name=\"action\" value=\"preview\">\
             Review response</button>\
             <p class=\"muted\">Or respond immediately, without reviewing:</p>\
             <button id=\"approve\" type=\"submit\" name=\"action\" value=\"approve\">\
             Send success now</button>\
             <button id=\"deny\" type=\"submit\" name=\"action\" value=\"deny\">\
             Send access_denied now</button></form>",
        );

        Page {
            title: "Authorization request".to_owned(),
            body,
            style: STYLE,
        }
    }
}

const BANNER: &str = "<p class=\"banner\" id=\"technical-banner\">Technical experience. \
There is no authentication here: this is for development and testing only.</p>";

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
fn everything_requested(interaction: &Interaction<'_>) -> std::collections::BTreeSet<String> {
    let request = interaction.request();
    request
        .claims
        .consentable(interaction.client, &request.scope)
        .into_iter()
        .map(|item| item.name)
        .collect()
}

fn approve(
    interaction: &Interaction<'_>,
    user: &User,
    id_token_edits: Option<ClaimEdits>,
    txn: Option<String>,
) -> Step {
    Step {
        decision: Decision::Approve(Approval {
            user_subject: user.subject.clone(),
            shared_claims: everything_requested(interaction),
            declined: Vec::new(),
            id_token_edits,
            txn,
        }),
        set_cookies: vec![remember(user)],
    }
}

fn deny(condition: &ErrorCondition, description: Option<&str>) -> Step {
    let description = description
        .map(str::trim)
        .filter(|text| !text.is_empty() && text.len() <= 500 && is_error_description(text))
        .unwrap_or(condition.description);
    Decision::Deny {
        code: condition.code,
        description: description.to_owned(),
    }
    .into()
}

/// RFC 6749 §4.1.2.1: `error_description` is printable ASCII without `"` or
/// `\`.
fn is_error_description(text: &str) -> bool {
    text.bytes()
        .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Page 2, success: the ID token claims, editable.
fn response_page(
    interaction: &Interaction<'_>,
    user: &User,
    txn: &str,
    base: &Map<String, Value>,
    text: &str,
    error: Option<&str>,
) -> Page {
    let request = interaction.request();
    let mut body = String::new();
    let _ = write!(
        body,
        "<h1>Response to <span id=\"client-name\">{}</span></h1>{BANNER}",
        html_escape(&interaction.client.name),
    );
    if let Some(error) = error {
        let _ = write!(
            body,
            "<p id=\"error\" class=\"error\">{}</p>",
            html_escape(error)
        );
    }
    let _ = write!(
        body,
        "<h2>Authorization response</h2><dl>\
         <dt>Customer</dt><dd id=\"customer-name\">{} ({})</dd>\
         <dt>Redirect to</dt><dd id=\"redirect-uri\">{}</dd>\
         <dt>code</dt><dd class=\"muted\">generated when you send</dd>\
         <dt>state</dt><dd id=\"state\">{}</dd>\
         <dt>iss</dt><dd id=\"iss\">{}</dd></dl>",
        html_escape(&user.display_name()),
        html_escape(&user.username),
        html_escape(&request.redirect_uri),
        html_escape(request.state.as_deref().unwrap_or("(none)")),
        html_escape(&interaction.state.issuer),
    );
    let rows = text.lines().count().clamp(12, 40) + 2;
    let _ = write!(
        body,
        "{form}\
         <input type=\"hidden\" name=\"customer\" value=\"{customer}\">\
         <input type=\"hidden\" name=\"outcome\" value=\"{OUTCOME_SUCCESS}\">\
         <input type=\"hidden\" name=\"txn\" value=\"{txn}\">\
         <input type=\"hidden\" name=\"base\" value=\"{base}\">\
         <h2>ID token claims</h2>\
         <p class=\"muted\">This is the ID token payload before it is signed. Change, add or \
         remove claims as you wish. Claims you leave alone are issued with their real values: \
         <code>iat</code>, <code>exp</code> and <code>auth_time</code> are set when the token \
         is issued, and <code>at_hash</code> is computed from the access token.</p>\
         <label for=\"id_token\">ID token claims (JSON)</label>\
         <textarea id=\"id_token\" name=\"id_token\" rows=\"{rows}\" spellcheck=\"false\">{text}</textarea>\
         <button id=\"send\" type=\"submit\" name=\"action\" value=\"send\">Send response</button>\
         <button id=\"back\" type=\"submit\" name=\"action\" value=\"back\">Back</button></form>",
        form = interaction.form_open(),
        customer = html_escape(&user.subject),
        txn = html_escape(txn),
        base = html_escape(&Value::Object(base.clone()).to_string()),
        text = html_escape(text),
    );
    Page {
        title: "Response".to_owned(),
        body,
        style: STYLE,
    }
}

/// Page 2, error: the error response, with an editable description.
fn error_page(
    interaction: &Interaction<'_>,
    condition: &ErrorCondition,
    description: &str,
) -> Page {
    let request = interaction.request();
    let code = condition.code.as_str();
    let mut body = String::new();
    let _ = write!(
        body,
        "<h1>Error response to <span id=\"client-name\">{client}</span></h1>{BANNER}\
         <h2>Authorization response</h2><dl>\
         <dt>Simulates</dt><dd>{label}</dd>\
         <dt>Redirect to</dt><dd id=\"redirect-uri\">{redirect}</dd>\
         <dt>error</dt><dd id=\"error-code\">{code}</dd>\
         <dt>state</dt><dd id=\"state\">{state}</dd>\
         <dt>iss</dt><dd id=\"iss\">{iss}</dd></dl>\
         {form}\
         <input type=\"hidden\" name=\"outcome\" value=\"{code}\">\
         <label for=\"error_description\">error_description</label>\
         <input id=\"error_description\" name=\"error_description\" value=\"{description}\" \
         maxlength=\"500\">\
         <p class=\"muted\">No code or ID token is issued.</p>\
         <button id=\"send\" type=\"submit\" name=\"action\" value=\"send_error\">Send error</button>\
         <button id=\"back\" type=\"submit\" name=\"action\" value=\"back\">Back</button></form>",
        client = html_escape(&interaction.client.name),
        label = html_escape(condition.label),
        redirect = html_escape(&request.redirect_uri),
        state = html_escape(request.state.as_deref().unwrap_or("(none)")),
        iss = html_escape(&interaction.state.issuer),
        form = interaction.form_open(),
        description = html_escape(description),
    );
    Page {
        title: "Error response".to_owned(),
        body,
        style: STYLE,
    }
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
