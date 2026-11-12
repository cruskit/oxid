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

/// The `outcome` form value for an error response.
const OUTCOME_ERROR: &str = "error";

const STYLE: &str = "body{max-width:82rem;background:#f4f5f7;margin:1.5rem auto}\
h1{font-size:1.25rem;font-weight:500;margin:0}h2{font-size:.75rem;letter-spacing:.06em;\
color:#5b6472;margin:0 0 1rem;text-transform:uppercase}\
.top{display:flex;flex-wrap:wrap;gap:.75rem 1.25rem;align-items:center;margin-bottom:1rem}\
.top h1{flex:1 1 20rem}.banner{margin:0;background:#fff4d6;border:1px solid #e5c568;color:#5c4300;\
padding:.5rem .75rem;border-radius:.4rem;font-size:.8rem}\
.cols{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-start}\
.panel{background:#fff;border:1px solid #dde1e7;border-radius:.6rem;padding:1.25rem;min-width:0;\
box-sizing:border-box}.request{flex:1 1 27rem}.response{flex:1.25 1 32rem}\
pre,textarea,code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}\
pre{background:#f4f5f7;padding:.75rem;border-radius:.5rem;margin:.25rem 0 .75rem;line-height:1.55;\
white-space:pre-wrap;word-break:break-word}#request-encoded{word-break:break-all}\
textarea{width:100%;box-sizing:border-box;padding:.75rem;border:1px solid #b8bfca;border-radius:.5rem;\
background:#fbfbfc;line-height:1.55;resize:vertical}\
select,input[type=text]{width:100%;min-height:2.75rem;padding:0 .75rem;border:1px solid #b8bfca;\
border-radius:.5rem;background:#fff;font:inherit;box-sizing:border-box}\
label,.label{display:block;font-weight:600;font-size:.9rem;margin:1rem 0 .4rem}\
dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.35rem 1rem;margin:0 0 1rem;\
font-size:.9rem}dt{color:#5b6472}dd{margin:0;word-break:break-word}\
.muted{color:#5b6472;font-size:.8rem;line-height:1.5}.row{display:flex;flex-wrap:wrap;gap:.6rem;\
align-items:center;justify-content:space-between}\
.tabs,.outcomes{display:flex;gap:.5rem;flex-wrap:wrap}\
.tabs input,.outcomes input{position:absolute;opacity:0;width:auto}\
.tabs label{margin:0;padding:.45rem .9rem;border-radius:.4rem;font-size:.8rem;font-weight:500;\
cursor:pointer;background:#eef0f3}.tabs input:checked+label{background:#16181d;color:#fff}\
.tabs input:focus-visible+label,.outcomes input:focus-visible+label{outline:2px solid #1d4ed8;\
outline-offset:2px}\
.outcomes label{flex:1 1 12rem;margin:0;padding:.75rem .9rem;border:1px solid #b8bfca;\
border-radius:.5rem;cursor:pointer;font-weight:600}.outcomes label span{display:block;\
font-weight:400;color:#5b6472;font-size:.8rem;margin-top:.2rem}\
.outcomes input:checked+label{border-color:#1d4ed8;background:#eef3ff;box-shadow:0 0 0 1px #1d4ed8}\
.request:has(#view-original:checked) #request-decoded{display:none}\
.request:has(#view-decoded:checked) #request-original{display:none}\
.response:has(#outcome-error:checked) #panel-success{display:none}\
.response:has(#outcome-success:checked) #panel-error{display:none}\
.pill{font-size:.75rem;border-radius:999px;padding:.2rem .6rem;background:#e3f4e4;color:#1e4620}\
.pill.edited{background:#ffefc7;color:#7a4b00}.ok{color:#1e4620}.bad{color:#b42318}\
#json-status{font-size:.75rem;font-weight:500}.notice{background:#eef3ff;border:1px solid #b9c8f5;\
padding:.5rem .75rem;border-radius:.4rem;font-size:.85rem}\
button{min-height:2.75rem;border-radius:.5rem;font:inherit;cursor:pointer}\
#send{background:#1d4ed8;color:#fff;border:0;font-weight:600;padding:0 1.4rem}\
#send:disabled{background:#8a93a3;cursor:not-allowed}\
#reset{background:#fff;border:1px solid #b8bfca;min-height:2.25rem;padding:0 .75rem;margin:0;\
font-size:.8rem}.send{border-top:1px solid #e6e9ee;margin-top:1.25rem;padding-top:.25rem}\
[hidden]{display:none!important}";

/// Progressive enhancement for the page. Written in plain ES5 so that it
/// also runs in the conformance suite's scripted browser.
const SCRIPT: &str = r"(function () {
  var dataEl = document.getElementById('oxid-data');
  if (!dataEl) { return; }
  var data = JSON.parse(dataEl.textContent);
  function el(id) { return document.getElementById(id); }
  var customer = el('customer'), claims = el('id_token'), base = el('base');
  var baseCustomer = el('base_customer'), status = el('json-status');
  var edited = el('edited'), reset = el('reset'), send = el('send');
  var error = el('error'), description = el('error_description');
  var success = el('outcome-success'), failure = el('outcome-error');
  var redirect = el('redirect-preview'), notice = el('script-notice');
  var remembered = el('remembered');

  function validJson() {
    try {
      var value = JSON.parse(claims.value);
      return value !== null && typeof value === 'object' && !(value instanceof Array);
    } catch (e) { return false; }
  }
  function same(a, b) {
    try { return JSON.stringify(JSON.parse(a)) === JSON.stringify(JSON.parse(b)); }
    catch (e) { return false; }
  }
  function refresh() {
    var ok = validJson();
    var isSuccess = success.checked;
    status.textContent = ok ? 'Valid JSON' : 'Not a valid JSON object';
    status.className = ok ? 'ok' : 'bad';
    edited.hidden = !ok || same(claims.value, base.value);
    send.disabled = isSuccess && !ok;
    send.textContent = isSuccess ? 'Send response' : 'Send error';
    var lines = [data.redirect_uri];
    if (isSuccess) {
      lines.push('  ?code=(generated when you send)');
    } else {
      lines.push('  ?error=' + error.value);
      lines.push('  &error_description=' + (description.value || data.errors[error.value] || ''));
    }
    if (data.state !== null) { lines.push('  &state=' + data.state); }
    lines.push('  &iss=' + data.issuer);
    redirect.textContent = lines.join('\n');
  }
  function showAttributes() {
    var blocks = document.querySelectorAll('.attributes');
    for (var i = 0; i < blocks.length; i++) {
      blocks[i].hidden = blocks[i].getAttribute('data-customer') !== customer.value;
    }
    if (remembered) { remembered.hidden = customer.value !== data.remembered; }
  }
  function loadCustomer(replacedEdits) {
    var text = data.previews[customer.value];
    if (typeof text !== 'string') { return; }
    claims.value = text;
    base.value = text;
    baseCustomer.value = customer.value;
    notice.hidden = !replacedEdits;
  }

  customer.addEventListener('change', function () {
    var hadEdits = validJson() ? !same(claims.value, base.value) : true;
    loadCustomer(hadEdits);
    showAttributes();
    refresh();
  });
  reset.addEventListener('click', function () {
    claims.value = base.value;
    notice.hidden = true;
    refresh();
  });
  error.addEventListener('change', function () {
    description.value = data.errors[error.value] || '';
    refresh();
  });
  claims.addEventListener('input', refresh);
  description.addEventListener('input', refresh);
  success.addEventListener('change', refresh);
  failure.addEventListener('change', refresh);

  reset.hidden = false;
  showAttributes();
  refresh();
})();";

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

        let mut body = String::new();
        let _ = write!(
            body,
            "<div class=\"top\"><h1>Authorization request from \
             <span id=\"client-name\">{}</span></h1>\
             <p class=\"banner\" id=\"technical-banner\">Technical experience. \
             No authentication: development and testing only.</p></div>",
            html_escape(&client.name),
        );
        if let Some(error) = &view.error {
            let _ = write!(
                body,
                "<p id=\"error\" class=\"error\" role=\"alert\">{}</p>",
                html_escape(error)
            );
        }
        if let Some(notice) = &view.notice {
            let _ = write!(
                body,
                "<p id=\"notice\" class=\"notice\" role=\"status\">{}</p>",
                html_escape(notice)
            );
        }
        body.push_str("<div class=\"cols\">");

        // --- Request ---
        body.push_str(
            "<section class=\"panel request\" aria-label=\"Request\"><h2>1 · Request</h2><dl>",
        );
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
            "<div class=\"row\"><span class=\"label\">Request object</span>\
             <div class=\"tabs\" role=\"radiogroup\" aria-label=\"Request object format\">\
             <input type=\"radio\" name=\"request-view\" id=\"view-decoded\" checked>\
             <label for=\"view-decoded\">Decoded</label>\
             <input type=\"radio\" name=\"request-view\" id=\"view-original\">\
             <label for=\"view-original\">Original JWT</label></div></div>\
             <div id=\"request-decoded\"><p class=\"muted\">Header</p>\
             <pre id=\"request-header\">{}</pre><p class=\"muted\">Payload</p>\
             <pre id=\"request-payload\">{}</pre></div>\
             <div id=\"request-original\"><p class=\"muted\">As received</p>\
             <pre id=\"request-encoded\">{}</pre></div></section>",
            html_escape(&header),
            html_escape(&payload),
            html_escape(&interaction.pushed.request_object),
        );

        // --- Response ---
        let _ = write!(
            body,
            "<section class=\"panel response\" aria-label=\"Response\"><h2>2 · Response</h2>{}",
            interaction.form_open()
        );
        body.push_str(
            "<div class=\"row\"><label for=\"customer\">Customer</label>\
             <span class=\"pill\" id=\"remembered\"",
        );
        if remembered.as_ref().map(|user| user.subject.as_str()) != selected_subject
            || remembered.is_none()
        {
            body.push_str(" hidden");
        }
        body.push_str(
            ">Used on your last flow</span></div><select id=\"customer\" name=\"customer\">",
        );
        for user in &users {
            let _ = write!(
                body,
                "<option value=\"{}\"{}>{} ({})</option>",
                html_escape(&user.subject),
                if selected_subject == Some(user.subject.as_str()) {
                    " selected"
                } else {
                    ""
                },
                html_escape(&user.display_name()),
                html_escape(&user.username),
            );
        }
        body.push_str("</select><details><summary class=\"muted\">Customer attributes</summary>");
        for user in &users {
            let _ = write!(
                body,
                "<div class=\"attributes\" data-customer=\"{}\"><p class=\"muted\">{} ({})</p>\
                 <pre>{}</pre></div>",
                html_escape(&user.subject),
                html_escape(&user.display_name()),
                html_escape(&user.username),
                html_escape(&pretty(&attributes(user))),
            );
        }
        body.push_str("</details>");

        let checked = |on: bool| if on { " checked" } else { "" };
        let _ = write!(
            body,
            "<span class=\"label\" id=\"outcome-label\">Outcome</span>\
             <div class=\"outcomes\" role=\"radiogroup\" aria-labelledby=\"outcome-label\">\
             <input type=\"radio\" name=\"outcome\" id=\"outcome-success\" \
             value=\"{OUTCOME_SUCCESS}\"{}>\
             <label for=\"outcome-success\">Success<span>Authorization code and ID token</span></label>\
             <input type=\"radio\" name=\"outcome\" id=\"outcome-error\" value=\"{OUTCOME_ERROR}\"{}>\
             <label for=\"outcome-error\">Error<span>No code or ID token is issued</span></label></div>",
            checked(!view.error_outcome),
            checked(view.error_outcome),
        );

        // Success: the claims editor.
        let rows = claims_text.lines().count().clamp(14, 34) + 1;
        let _ = write!(
            body,
            "<div id=\"panel-success\">\
             <input type=\"hidden\" name=\"txn\" value=\"{txn}\">\
             <input type=\"hidden\" id=\"base\" name=\"base\" value=\"{base}\">\
             <input type=\"hidden\" id=\"base_customer\" name=\"base_customer\" value=\"{base_customer}\">\
             <div class=\"row\"><label for=\"id_token\">ID token claims, before signing</label>\
             <span class=\"row\"><span class=\"pill edited\" id=\"edited\" hidden>Edited</span>\
             <span id=\"json-status\" role=\"status\"></span>\
             <button type=\"button\" id=\"reset\" hidden>Reset</button></span></div>\
             <p class=\"notice\" id=\"script-notice\" hidden>Your edits were replaced with this \
             customer's generated claims.</p>\
             <textarea id=\"id_token\" name=\"id_token\" rows=\"{rows}\" spellcheck=\"false\">{text}</textarea>\
             <p class=\"muted\">Change, add or remove any claim. Claims you leave alone get their \
             real values when the token is issued: <code>iat</code>, <code>exp</code> and \
             <code>auth_time</code> are set then, and <code>at_hash</code> is computed from the \
             access token.</p></div>",
            txn = html_escape(&txn),
            base = html_escape(&base),
            base_customer = html_escape(selected_subject.unwrap_or_default()),
            text = html_escape(claims_text),
        );

        // Error: a predefined condition and its description.
        body.push_str(
            "<div id=\"panel-error\"><label for=\"error\">Error condition</label>\
             <select id=\"error\" name=\"error\">",
        );
        for condition in ERROR_CONDITIONS {
            let code = condition.code.as_str();
            let _ = write!(
                body,
                "<option value=\"{code}\"{}>{code} · {}</option>",
                if condition.code == error_code.code {
                    " selected"
                } else {
                    ""
                },
                html_escape(condition.label),
            );
        }
        let _ = write!(
            body,
            "</select><label for=\"error_description\">error_description</label>\
             <input type=\"text\" id=\"error_description\" name=\"error_description\" \
             value=\"{}\" maxlength=\"500\"></div>",
            html_escape(error_description),
        );

        // What goes back to the client, and the button that sends it.
        let _ = write!(
            body,
            "<div class=\"send\"><span class=\"label\">Authorization response</span>\
             <pre id=\"redirect-preview\">{}\n  &amp;iss={}</pre>\
             <button id=\"send\" type=\"submit\" name=\"action\" value=\"send\">Send response</button>\
             </div></form></section></div>",
            html_escape(&request.redirect_uri),
            html_escape(&interaction.state.issuer),
        );

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
        let _ = write!(
            body,
            "<script type=\"application/json\" id=\"oxid-data\">{}</script>",
            data.to_string().replace('<', "\\u003c")
        );

        Page {
            title: "Authorization request".to_owned(),
            body,
            style: STYLE,
            script: Some(SCRIPT),
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
fn everything_requested(interaction: &Interaction<'_>) -> std::collections::BTreeSet<String> {
    let request = interaction.request();
    request
        .claims
        .consentable(interaction.client, &request.scope)
        .into_iter()
        .map(|item| item.name)
        .collect()
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
