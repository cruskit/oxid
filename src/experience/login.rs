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
use std::fmt::Write as _;
use std::sync::Arc;

use serde_json::{Map, Value};

use super::{
    Approval, Decision, Experience, Form, Interaction, Kind, Page, Step, StepFuture, duration_text,
    host_cookie,
};
use crate::claims::{self, ConsentItem};
use crate::error::ErrorCode;
use crate::user::{User, UserStore};
use crate::util::{html_escape, random_token};

/// Prefix of the consent form's per-claim checkboxes: `share_<claim>`.
const SHARE_FIELD_PREFIX: &str = "share_";

/// Holds the secret that ties a signed-in session to this browser.
pub const LOGIN_COOKIE: &str = "__Host-oxid-login";

const ACTION_SIGN_IN: &str = "sign-in";
const ACTION_APPROVE: &str = "approve";
const ACTION_DENY: &str = "deny";
/// Shows the consent page again with every voluntary claim turned on.
const ACTION_SHARE_ALL: &str = "share-all";

const STYLE: &str = ".who{display:flex;align-items:center;gap:.5rem;font-size:.85rem;color:#5d6577;\
margin:0 0 1.25rem}.who::before{content:'';width:.5rem;height:.5rem;border-radius:50%;\
background:#0a7d55}.who strong{color:#0e1320}\
.ask{background:#fff7f2;border:1px solid #ffd9c7;border-radius:.9rem;padding:.9rem 1rem;\
margin:.75rem 0 1rem}.card .ask p{margin:0;color:#5d6577;font-size:.9rem}\
.card .ask strong{color:#0e1320}.card .ask .purpose{margin-top:.3rem;color:#0e1320;\
font-size:1.1rem;font-weight:600;line-height:1.35}\
.head{display:flex;align-items:baseline;justify-content:space-between}\
.card .link{display:inline;width:auto;min-height:0;margin:0;padding:.2rem .4rem;border-radius:.4rem;\
background:none;color:#b3400f;font-size:.8rem;font-weight:600}\
.hint{font-size:.85rem;color:#5d6577;margin:0 0 .5rem}\
ul.claims{list-style:none;padding:0;margin:0;border:1px solid #e6e8ee;border-radius:.9rem}\
ul.claims li+li{border-top:1px solid #e6e8ee}\
ul.claims .row{display:flex;align-items:center;justify-content:space-between;gap:1rem;\
padding:.85rem 1rem;margin:0}ul.claims label.row{cursor:pointer}\
.what{min-width:0}.what .name{display:block;font-size:.8rem;color:#5d6577}\
.what .value{display:block;font-weight:600;word-break:break-word;line-height:1.4;margin-top:.1rem}\
.what .value span{display:block}.what .value em{font-style:normal;font-weight:400;color:#5d6577}\
.what .none{font-weight:400;color:#7b8394}\
.tag{flex:none;font-size:.7rem;font-weight:600;letter-spacing:.03em;border-radius:999px;\
padding:.25rem .6rem;background:#eef0f4;color:#3c4354}\
.card .switch{appearance:none;-webkit-appearance:none;flex:none;width:2.75rem;height:1.6rem;\
padding:0;margin:0;border:0;border-radius:999px;background:#cfd3dc;position:relative;\
cursor:pointer;transition:background .15s}\
.card .switch::after{content:'';position:absolute;top:.2rem;left:.2rem;width:1.2rem;height:1.2rem;\
border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:transform .15s}\
.card .switch:checked{background:#0a7d55}\
.card .switch:checked::after{transform:translateX(1.15rem)}";

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

/// The client as a small card: an initial, its name and a line about it.
fn client_card(name: &str, line: &str) -> String {
    let initial: String = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default();
    format!(
        "<div class=\"rp\"><div class=\"avatar\" aria-hidden=\"true\">{}</div>\
         <div><strong id=\"client-name\">{}</strong><span>{}</span></div></div>",
        html_escape(&initial),
        html_escape(name),
        html_escape(line),
    )
}

/// The first page. It names the client and says only that it wants
/// information shared; what and why is for the signed-in user to see.
fn login_page(interaction: &Interaction<'_>, error: Option<&str>) -> Page {
    let name = &interaction.client.name;
    // The user is not logging in to the client: they are logging in to see
    // what it has asked for. The lead introduces the card that says who.
    let mut body = String::from(
        "<h1>Log in to oxID</h1>\
         <p class=\"lead\" id=\"login-reason\">Log in to review this request:</p>",
    );
    body.push_str(&client_card(
        name,
        "is asking you to share some of your information.",
    ));
    if let Some(error) = error {
        let _ = write!(
            body,
            "<p id=\"error\" class=\"alert\" role=\"alert\">{}</p>",
            html_escape(error)
        );
    }
    body.push_str(&interaction.form_open());
    let _ = write!(
        body,
        "<label class=\"field\" for=\"username\">Username</label>\
         <input id=\"username\" name=\"username\" type=\"text\" autocomplete=\"username\" \
         autocapitalize=\"none\" spellcheck=\"false\" autofocus>\
         <label class=\"field\" for=\"password\">Password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" \
         autocomplete=\"current-password\">\
         <button id=\"sign-in\" class=\"primary\" type=\"submit\" name=\"action\" \
         value=\"{ACTION_SIGN_IN}\">Log in</button>\
         <button id=\"deny\" class=\"ghost\" type=\"submit\" name=\"action\" \
         value=\"{ACTION_DENY}\" formnovalidate>Cancel and return to {}</button></form>\
         <p class=\"fine\">You'll choose what to share after you log in.</p>",
        html_escape(name)
    );

    Page {
        title: "Log in".to_owned(),
        body,
        style: STYLE,
        script: None,
        wide: false,
    }
}

/// The second page: who is asking, why, and exactly what would be shared.
/// Voluntary claims are off unless the user asked for them all (`all_on`).
fn consent_page(interaction: &Interaction<'_>, user: &User, all_on: bool) -> Page {
    let client = interaction.client;
    let request = interaction.request();
    let name = html_escape(&client.name);

    let mut body = format!(
        "<p class=\"who\" id=\"signed-in\">Logged in as <strong>{}</strong></p>",
        html_escape(&user.display_name())
    );

    // Only what can actually be released is listed. `txn` is technical and
    // is not shown (ConnectID identity assurance §5.3.2).
    let requested = request.claims.consentable(client, &request.scope);
    let values =
        request
            .claims
            .shareable_values(user, client, &request.scope, interaction.state.now());
    let (required, optional): (Vec<&ConsentItem>, Vec<&ConsentItem>) =
        requested.iter().partition(|item| item.essential);

    // The purpose is written by the client to complete the sentence "... is
    // asking you to share your information for the purpose of ..."
    // (ConnectID identity assurance §5.1), so that is how it is shown: the
    // sentence, with the purpose set apart as the part to read.
    let asking = if requested.is_empty() {
        "is asking you to log in with oxID"
    } else {
        "is asking you to share your information"
    };
    body.push_str("<h1>Review this request</h1><div class=\"ask\">");
    match &request.purpose {
        Some(purpose) => {
            let _ = write!(
                body,
                "<p><strong id=\"client-name\">{name}</strong> {asking} \
                 for the purpose of</p><p id=\"purpose\" class=\"purpose\">{}</p>",
                html_escape(purpose)
            );
        }
        None => {
            let _ = write!(
                body,
                "<p><strong id=\"client-name\">{name}</strong> {asking}.</p>"
            );
        }
    }
    body.push_str("</div>");
    if requested.is_empty() {
        let _ = write!(
            body,
            "<p id=\"requested-none\" class=\"lead\">{name} will be told that you logged in \
             with oxID. No personal details will be shared.</p>"
        );
    } else {
        body.push_str("<p class=\"lead\">Check what will be shared before you continue.</p>");
    }

    body.push_str(&interaction.form_open());
    if !requested.is_empty() {
        body.push_str("<div id=\"requested\">");
        if !required.is_empty() {
            let _ = write!(
                body,
                "<h2>Required by {name}</h2>\
                 <p id=\"required-hint\" class=\"hint\">{name} needs these to continue. \
                 If you'd rather not share them, cancel.</p><ul class=\"claims\">"
            );
            for item in required {
                claim_row(&mut body, item, values.get(&item.name), false);
            }
            body.push_str("</ul>");
        }
        if !optional.is_empty() {
            body.push_str("<div class=\"head\"><h2>Optional</h2>");
            if optional.iter().any(|item| values.contains_key(&item.name)) {
                let _ = write!(
                    body,
                    "<button id=\"share-all\" class=\"link\" type=\"submit\" name=\"action\" \
                     value=\"{ACTION_SHARE_ALL}\">Turn all on</button>"
                );
            }
            body.push_str(
                "</div><p id=\"optional-hint\" class=\"hint\">\
                 Your choice. Turn on anything you're happy to share.</p><ul class=\"claims\">",
            );
            for item in optional {
                claim_row(&mut body, item, values.get(&item.name), all_on);
            }
            body.push_str("</ul>");
        }
        body.push_str("</div>");
    }

    let allow = if requested.is_empty() {
        "Continue"
    } else {
        "Share and continue"
    };
    let _ = write!(
        body,
        "<button id=\"approve\" class=\"primary\" type=\"submit\" name=\"action\" \
         value=\"{ACTION_APPROVE}\">{allow}</button>\
         <button id=\"deny\" class=\"ghost\" type=\"submit\" name=\"action\" \
         value=\"{ACTION_DENY}\" formnovalidate>Cancel</button></form>\
         <p class=\"fine\">You'll be taken back to {name}. For your security, this request \
         expires {limit} after you arrived.</p>",
        limit = duration_text(interaction.state.security.session_ttl),
    );

    Page {
        title: format!("Share with {}", client.name),
        body,
        style: STYLE,
        script: None,
        wide: false,
    }
}

/// One claim on the consent page: what it is and the value to be shared.
/// A voluntary claim has a switch, off until the user turns it on. An
/// essential one has none: it can only be refused by cancelling.
fn claim_row(body: &mut String, item: &ConsentItem, value: Option<&Value>, on: bool) {
    let name = html_escape(&item.name);
    let what = format!(
        "<span class=\"what\"><span class=\"name\">{}</span>{}</span>",
        html_escape(&item.label),
        match value {
            Some(value) => format!(
                "<span class=\"value\" id=\"value-{name}\">{}</span>",
                value_html(&item.name, value)
            ),
            // Nothing is released for a claim the user does not have.
            None => format!(
                "<span class=\"value none\" id=\"value-{name}\">\
                 Not on file, so it won't be shared</span>"
            ),
        }
    );
    let _ = if item.essential {
        write!(
            body,
            "<li data-claim=\"{name}\" data-essential=\"true\"><div class=\"row\">{what}\
             <span class=\"tag\">Required</span></div></li>"
        )
    } else if value.is_none() {
        write!(
            body,
            "<li data-claim=\"{name}\"><div class=\"row\">{what}</div></li>"
        )
    } else {
        write!(
            body,
            "<li data-claim=\"{name}\"><label class=\"row\" for=\"share-{name}\">{what}\
             <input type=\"checkbox\" class=\"switch\" id=\"share-{name}\" \
             name=\"{SHARE_FIELD_PREFIX}{name}\" value=\"1\"{checked}></label></li>",
            checked = if on { " checked" } else { "" }
        )
    };
}

/// A claim value as the user should read it, HTML-escaped. The value shown
/// is the value shared; only its presentation differs from the JSON.
fn value_html(name: &str, value: &Value) -> String {
    match value {
        Value::Object(members) if name == "address" => {
            html_escape(&claims::one_line_address(value).unwrap_or_else(|| members_text(members)))
        }
        Value::Object(members) => {
            let mut lines = String::new();
            for (key, member) in members {
                let _ = write!(
                    lines,
                    "<span><em>{}:</em> {}</span>",
                    html_escape(&member_label(key)),
                    html_escape(&scalar_text(member))
                );
            }
            lines
        }
        other => html_escape(&scalar_text(other)),
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

    #[test]
    fn values_are_shown_as_text_and_escaped() {
        assert_eq!(value_html("given_name", &json!("A<b>")), "A&lt;b&gt;");
        assert_eq!(value_html("over18", &json!(true)), "Yes");
        assert_eq!(value_html("over65", &json!(false)), "No");
        assert_eq!(
            value_html(
                "address",
                &json!({"street_address": "1 Main St", "locality": "Sydney",
                        "region": "NSW", "postal_code": "2000"})
            ),
            "1 Main St, Sydney, NSW 2000"
        );
        assert_eq!(
            value_html(
                "beneficiary_account_au",
                &json!({"account_bsb": "123-456", "some_thing": "<x>"})
            ),
            "<span><em>BSB:</em> 123-456</span><span><em>Some thing:</em> &lt;x&gt;</span>"
        );
    }
}
