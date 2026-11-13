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
//! Failures are reported in one of two ways. When the request cannot be tied
//! to a registered redirect URI the user sees an error page and is *not*
//! redirected (the provider must not be an open redirector, §5.3.2.1-7).
//! Otherwise the error goes back to the client's redirect URI.

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use url::Url;
use uuid::Uuid;

use super::{Params, no_store};
use crate::client::Client;
use crate::error::ErrorCode;
use crate::experience::{Approval, Decision, Interaction, Page, Step, cookie};
use crate::state::AppState;
use crate::store::{
    AuthorizationCode, ConsentOutcome, ConsentRecord, Grant, PushedRequest, StoreError, StoreResult,
};
use crate::util::{ct_eq, html_escape, random_token};

/// Double-submit CSRF cookie. The `__Host-` prefix pins it to this origin,
/// `Secure` and path `/` (RFC 6265bis §4.1.3.2).
const CSRF_COOKIE: &str = "__Host-oxid-csrf";

/// Content security policy for every page, before `form-action` and
/// `script-src` are added by [`content_security_policy`].
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     frame-ancestors 'none'; base-uri 'none'";

/// The policy for one page.
///
/// Forms post to this origin only. But the final post of an interaction is
/// answered with a redirect to the client's redirect URI, and browsers apply
/// `form-action` to that redirect as well (CSP3 §6.3.1; Chromium enforces
/// it). A page of an interaction therefore also names the origin of the
/// redirect URI of the request being decided, `redirect_to`, or the browser
/// blocks the authorization response. That URI is an exact match for one
/// the client registered, checked when the request was pushed.
fn content_security_policy(redirect_to: Option<&str>, nonce: Option<&str>) -> HeaderValue {
    let mut policy = format!("{CONTENT_SECURITY_POLICY}; form-action 'self'");
    let origin = redirect_to
        .and_then(|uri| Url::parse(uri).ok())
        .map(|uri| uri.origin())
        .filter(url::Origin::is_tuple)
        .map(|origin| origin.ascii_serialization());
    if let Some(origin) = origin {
        policy.push(' ');
        policy.push_str(&origin);
    }
    if let Some(nonce) = nonce {
        policy.push_str("; script-src 'nonce-");
        policy.push_str(nonce);
        policy.push('\'');
    }
    HeaderValue::from_str(&policy).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
    })
}

/// Styles shared by every experience; a page may add its own.
const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;\
padding:0 1rem;color:#1a1a1a}h1{font-size:1.4rem}label{display:block;margin:.8rem 0 .2rem}\
input{width:100%;padding:.5rem;box-sizing:border-box}\
input[type=checkbox]{width:auto;margin-right:.5rem}button{padding:.6rem 1.2rem;margin:1rem .5rem 0 0}\
.error{color:#b00020}.box{background:#f4f4f4;padding:.8rem;border-radius:.3rem}";

fn page(
    status: StatusCode,
    title: &str,
    body: &str,
    style: &str,
    script: Option<&str>,
    redirect_to: Option<&str>,
) -> Response {
    // A page's own script runs under a nonce; nothing else can. The nonce is
    // unguessable, so markup injected into the page could not carry it.
    let nonce = random_token(16);
    let (script_tag, policy) = match script {
        Some(script) => (
            format!("<script nonce=\"{nonce}\">{script}</script>"),
            content_security_policy(redirect_to, Some(&nonce)),
        ),
        None => (String::new(), content_security_policy(redirect_to, None)),
    };
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} - oxID</title><style>{STYLE}{style}</style></head>\
         <body>{body}{script_tag}</body></html>",
        title = html_escape(title),
    );
    let mut response = no_store((status, Html(html)).into_response());
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, policy);
    response
}

/// An error shown to the user because it is not safe to redirect.
/// The page shown when the store cannot be reached. The detail is logged,
/// never shown.
fn store_unavailable(error: &StoreError) -> Response {
    tracing::error!(%error, "authorization endpoint could not use the store");
    error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "The server could not complete the request. Please try again from the application.",
    )
}

fn error_page(status: StatusCode, message: &str) -> Response {
    tracing::info!(message, "authorization request rejected with an error page");
    page(
        status,
        "Request error",
        &format!(
            "<h1 id=\"error-title\">This sign-in request cannot be completed</h1>\
             <p id=\"error-message\" class=\"error\">{}</p>\
             <p>Please return to the application and try again.</p>",
            html_escape(message)
        ),
        "",
        None,
        None,
    )
}

/// Redirect the browser back to the client with `params` plus the `iss`
/// parameter (RFC 9207). 303 is used so the POST is never replayed
/// (FAPI 2.0 §5.3.2.2-10/11).
fn redirect_to_client(state: &AppState, redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let Ok(mut url) = Url::parse(redirect_uri) else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The redirect URI is invalid.",
        );
    };
    url.query_pairs_mut()
        .extend_pairs(params)
        .append_pair("iss", &state.issuer);
    let Ok(location) = HeaderValue::from_str(url.as_str()) else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The redirect URI is invalid.",
        );
    };
    let mut response = no_store(StatusCode::SEE_OTHER.into_response());
    response.headers_mut().insert(header::LOCATION, location);
    response
}

fn redirect_error(
    state: &AppState,
    redirect_uri: &str,
    client_state: Option<&str>,
    code: ErrorCode,
    description: &str,
) -> Response {
    let mut params = vec![("error", code.as_str()), ("error_description", description)];
    if let Some(client_state) = client_state {
        params.push(("state", client_state));
    }
    redirect_to_client(state, redirect_uri, &params)
}

fn is_csrf_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn add_cookies(response: &mut Response, cookies: &[String]) {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// Render an experience's page, setting the CSRF cookie its form relies on.
/// `redirect_uri` is where the interaction will end; see
/// [`content_security_policy`].
fn experience_page(
    experience_page: &Page,
    csrf: &str,
    cookies: &[String],
    redirect_uri: &str,
) -> Response {
    let mut response = page(
        StatusCode::OK,
        &experience_page.title,
        &experience_page.body,
        experience_page.style,
        experience_page.script,
        Some(redirect_uri),
    );
    let csrf_cookie = format!("{CSRF_COOKIE}={csrf}; Path=/; Secure; HttpOnly; SameSite=Strict");
    add_cookies(&mut response, &[csrf_cookie]);
    add_cookies(&mut response, cookies);
    response
}

/// The pushed request named by the browser's parameters, or the error page
/// explaining why there is none.
async fn load_request(
    state: &AppState,
    client_id: Option<&str>,
    request_uri: Option<&str>,
) -> Result<(std::sync::Arc<Client>, String, PushedRequest), Box<Response>> {
    let bad = |message: &str| Box::new(error_page(StatusCode::BAD_REQUEST, message));

    let client_id = client_id.ok_or_else(|| bad("The client_id parameter is missing."))?;
    let client = state
        .clients
        .get(client_id)
        .ok_or_else(|| bad("The client is not registered."))?;
    let request_uri = request_uri.ok_or_else(|| {
        bad("A pushed authorization request is required: the request_uri parameter is missing.")
    })?;
    let pushed = state
        .store
        .peek_request(request_uri, state.now())
        .await
        .map_err(|error| Box::new(store_unavailable(&error)))?
        .ok_or_else(|| bad("The request_uri is invalid, has expired, or has already been used."))?;
    // RFC 9126 §4: a request_uri is only usable by the client that pushed it.
    if pushed.request.client_id != client.id {
        return Err(bad("The request_uri was not issued to this client."));
    }
    Ok((client, request_uri.to_owned(), pushed))
}

/// `GET /authorize`
pub async fn authorize(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Ok(params) = Params::parse(query.unwrap_or_default().as_bytes()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "A request parameter was sent more than once.",
        );
    };

    // A request without PAR. If it names a redirect URI registered to the
    // client we can safely say so via redirect; otherwise show a page.
    if params.get("request_uri").is_none()
        && let Some(client) = params.get("client_id").and_then(|id| state.clients.get(id))
        && let Some(redirect_uri) = params.get("redirect_uri")
        && client.has_redirect_uri(redirect_uri)
    {
        return redirect_error(
            &state,
            redirect_uri,
            params.get("state"),
            ErrorCode::InvalidRequest,
            "authorization requests must be sent via the pushed authorization request endpoint",
        );
    }

    let (client, request_uri, pushed) =
        match load_request(&state, params.get("client_id"), params.get("request_uri")).await {
            Ok(found) => found,
            Err(response) => return *response,
        };

    let csrf = cookie(&headers, CSRF_COOKIE)
        .filter(|v| is_csrf_token(v))
        .map_or_else(|| random_token(32), str::to_owned);
    let interaction = Interaction {
        state: &state,
        client: &client,
        request_uri: &request_uri,
        pushed: &pushed,
        csrf: &csrf,
        headers: &headers,
    };
    let step = state.experience.start(&interaction).await;
    conclude(&interaction, step).await
}

/// `POST /authorize/decision`: a form submitted from an experience's page.
pub async fn decision(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(params) = Params::parse(&body) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "A form field was sent more than once.",
        );
    };

    // Double-submit check: the form value must match the cookie this origin
    // set, which a cross-site attacker can neither read nor set.
    let csrf_ok = match (cookie(&headers, CSRF_COOKIE), params.get("csrf")) {
        (Some(cookie), Some(form)) => is_csrf_token(cookie) && ct_eq(cookie, form),
        _ => false,
    };
    if !csrf_ok {
        return error_page(
            StatusCode::FORBIDDEN,
            "This form could not be verified. Please start again from the application.",
        );
    }
    let csrf = params.get("csrf").unwrap_or_default();

    let (client, request_uri, pushed) =
        match load_request(&state, params.get("client_id"), params.get("request_uri")).await {
            Ok(found) => found,
            Err(response) => return *response,
        };
    let interaction = Interaction {
        state: &state,
        client: &client,
        request_uri: &request_uri,
        pushed: &pushed,
        csrf,
        headers: &headers,
    };
    let step = state.experience.submit(&interaction, &params).await;
    conclude(&interaction, step).await
}

/// Turn an experience's step into the HTTP response, completing the
/// protocol side of a final decision.
async fn conclude(interaction: &Interaction<'_>, step: Step) -> Response {
    match try_conclude(interaction, step).await {
        Ok(response) => response,
        Err(error) => store_unavailable(&error),
    }
}

async fn try_conclude(interaction: &Interaction<'_>, step: Step) -> StoreResult<Response> {
    let state = interaction.state;
    let request = interaction.request();
    let now = state.now();
    let mut response = match step.decision {
        Decision::Page(page) => {
            return Ok(experience_page(
                &page,
                interaction.csrf,
                &step.set_cookies,
                &request.redirect_uri,
            ));
        }
        Decision::Deny { code, description } => {
            // The experience may already have discarded the request (after
            // too many failed sign-ins), so its absence is not an error.
            state
                .store
                .take_request(interaction.request_uri, now)
                .await?;
            record_decision(interaction, None, now, ConsentOutcome::Denied).await?;
            redirect_error(
                state,
                &request.redirect_uri,
                request.state.as_deref(),
                code,
                &description,
            )
        }
        Decision::Approve(approval) => {
            // One-time use is enforced here, at the point of authorization.
            let Some(pushed) = state
                .store
                .take_request(interaction.request_uri, now)
                .await?
            else {
                return Ok(error_page(
                    StatusCode::BAD_REQUEST,
                    "The request_uri is invalid, has expired, or has already been used.",
                ));
            };
            let request = pushed.request;
            let txn = record_decision(interaction, Some(&approval), now, ConsentOutcome::Approved)
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
            redirect_to_client(state, &request.redirect_uri, &out)
        }
    };
    add_cookies(&mut response, &step.set_cookies);
    Ok(response)
}

/// Record the outcome of a transaction, with the purpose the client gave
/// (OAuth 2 Purpose §5), and return the transaction's identifier.
async fn record_decision(
    interaction: &Interaction<'_>,
    approval: Option<&Approval>,
    now: i64,
    outcome: ConsentOutcome,
) -> StoreResult<String> {
    let state = interaction.state;
    let client = interaction.client;
    let purpose = interaction.request().purpose.as_deref();
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
pub(crate) mod test_support {
    use std::collections::HashMap;

    use axum::body::Body;
    use axum::http::{Request, Response, header};
    use url::Url;

    use super::CSRF_COOKIE;
    use crate::http::test_support::{Harness, body_text};
    use crate::http::{PATH_AUTHORIZE, PATH_DECISION};

    pub fn authorize_path(request_uri: &str) -> String {
        let query: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", "rp")
            .append_pair("request_uri", request_uri)
            .finish();
        format!("{PATH_AUTHORIZE}?{query}")
    }

    /// Load the login page and return the CSRF token it issued.
    pub async fn open_login(harness: &Harness, request_uri: &str) -> String {
        let response = harness.get(None, &authorize_path(request_uri)).await;
        assert_eq!(response.status(), 200, "{}", body_text(response).await);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        cookie
            .strip_prefix(&format!("{CSRF_COOKIE}="))
            .and_then(|rest| rest.split(';').next())
            .unwrap()
            .to_owned()
    }

    pub async fn submit(
        harness: &Harness,
        csrf_cookie: Option<&str>,
        fields: &[(&str, &str)],
    ) -> Response<Body> {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request = Request::post(PATH_DECISION)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(csrf) = csrf_cookie {
            request = request.header(header::COOKIE, format!("other=1; {CSRF_COOKIE}={csrf}"));
        }
        harness
            .send(None, request.body(Body::from(body)).unwrap())
            .await
    }

    /// Query parameters of a redirect response's `Location`.
    pub fn redirect_params(response: &Response<Body>) -> (String, HashMap<String, String>) {
        assert_eq!(response.status(), 303);
        let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        let params = location.query_pairs().into_owned().collect();
        let mut base = location;
        base.set_query(None);
        (base.to_string(), params)
    }

    /// Names of the ticked checkboxes on a consent page, as a browser would
    /// submit them.
    pub fn ticked(html: &str) -> Vec<String> {
        html.split("<input type=\"checkbox\"")
            .skip(1)
            .filter_map(|rest| {
                let tag = rest.split('>').next()?;
                let name = tag.split("name=\"").nth(1)?.split('"').next()?;
                tag.contains(" checked").then(|| name.to_owned())
            })
            .collect()
    }

    /// Run the browser leg for a pushed request, sharing everything offered,
    /// and return the code.
    pub async fn approve(harness: &Harness, request_uri: &str) -> String {
        approve_declining(harness, request_uri, &[]).await
    }

    /// As [`approve`], but unticking the checkboxes for `declined` claims.
    pub async fn approve_declining(
        harness: &Harness,
        request_uri: &str,
        declined: &[&str],
    ) -> String {
        let page = harness.get(None, &authorize_path(request_uri)).await;
        let html = body_text(page).await;
        let csrf = open_login(harness, request_uri).await;
        let ticked: Vec<String> = ticked(&html)
            .into_iter()
            .filter(|field| !declined.iter().any(|d| *field == format!("share_{d}")))
            .collect();
        let mut fields = vec![
            ("csrf", csrf.as_str()),
            ("client_id", "rp"),
            ("request_uri", request_uri),
            ("username", crate::user::DEMO_USERNAME),
            ("password", crate::user::DEMO_PASSWORD),
            ("action", "approve"),
        ];
        fields.extend(ticked.iter().map(|field| (field.as_str(), "1")));
        let response = submit(harness, Some(&csrf), &fields).await;
        redirect_params(&response)
            .1
            .remove("code")
            .expect("code in redirect")
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header};
    use serde_json::json;

    use super::test_support::{
        approve, approve_declining, authorize_path, open_login, redirect_params, submit, ticked,
    };
    use super::*;
    use crate::http::PATH_AUTHORIZE;
    use crate::http::test_support::{Harness, body_text};
    use crate::state::test_support::ISSUER;
    use crate::store::MAX_FAILED_LOGINS;
    use crate::user::{DEMO_PASSWORD, DEMO_USERNAME};

    fn login_fields<'a>(csrf: &'a str, uri: &'a str, password: &'a str) -> [(&'a str, &'a str); 6] {
        [
            ("csrf", csrf),
            ("client_id", "rp"),
            ("request_uri", uri),
            ("username", DEMO_USERNAME),
            ("password", password),
            ("action", "approve"),
        ]
    }

    #[tokio::test]
    async fn shows_login_page_with_client_purpose_and_requested_claims() {
        let harness = Harness::new();
        let uri = harness
            .push(&json!({
                "purpose": "Verify your <age> for checkout",
                "claims": {"id_token": {
                    "given_name": null,
                    "nickname": null,
                    "verified_claims": {
                        "verification": {"trust_framework": {"value": "au_connectid"}},
                        "claims": {"over18": null, "beneficiary_account_au": {"essential": true}},
                    },
                }},
            }))
            .await;
        let response = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            "no CORS on the authorization endpoint (FAPI 2.0 5.2.3)"
        );
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            cookie.contains("Secure")
                && cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Strict")
        );

        let html = body_text(response).await;
        assert!(html.contains("Test RP"));
        assert!(
            html.contains("Verify your &lt;age&gt; for checkout"),
            "purpose is shown, escaped"
        );
        assert!(html.contains("name=\"share_given_name\" value=\"1\" checked>Given name"));
        assert!(html.contains("data-claim=\"over18\""));
        assert!(
            html.contains("<li data-claim=\"beneficiary_account_au\" data-essential=\"true\">")
        );
        assert_eq!(ticked(&html), ["share_given_name", "share_over18"]);
        assert!(html.contains("Bank account (BSB and account number)"));
        assert!(
            !html.contains("nickname"),
            "unsupported claims are not offered"
        );
        assert!(html.contains("id=\"username\"") && html.contains("id=\"password\""));
    }

    #[tokio::test]
    async fn approval_redirects_with_code_state_and_iss() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        let response = submit(
            &harness,
            Some(&csrf),
            &login_fields(&csrf, &uri, DEMO_PASSWORD),
        )
        .await;
        let (base, params) = redirect_params(&response);
        assert_eq!(base, "https://rp.example.com/cb");
        assert_eq!(params["state"], "st-1");
        assert_eq!(params["iss"], ISSUER);
        assert!(params["code"].len() >= 43);
        assert!(!params.contains_key("error"));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn decisions_are_recorded_with_their_purpose() {
        let harness = Harness::new();
        let pushed = json!({
            "purpose": "Opening your savings account",
            "claims": {"id_token": {"family_name": null, "nickname": null}},
        });
        let uri = harness.push(&pushed).await;
        approve(&harness, &uri).await;

        let history = harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        let record = &history[0];
        assert_eq!(
            record.purpose.as_deref(),
            Some("Opening your savings account")
        );
        assert_eq!(record.client_id, "rp");
        assert_eq!(record.claims, ["family_name"]);
        assert_eq!(record.outcome, ConsentOutcome::Approved);
        assert_eq!(record.decided_at, harness.state.now());
        assert_eq!(record.txn.len(), 36);

        // A cancelled request is recorded too, against no user.
        let uri = harness.push(&pushed).await;
        let csrf = open_login(&harness, &uri).await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("client_id", "rp"),
            ("request_uri", &uri),
            ("action", "deny"),
        ];
        submit(&harness, Some(&csrf), &fields).await;
        assert_eq!(
            harness
                .state
                .store
                .consent_history("demo-user-0001")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn user_can_decline_voluntary_claims_but_not_essential_ones() {
        let harness = Harness::new();
        let pushed = json!({"claims": {"id_token": {
            "given_name": {"essential": true},
            "email": null,
            "phone_number": {"essential": false},
            "verified_claims": {
                "verification": {"trust_framework": {"value": "au_connectid"}},
                "claims": {"over18": {"essential": true}, "over21": null},
            },
        }}});
        let uri = harness.push(&pushed).await;
        let html = body_text(harness.get(None, &authorize_path(&uri)).await).await;
        // Essential claims have no checkbox at all.
        assert_eq!(
            ticked(&html),
            ["share_email", "share_over21", "share_phone_number"]
        );
        assert!(!html.contains("share_given_name") && !html.contains("share_over18"));
        assert!(html.contains("id=\"optional-hint\"") && html.contains("id=\"required-hint\""));

        approve_declining(&harness, &uri, &["email", "over21"]).await;
        let record = &harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap()[0];
        assert_eq!(record.claims, ["given_name", "over18", "phone_number"]);
        assert_eq!(record.declined, ["email", "over21"]);

        // Submitting nothing at all still shares the essential claims, and
        // fields for claims that were never offered are ignored.
        let uri = harness.push(&pushed).await;
        let csrf = open_login(&harness, &uri).await;
        let mut fields = login_fields(&csrf, &uri, DEMO_PASSWORD).to_vec();
        fields.push(("share_birthdate", "1"));
        fields.push(("share_name", "1"));
        submit(&harness, Some(&csrf), &fields).await;
        let record = &harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap()[0];
        assert_eq!(record.claims, ["given_name", "over18"]);
        assert_eq!(record.declined, ["email", "over21", "phone_number"]);
    }

    #[tokio::test]
    async fn declined_claims_stay_unticked_after_a_wrong_password() {
        let harness = Harness::new();
        let uri = harness
            .push(&json!({"claims": {"id_token": {"email": null, "given_name": null}}}))
            .await;
        let csrf = open_login(&harness, &uri).await;
        let mut fields = login_fields(&csrf, &uri, "wrong").to_vec();
        fields.push(("share_given_name", "1"));
        let html = body_text(submit(&harness, Some(&csrf), &fields).await).await;
        assert!(html.contains("username or password is incorrect"));
        assert_eq!(ticked(&html), ["share_given_name"]);
        assert!(
            html.contains("name=\"share_email\""),
            "still offered, unticked"
        );
    }

    #[tokio::test]
    async fn login_page_says_when_nothing_personal_is_shared() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let html = body_text(harness.get(None, &authorize_path(&uri)).await).await;
        assert!(html.contains("id=\"requested-none\""));
        assert!(!html.contains("id=\"purpose\""));
    }

    #[tokio::test]
    async fn state_is_omitted_from_the_response_when_not_requested() {
        let harness = Harness::new();
        let uri = harness.push(&json!({"state": null})).await;
        let csrf = open_login(&harness, &uri).await;
        let response = submit(
            &harness,
            Some(&csrf),
            &login_fields(&csrf, &uri, DEMO_PASSWORD),
        )
        .await;
        let (_, params) = redirect_params(&response);
        assert!(!params.contains_key("state"));
        assert!(params.contains_key("code"));
    }

    #[tokio::test]
    async fn request_uri_survives_page_reloads_but_is_single_use_once_decided() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        open_login(&harness, &uri).await;
        open_login(&harness, &uri).await;
        approve(&harness, &uri).await;

        let reused = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(reused).await.contains("already been used"));
    }

    #[tokio::test]
    async fn denial_redirects_with_access_denied_and_consumes_the_request() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("client_id", "rp"),
            ("request_uri", &uri),
            ("action", "deny"),
        ];
        let response = submit(&harness, Some(&csrf), &fields).await;
        let (_, params) = redirect_params(&response);
        assert_eq!(params["error"], "access_denied");
        assert_eq!(params["state"], "st-1");
        assert_eq!(params["iss"], ISSUER);
        assert!(!params.contains_key("code"));

        let again = submit(&harness, Some(&csrf), &fields).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wrong_password_re_prompts_then_gives_up() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        for _ in 1..MAX_FAILED_LOGINS {
            let response = submit(&harness, Some(&csrf), &login_fields(&csrf, &uri, "wrong")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                body_text(response)
                    .await
                    .contains("username or password is incorrect")
            );
        }
        let last = submit(&harness, Some(&csrf), &login_fields(&csrf, &uri, "wrong")).await;
        assert_eq!(redirect_params(&last).1["error"], "access_denied");
        // The request is gone, so even the right password no longer works.
        let after = submit(
            &harness,
            Some(&csrf),
            &login_fields(&csrf, &uri, DEMO_PASSWORD),
        )
        .await;
        assert_eq!(after.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn decision_requires_matching_csrf_cookie_and_field() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        let forged = random_token(32);

        let no_cookie = submit(&harness, None, &login_fields(&csrf, &uri, DEMO_PASSWORD)).await;
        assert_eq!(no_cookie.status(), StatusCode::FORBIDDEN);
        let mismatch = submit(
            &harness,
            Some(&csrf),
            &login_fields(&forged, &uri, DEMO_PASSWORD),
        )
        .await;
        assert_eq!(mismatch.status(), StatusCode::FORBIDDEN);
        // Nothing was consumed by the rejected attempts.
        approve(&harness, &uri).await;
    }

    #[tokio::test]
    async fn expired_request_uri_shows_an_error_page() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        harness
            .clock
            .advance(harness.state.security.request_uri_ttl);
        let response = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::LOCATION));
    }

    #[tokio::test]
    async fn request_uri_is_bound_to_the_client_that_pushed_it() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let query: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", "someone-else")
            .append_pair("request_uri", &uri)
            .finish();
        let response = harness
            .get(None, &format!("{PATH_AUTHORIZE}?{query}"))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::LOCATION));
    }

    #[tokio::test]
    async fn requests_without_par_are_rejected() {
        let harness = Harness::new();
        // Registered redirect URI: the error can be returned to the client.
        let registered = "/authorize?client_id=rp&response_type=code&scope=openid&state=abc\
                          &redirect_uri=https%3A%2F%2Frp.example.com%2Fcb";
        let response = harness.get(None, registered).await;
        let (base, params) = redirect_params(&response);
        assert_eq!(base, "https://rp.example.com/cb");
        assert_eq!(params["error"], "invalid_request");
        assert_eq!(params["state"], "abc");
        assert_eq!(params["iss"], ISSUER);

        // Unregistered redirect URI: never redirect (no open redirector).
        let unregistered = "/authorize?client_id=rp&response_type=code\
                            &redirect_uri=https%3A%2F%2Fevil.example.com%2Fcb";
        let response = harness.get(None, unregistered).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::LOCATION));

        for path in [
            "/authorize",
            "/authorize?client_id=rp",
            "/authorize?client_id=unknown&request_uri=x",
        ] {
            let response = harness.get(None, path).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn existing_csrf_cookie_is_reused_across_tabs() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let first = open_login(&harness, &uri).await;
        let request = axum::http::Request::get(authorize_path(&uri))
            .header(header::COOKIE, format!("{CSRF_COOKIE}={first}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = harness.send(None, request).await;
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains(&first)
        );
    }
}
