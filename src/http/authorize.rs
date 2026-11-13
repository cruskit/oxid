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
//! Two clocks apply. The `request_uri` lifetime limits how long the browser
//! may take to *arrive* (RFC 9126 §2.2). Arriving in time starts the user's
//! session, and from then on only the session (`security.session_ttl`)
//! limits how long they may take to sign in, read and decide. A user whose
//! session runs out is told so, and can go back to the client, which gets
//! `access_denied` by the usual error redirect.
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
use crate::experience::{
    Approval, Decision, Interaction, Page, Step, cookie, duration_text, form_open,
};
use crate::state::AppState;
use crate::store::{
    AuthorizationCode, ConsentOutcome, ConsentRecord, Grant, PushedRequest, StoreError,
    StoreResult, Visit,
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

/// Styles shared by every page. The first rules are a plain base that a wide
/// page (the technical experience) builds on. The `.card` rules are the
/// oxID look for pages meant for end users.
const STYLE: &str = "body{margin:0;padding:0 1rem 2.5rem;color:#0e1320;background:#f3f4f8;\
font-family:Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;\
-webkit-font-smoothing:antialiased}h1{font-size:1.4rem}label{display:block;margin:.8rem 0 .2rem}\
input{width:100%;padding:.5rem;box-sizing:border-box}\
input[type=checkbox]{width:auto;margin-right:.5rem}button{padding:.6rem 1.2rem;margin:1rem .5rem 0 0}\
.error{color:#b00020}.box{background:#f4f4f4;padding:.8rem;border-radius:.3rem}\
.brand{display:flex;align-items:center;justify-content:center;gap:.6rem;padding:2.25rem 0 1.5rem;\
font-size:1.35rem;font-weight:700;letter-spacing:-.03em}\
.brand i{width:1.9rem;height:1.9rem;border-radius:.6rem;display:grid;place-items:center;\
background:linear-gradient(135deg,#ff4d2e,#ff9a1f);box-shadow:0 4px 12px rgba(255,86,48,.35)}\
.brand i::after{content:'';width:.7rem;height:.7rem;border-radius:50%;border:.2rem solid #fff}\
.brand b{color:#ff5630}\
.card{max-width:27rem;margin:0 auto;background:#fff;border-radius:1.25rem;padding:2rem 1.75rem;\
box-sizing:border-box;box-shadow:0 1px 2px rgba(14,19,32,.06),0 16px 48px rgba(14,19,32,.09)}\
.card h1{font-size:1.5rem;line-height:1.25;letter-spacing:-.02em;margin:0 0 .5rem}\
.card h2{font-size:.75rem;letter-spacing:.07em;text-transform:uppercase;color:#5d6577;\
margin:1.5rem 0 .5rem}.card p{line-height:1.55;margin:.5rem 0}\
.card .lead{color:#5d6577;margin:0 0 1.25rem}.card .fine{color:#5d6577;font-size:.8rem;\
text-align:center;margin:1.25rem 0 0}\
.card .field{display:block;font-size:.85rem;font-weight:600;margin:1rem 0 .35rem}\
.card input[type=text],.card input[type=password]{width:100%;min-height:3rem;padding:0 .9rem;\
border:1.5px solid #d9dce4;border-radius:.75rem;font:inherit;color:inherit;background:#fff}\
.card input:focus-visible,.card button:focus-visible{outline:none;border-color:#0e1320;\
box-shadow:0 0 0 3px rgba(255,86,48,.3)}\
.card button{display:block;width:100%;min-height:3.1rem;margin:.6rem 0 0;padding:0 1rem;border:0;\
border-radius:999px;font:inherit;font-weight:600;cursor:pointer}\
.card .primary{background:#0e1320;color:#fff;margin-top:1.5rem}.card .primary:hover{background:#252c40}\
.card .ghost{background:none;color:#0e1320}.card .ghost:hover{background:#f3f4f8}\
.card .alert{background:#fdecea;color:#a1241a;border-radius:.75rem;padding:.75rem .9rem;\
font-size:.9rem;margin:0 0 1rem}\
.rp{display:flex;gap:.8rem;align-items:center;background:#f6f7fa;border-radius:.9rem;\
padding:.9rem 1rem;margin:0 0 1.25rem}.rp .avatar{flex:none;width:2.6rem;height:2.6rem;\
border-radius:.8rem;background:#0e1320;color:#fff;display:grid;place-items:center;font-weight:700;\
font-size:1.1rem}.rp strong{display:block}.rp span{font-size:.85rem;color:#5d6577;line-height:1.4}\
.badge{width:3.25rem;height:3.25rem;border-radius:50%;display:grid;place-items:center;\
background:#fff1e8;color:#d9480f;font-size:1.6rem;font-weight:700;margin:0 0 1.25rem}\
.legal{max-width:27rem;margin:1.25rem auto 0;text-align:center;font-size:.75rem;color:#7b8394;\
line-height:1.5}";

/// One HTML page.
struct Shell<'a> {
    status: StatusCode,
    title: &'a str,
    body: &'a str,
    /// Extra CSS, after the shared styles.
    style: &'a str,
    script: Option<&'a str>,
    /// Where a form on the page may end up redirecting to; see
    /// [`content_security_policy`].
    redirect_to: Option<&'a str>,
    /// Replace the page with `url` after this many seconds.
    refresh: Option<(i64, String)>,
    wide: bool,
}

impl Shell<'_> {
    fn render(&self) -> Response {
        // A page's own script runs under a nonce; nothing else can. The nonce
        // is unguessable, so markup injected into the page could not carry it.
        let nonce = random_token(16);
        // The reload is a script timer, not a `<meta>` refresh: scripted
        // browsers, such as the conformance suite's, follow those at once.
        let reload = self.refresh.as_ref().map(|(after, url)| {
            let url = serde_json::Value::from(url.as_str())
                .to_string()
                .replace('<', "\\u003c");
            format!("setTimeout(function(){{location.replace({url})}},{after}000);")
        });
        let mut scripts = String::new();
        for script in [self.script, reload.as_deref()].into_iter().flatten() {
            scripts.push_str("<script nonce=\"");
            scripts.push_str(&nonce);
            scripts.push_str("\">");
            scripts.push_str(script);
            scripts.push_str("</script>");
        }
        let policy = content_security_policy(
            self.redirect_to,
            (!scripts.is_empty()).then_some(nonce.as_str()),
        );
        let html = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{title} - oxID</title><style>{STYLE}{style}</style></head>\
             <body><header class=\"brand\"><i></i><span>ox<b>ID</b></span></header>\
             <main class=\"{class}\">{body}</main>{footer}{scripts}</body></html>",
            title = html_escape(self.title),
            style = self.style,
            class = if self.wide { "wide" } else { "card" },
            body = self.body,
            footer = if self.wide {
                ""
            } else {
                "<footer class=\"legal\">Protected by oxID. We never share your details \
                 without your say-so.</footer>"
            },
        );
        let mut response = no_store((self.status, Html(html)).into_response());
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy);
        response
    }
}

/// The page shown when the store cannot be reached. The detail is logged,
/// never shown.
fn store_unavailable(error: &StoreError) -> Response {
    tracing::error!(%error, "authorization endpoint could not use the store");
    error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "The server could not complete the request. Please try again from the application.",
    )
}

/// An error shown to the user because it is not safe to redirect.
fn error_page(status: StatusCode, message: &str) -> Response {
    tracing::info!(message, "authorization request rejected with an error page");
    Shell {
        status,
        title: "Request error",
        body: &format!(
            "<div class=\"badge\">!</div>\
             <h1 id=\"error-title\">We couldn't complete this request</h1>\
             <p id=\"error-message\" class=\"alert\">{}</p>\
             <p class=\"lead\">Please return to the application and try again.</p>",
            html_escape(message)
        ),
        style: "",
        script: None,
        redirect_to: None,
        refresh: None,
        wide: false,
    }
    .render()
}

/// The `action` of the button on the session expiry page.
const ACTION_RETURN_EXPIRED: &str = "session-expired-return";

/// The `error_description` sent to the client when a user goes back to it
/// from the session expiry page.
const SESSION_TIMEOUT_DESCRIPTION: &str =
    "session timeout: the user did not complete the request in time";

/// Tell the user their session ran out, and offer the way back to the
/// client. The button posts to the decision endpoint, which answers with the
/// usual error redirect ([`return_expired`]).
fn session_expired_page(
    state: &AppState,
    client: &Client,
    request_uri: &str,
    pushed: &PushedRequest,
    csrf: &str,
) -> Response {
    let name = html_escape(&client.name);
    let body = format!(
        "<div class=\"badge\">!</div>\
         <h1 id=\"session-expired\">Your session has expired</h1>\
         <p class=\"lead\">To keep your details safe, we ended this request because it \
         wasn't completed within {limit}. Nothing has been shared with \
         <strong>{name}</strong>.</p>{form}\
         <button id=\"return\" class=\"primary\" type=\"submit\" name=\"action\" \
         value=\"{ACTION_RETURN_EXPIRED}\">Return to {name}</button></form>\
         <p class=\"fine\">You can start again from {name} at any time.</p>",
        limit = duration_text(state.security.session_ttl),
        form = form_open(csrf, &client.id, request_uri),
    );
    let mut response = Shell {
        status: StatusCode::BAD_REQUEST,
        title: "Session expired",
        body: &body,
        style: "",
        script: None,
        redirect_to: Some(&pushed.request.redirect_uri),
        refresh: None,
        wide: false,
    }
    .render();
    add_cookies(&mut response, &[csrf_cookie(csrf)]);
    response
}

/// Send a user whose session expired back to the client: `access_denied`,
/// by the same redirect as any other refusal. The request is consumed.
async fn return_expired(
    state: &AppState,
    client: &Client,
    request_uri: &str,
) -> StoreResult<Response> {
    let now = state.now();
    let Some(pushed) = state.store.take_request(request_uri, now).await? else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "The request_uri is invalid, has expired, or has already been used.",
        ));
    };
    let request = pushed.request;
    tracing::info!(client_id = %client.id, "session expired; returning the user to the client");
    record_decision(
        state,
        client,
        request.purpose.as_deref(),
        None,
        now,
        ConsentOutcome::Denied,
    )
    .await?;
    Ok(redirect_error(
        state,
        &request.redirect_uri,
        request.state.as_deref(),
        ErrorCode::AccessDenied,
        SESSION_TIMEOUT_DESCRIPTION,
    ))
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

fn csrf_cookie(csrf: &str) -> String {
    format!("{CSRF_COOKIE}={csrf}; Path=/; Secure; HttpOnly; SameSite=Strict")
}

fn add_cookies(response: &mut Response, cookies: &[String]) {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// The authorization endpoint URL for a request, as the client sent the
/// browser to it.
fn authorize_path(client_id: &str, request_uri: &str) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("request_uri", request_uri)
        .finish();
    format!("{}?{query}", super::PATH_AUTHORIZE)
}

/// Render an experience's page, setting the CSRF cookie its form relies on.
///
/// The page reloads itself when the session ends, which replaces it with the
/// session expiry page: the user is told, rather than finding out when they
/// submit the form.
fn experience_page(page: &Page, interaction: &Interaction<'_>, cookies: &[String]) -> Response {
    let remaining = interaction.session.expires_at - interaction.state.now();
    let mut response = Shell {
        status: StatusCode::OK,
        title: &page.title,
        body: &page.body,
        style: page.style,
        script: page.script,
        redirect_to: Some(&interaction.request().redirect_uri),
        refresh: Some((
            remaining.max(1),
            authorize_path(&interaction.client.id, interaction.request_uri),
        )),
        wide: page.wide,
    }
    .render();
    add_cookies(&mut response, &[csrf_cookie(interaction.csrf)]);
    add_cookies(&mut response, cookies);
    response
}

/// The pushed request named by the browser's parameters, or the error page
/// explaining why there is none. `arriving` is whether the browser is
/// loading the authorization endpoint, which may start the user's session,
/// as opposed to submitting a form from within one.
async fn load_request(
    state: &AppState,
    client_id: Option<&str>,
    request_uri: Option<&str>,
    arriving: bool,
) -> Result<(std::sync::Arc<Client>, String, Visit), Box<Response>> {
    let bad = |message: &str| Box::new(error_page(StatusCode::BAD_REQUEST, message));

    let client_id = client_id.ok_or_else(|| bad("The client_id parameter is missing."))?;
    let client = state
        .clients
        .get(client_id)
        .ok_or_else(|| bad("The client is not registered."))?;
    let request_uri = request_uri.ok_or_else(|| {
        bad("A pushed authorization request is required: the request_uri parameter is missing.")
    })?;
    let now = state.now();
    let visit = if arriving {
        state.store.arrive(request_uri, now).await
    } else {
        state.store.resume(request_uri, now).await
    }
    .map_err(|error| Box::new(store_unavailable(&error)))?
    .ok_or_else(|| bad("The request_uri is invalid, has expired, or has already been used."))?;
    let (Visit::Active(pushed, _) | Visit::Expired(pushed)) = &visit;
    // RFC 9126 §4: a request_uri is only usable by the client that pushed it.
    if pushed.request.client_id != client.id {
        return Err(bad("The request_uri was not issued to this client."));
    }
    Ok((client, request_uri.to_owned(), visit))
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

    let (client, request_uri, visit) = match load_request(
        &state,
        params.get("client_id"),
        params.get("request_uri"),
        true,
    )
    .await
    {
        Ok(found) => found,
        Err(response) => return *response,
    };

    let csrf = cookie(&headers, CSRF_COOKIE)
        .filter(|v| is_csrf_token(v))
        .map_or_else(|| random_token(32), str::to_owned);
    let (pushed, session) = match visit {
        Visit::Active(pushed, session) => (pushed, session),
        Visit::Expired(pushed) => {
            return session_expired_page(&state, &client, &request_uri, &pushed, &csrf);
        }
    };
    let interaction = Interaction {
        state: &state,
        client: &client,
        request_uri: &request_uri,
        pushed: &pushed,
        session: &session,
        csrf: &csrf,
        headers: &headers,
    };
    let step = state.experience.start(&interaction).await;
    conclude(&interaction, step).await
}

/// `POST /authorize/decision`: a form submitted from an experience's page,
/// or from the session expiry page.
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

    let (client, request_uri, visit) = match load_request(
        &state,
        params.get("client_id"),
        params.get("request_uri"),
        false,
    )
    .await
    {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let (pushed, session) = match visit {
        Visit::Active(pushed, session) => (pushed, session),
        // Too late to decide anything: whatever was submitted, the only way
        // on is back to the client with an error.
        Visit::Expired(_) if params.get("action") == Some(ACTION_RETURN_EXPIRED) => {
            return match return_expired(&state, &client, &request_uri).await {
                Ok(response) => response,
                Err(error) => store_unavailable(&error),
            };
        }
        Visit::Expired(pushed) => {
            return session_expired_page(&state, &client, &request_uri, &pushed, csrf);
        }
    };
    let interaction = Interaction {
        state: &state,
        client: &client,
        request_uri: &request_uri,
        pushed: &pushed,
        session: &session,
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
            return Ok(experience_page(&page, interaction, &step.set_cookies));
        }
        Decision::Deny { code, description } => {
            // The experience may already have discarded the request (after
            // too many failed sign-ins), so its absence is not an error.
            state
                .store
                .take_request(interaction.request_uri, now)
                .await?;
            record_decision(
                state,
                interaction.client,
                request.purpose.as_deref(),
                None,
                now,
                ConsentOutcome::Denied,
            )
            .await?;
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
            let txn = record_decision(
                state,
                interaction.client,
                request.purpose.as_deref(),
                Some(&approval),
                now,
                ConsentOutcome::Approved,
            )
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
    state: &AppState,
    client: &Client,
    purpose: Option<&str>,
    approval: Option<&Approval>,
    now: i64,
    outcome: ConsentOutcome,
) -> StoreResult<String> {
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
    use crate::experience::login::LOGIN_COOKIE;
    use crate::http::test_support::{Harness, body_text};
    use crate::http::{PATH_AUTHORIZE, PATH_DECISION};

    pub fn authorize_path(request_uri: &str) -> String {
        let query: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", "rp")
            .append_pair("request_uri", request_uri)
            .finish();
        format!("{PATH_AUTHORIZE}?{query}")
    }

    /// The value of the cookie `name` among a response's `Set-Cookie`s.
    pub fn set_cookie(response: &Response<Body>, name: &str) -> Option<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| value.strip_prefix(&format!("{name}=")))
            .and_then(|rest| rest.split(';').next())
            .map(str::to_owned)
    }

    /// Load the login page and return the CSRF token it issued.
    pub async fn open_login(harness: &Harness, request_uri: &str) -> String {
        let response = harness.get(None, &authorize_path(request_uri)).await;
        let csrf = set_cookie(&response, CSRF_COOKIE);
        assert_eq!(response.status(), 200, "{}", body_text(response).await);
        csrf.unwrap()
    }

    /// Post a form with the given `Cookie` header.
    pub async fn submit_with(
        harness: &Harness,
        cookies: Option<&str>,
        fields: &[(&str, &str)],
    ) -> Response<Body> {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request = Request::post(PATH_DECISION)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookies) = cookies {
            request = request.header(header::COOKIE, cookies);
        }
        harness
            .send(None, request.body(Body::from(body)).unwrap())
            .await
    }

    /// Post a form from a browser holding only the CSRF cookie.
    pub async fn submit(
        harness: &Harness,
        csrf_cookie: Option<&str>,
        fields: &[(&str, &str)],
    ) -> Response<Body> {
        let cookies = csrf_cookie.map(|csrf| format!("other=1; {CSRF_COOKIE}={csrf}"));
        submit_with(harness, cookies.as_deref(), fields).await
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

    fn checkboxes(html: &str, only_ticked: bool) -> Vec<String> {
        html.split("<input type=\"checkbox\"")
            .skip(1)
            .filter_map(|rest| {
                let tag = rest.split('>').next()?;
                let name = tag.split("name=\"").nth(1)?.split('"').next()?;
                (!only_ticked || tag.contains(" checked")).then(|| name.to_owned())
            })
            .collect()
    }

    /// Names of the checkboxes on a consent page: the voluntary claims.
    pub fn offered(html: &str) -> Vec<String> {
        checkboxes(html, false)
    }

    /// Names of the checkboxes that are ticked when the page loads.
    pub fn ticked(html: &str) -> Vec<String> {
        checkboxes(html, true)
    }

    /// A browser that has signed in and is looking at the consent page.
    pub struct SignedIn {
        pub csrf: String,
        /// The `Cookie` header the browser sends.
        pub cookies: String,
        /// The consent page.
        pub html: String,
    }

    /// Load the login page and sign in as the demo user.
    pub async fn sign_in(harness: &Harness, request_uri: &str) -> SignedIn {
        let csrf = open_login(harness, request_uri).await;
        let fields = [
            ("csrf", csrf.as_str()),
            ("client_id", "rp"),
            ("request_uri", request_uri),
            ("username", crate::user::DEMO_USERNAME),
            ("password", crate::user::DEMO_PASSWORD),
            ("action", "sign-in"),
        ];
        let response = submit(harness, Some(&csrf), &fields).await;
        assert_eq!(response.status(), 200);
        let login = set_cookie(&response, LOGIN_COOKIE).expect("signing in sets a cookie");
        SignedIn {
            cookies: format!("{CSRF_COOKIE}={csrf}; {LOGIN_COOKIE}={login}"),
            csrf,
            html: body_text(response).await,
        }
    }

    /// Submit the consent page with the `share` checkboxes turned on.
    pub async fn consent(
        harness: &Harness,
        request_uri: &str,
        browser: &SignedIn,
        share: &[String],
        action: &str,
    ) -> Response<Body> {
        let mut fields = vec![
            ("csrf", browser.csrf.as_str()),
            ("client_id", "rp"),
            ("request_uri", request_uri),
            ("action", action),
        ];
        fields.extend(share.iter().map(|field| (field.as_str(), "1")));
        submit_with(harness, Some(&browser.cookies), &fields).await
    }

    /// Run the browser leg for a pushed request, sharing everything offered,
    /// and return the code.
    pub async fn approve(harness: &Harness, request_uri: &str) -> String {
        approve_declining(harness, request_uri, &[]).await
    }

    /// As [`approve`], but leaving the `declined` claims turned off.
    pub async fn approve_declining(
        harness: &Harness,
        request_uri: &str,
        declined: &[&str],
    ) -> String {
        let browser = sign_in(harness, request_uri).await;
        let share: Vec<String> = offered(&browser.html)
            .into_iter()
            .filter(|field| !declined.iter().any(|d| *field == format!("share_{d}")))
            .collect();
        let response = consent(harness, request_uri, &browser, &share, "approve").await;
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
        approve, approve_declining, authorize_path, consent, offered, open_login, redirect_params,
        set_cookie, sign_in, submit, submit_with, ticked,
    };
    use super::*;
    use crate::experience::login::LOGIN_COOKIE;
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
            ("action", "sign-in"),
        ]
    }

    fn base_fields<'a>(csrf: &'a str, uri: &'a str, action: &'a str) -> [(&'a str, &'a str); 4] {
        [
            ("csrf", csrf),
            ("client_id", "rp"),
            ("request_uri", uri),
            ("action", action),
        ]
    }

    fn everything_requested() -> serde_json::Value {
        json!({
            "purpose": "Verify your <age> for checkout",
            "claims": {"id_token": {
                "given_name": null,
                "nickname": null,
                "verified_claims": {
                    "verification": {"trust_framework": {"value": "au_connectid"}},
                    "claims": {"over18": null, "beneficiary_account_au": {"essential": true}},
                },
            }},
        })
    }

    #[tokio::test]
    async fn login_page_names_the_client_but_not_what_is_requested() {
        let harness = Harness::new();
        let uri = harness.push(&everything_requested()).await;
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
        assert!(html.contains("Log in to oxID"));
        assert!(html.contains("<strong id=\"client-name\">Test RP</strong>"));
        assert!(html.contains("id=\"username\"") && html.contains("id=\"password\""));
        assert!(html.contains("id=\"sign-in\"") && html.contains("id=\"deny\""));
        // Nothing about the request is shown before the user signs in.
        for hidden in ["checkout", "Given name", "data-claim", "Alex", "share_"] {
            assert!(!html.contains(hidden), "{hidden}");
        }
    }

    #[tokio::test]
    async fn consent_page_shows_client_purpose_and_each_claim_with_its_value() {
        let harness = Harness::new();
        let uri = harness.push(&everything_requested()).await;
        let browser = sign_in(&harness, &uri).await;
        let html = &browser.html;
        assert!(html.contains("<span id=\"client-name\">Test RP</span>"));
        assert!(html.contains("Logged in as <strong>Alex Jordan Citizen</strong>"));
        assert!(
            html.contains("<p id=\"purpose\">Verify your &lt;age&gt; for checkout</p>"),
            "purpose is shown, escaped"
        );
        // Each claim is listed with the value that would be shared.
        assert!(html.contains("<span class=\"value\" id=\"value-given_name\">Alex</span>"));
        assert!(html.contains("<span class=\"value\" id=\"value-over18\">Yes</span>"));
        assert!(html.contains("Bank account (BSB and account number)"));
        assert!(html.contains("<em>BSB:</em> 123456") && html.contains("12345678"));
        assert!(
            html.contains("<li data-claim=\"beneficiary_account_au\" data-essential=\"true\">")
        );
        // Voluntary claims are offered, and off until the user chooses.
        assert_eq!(offered(html), ["share_given_name", "share_over18"]);
        assert_eq!(ticked(html), Vec::<String>::new());
        assert!(
            !html.contains("nickname"),
            "unsupported claims are not offered"
        );
        assert!(!html.contains("id=\"password\""));
    }

    #[tokio::test]
    async fn claims_the_user_does_not_have_are_shown_as_not_shared() {
        let harness = Harness::new();
        let uri = harness
            .push(&json!({"claims": {"id_token": {"given_name": null}}}))
            .await;
        let browser = sign_in(&harness, &uri).await;
        assert!(!browser.html.contains("Not on file"));
        // Every demo customer has a given name, so check the rendering of a
        // missing value through the list of values instead.
        let user = harness
            .state
            .users
            .find_by_subject("demo-user-0001")
            .unwrap();
        let mut without = (*user).clone();
        without.claims.remove("given_name");
        let client = harness.state.clients.get("rp").unwrap();
        let request =
            crate::claims::ClaimsRequest::parse(&json!({"id_token": {"given_name": null}}))
                .unwrap();
        let values = request.shareable_values(&without, &client, &[], harness.state.now());
        assert_eq!(values, serde_json::Map::new());
        let values = request.shareable_values(&user, &client, &[], harness.state.now());
        assert_eq!(values["given_name"], "Alex");
    }

    #[tokio::test]
    async fn approval_redirects_with_code_state_and_iss() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let browser = sign_in(&harness, &uri).await;
        let response = consent(&harness, &uri, &browser, &[], "approve").await;
        let (base, params) = redirect_params(&response);
        assert_eq!(base, "https://rp.example.com/cb");
        assert_eq!(params["state"], "st-1");
        assert_eq!(params["iss"], ISSUER);
        assert!(params["code"].len() >= 43);
        assert!(!params.contains_key("error"));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            set_cookie(&response, LOGIN_COOKIE).as_deref(),
            Some(""),
            "the sign-in cookie is cleared"
        );
    }

    #[tokio::test]
    async fn consent_is_only_taken_from_the_browser_that_signed_in() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let browser = sign_in(&harness, &uri).await;

        // Someone else who knows the request_uri, with their own CSRF cookie.
        let other = open_login(&harness, &uri).await;
        let fields = base_fields(&other, &uri, "approve");
        let response = submit(&harness, Some(&other), &fields).await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body_text(response).await;
        assert!(html.contains("id=\"password\"") && html.contains("Log in to continue."));

        let forged = format!("{CSRF_COOKIE}={other}; {LOGIN_COOKIE}={}", random_token(32));
        let response = submit_with(&harness, Some(&forged), &fields).await;
        assert!(body_text(response).await.contains("id=\"password\""));
        // They are shown the login page, not the user's details.
        let request = axum::http::Request::get(authorize_path(&uri))
            .header(header::COOKIE, &forged)
            .body(axum::body::Body::empty())
            .unwrap();
        let html = body_text(harness.send(None, request).await).await;
        assert!(html.contains("id=\"password\"") && !html.contains("Alex"));

        // The browser that signed in comes back to the consent page on a
        // reload, and can still complete.
        let request = axum::http::Request::get(authorize_path(&uri))
            .header(header::COOKIE, &browser.cookies)
            .body(axum::body::Body::empty())
            .unwrap();
        let html = body_text(harness.send(None, request).await).await;
        assert!(html.contains("id=\"approve\"") && !html.contains("id=\"password\""));
        let response = consent(&harness, &uri, &browser, &[], "approve").await;
        assert!(redirect_params(&response).1.contains_key("code"));
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
        submit(&harness, Some(&csrf), &base_fields(&csrf, &uri, "deny")).await;
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
    async fn voluntary_claims_are_shared_only_if_chosen_and_essential_ones_always() {
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
        let browser = sign_in(&harness, &uri).await;
        // Essential claims have no checkbox at all; the rest start off.
        assert_eq!(
            offered(&browser.html),
            ["share_email", "share_over21", "share_phone_number"]
        );
        assert_eq!(ticked(&browser.html), Vec::<String>::new());
        assert!(!browser.html.contains("share_given_name"));
        assert!(!browser.html.contains("share_over18"));
        assert!(browser.html.contains("id=\"optional-hint\""));
        assert!(browser.html.contains("id=\"required-hint\""));

        // Fields for claims that were never offered are ignored.
        let share = ["share_phone_number", "share_birthdate", "share_name"].map(str::to_owned);
        consent(&harness, &uri, &browser, &share, "approve").await;
        let record = &harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap()[0];
        assert_eq!(record.claims, ["given_name", "over18", "phone_number"]);
        assert_eq!(record.declined, ["email", "over21"]);

        // "Turn all on" shows the page again with every switch on.
        let uri = harness.push(&pushed).await;
        let browser = sign_in(&harness, &uri).await;
        assert!(browser.html.contains("id=\"share-all\""));
        let response = consent(&harness, &uri, &browser, &[], "share-all").await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body_text(response).await;
        assert_eq!(ticked(&html), offered(&html));
        assert_eq!(offered(&html).len(), 3);

        // Choosing nothing still shares the essential claims.
        let uri = harness.push(&pushed).await;
        let browser = sign_in(&harness, &uri).await;
        consent(&harness, &uri, &browser, &[], "approve").await;
        let record = &harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap()[0];
        assert_eq!(record.claims, ["given_name", "over18"]);
        assert_eq!(record.declined, ["email", "over21", "phone_number"]);

        let uri = harness.push(&pushed).await;
        approve_declining(&harness, &uri, &["email"]).await;
        let record = &harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap()[0];
        assert_eq!(record.declined, ["email"]);
    }

    #[tokio::test]
    async fn consent_page_says_when_nothing_personal_is_shared() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let browser = sign_in(&harness, &uri).await;
        assert!(browser.html.contains("id=\"requested-none\""));
        assert!(!browser.html.contains("id=\"purpose\""));
    }

    #[tokio::test]
    async fn state_is_omitted_from_the_response_when_not_requested() {
        let harness = Harness::new();
        let uri = harness.push(&json!({"state": null})).await;
        let browser = sign_in(&harness, &uri).await;
        let response = consent(&harness, &uri, &browser, &[], "approve").await;
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
        let fields = base_fields(&csrf, &uri, "deny");
        let response = submit(&harness, Some(&csrf), &fields).await;
        let (_, params) = redirect_params(&response);
        assert_eq!(params["error"], "access_denied");
        assert_eq!(params["state"], "st-1");
        assert_eq!(params["iss"], ISSUER);
        assert!(!params.contains_key("code"));

        let again = submit(&harness, Some(&csrf), &fields).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST);

        // The consent page can be cancelled too.
        let uri = harness.push(&json!({})).await;
        let browser = sign_in(&harness, &uri).await;
        let response = consent(&harness, &uri, &browser, &[], "deny").await;
        assert_eq!(redirect_params(&response).1["error"], "access_denied");
    }

    #[tokio::test]
    async fn wrong_password_re_prompts_then_gives_up() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        for _ in 1..MAX_FAILED_LOGINS {
            let response = submit(&harness, Some(&csrf), &login_fields(&csrf, &uri, "wrong")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(set_cookie(&response, LOGIN_COOKIE).is_none());
            let html = body_text(response).await;
            assert!(html.contains("username or password is incorrect"));
            assert!(html.contains("id=\"password\""));
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
        let html = body_text(response).await;
        assert!(html.contains("id=\"error-message\""));
        assert!(!html.contains("id=\"return\""), "no way back is offered");
    }

    #[tokio::test]
    async fn a_form_cannot_be_submitted_for_a_request_no_browser_arrived_for() {
        let harness = Harness::new();
        let arrived = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &arrived).await;
        let uri = harness.push(&json!({})).await;
        let response = submit(
            &harness,
            Some(&csrf),
            &login_fields(&csrf, &uri, DEMO_PASSWORD),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn arriving_in_time_gives_the_user_a_session_longer_than_the_request_uri() {
        let harness = Harness::new();
        let security = &harness.state.security;
        assert_eq!(security.session_ttl, 300);
        assert!(security.request_uri_ttl < security.session_ttl);

        let uri = harness.push(&json!({})).await;
        harness.clock.advance(security.request_uri_ttl - 1);
        let response = harness.get(None, &authorize_path(&uri)).await;
        let html = body_text(response).await;
        // The page takes itself to the expiry page when the session ends.
        assert!(html.contains(&format!(
            "setTimeout(function(){{location.replace(\"/authorize?client_id=rp&request_uri={}\")}},300000);",
            uri.replace(':', "%3A")
        )));

        // Long after the request_uri expired, the user can still sign in,
        // read the consent page and decide.
        harness.clock.advance(200);
        let browser = sign_in(&harness, &uri).await;
        assert!(browser.html.contains(")},100000);"));
        assert!(browser.html.contains("expires 5 minutes after you arrived"));
        harness.clock.advance(99);
        let response = consent(&harness, &uri, &browser, &[], "approve").await;
        assert!(redirect_params(&response).1.contains_key("code"));
    }

    #[tokio::test]
    async fn an_expired_session_is_explained_and_returns_access_denied_to_the_client() {
        let harness = Harness::new();
        let uri = harness
            .push(&json!({"purpose": "Opening your savings account"}))
            .await;
        let browser = sign_in(&harness, &uri).await;
        harness.clock.advance(harness.state.security.session_ttl);

        // Too late to approve: the user is told why instead.
        let late = consent(&harness, &uri, &browser, &[], "approve").await;
        assert_eq!(late.status(), StatusCode::BAD_REQUEST);
        assert!(!late.headers().contains_key(header::LOCATION));
        assert!(body_text(late).await.contains("id=\"session-expired\""));

        // Reloading, as the page does by itself, shows the same.
        let response = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("form-action 'self' https://rp.example.com"),
            "the way back must not be blocked"
        );
        let html = body_text(response).await;
        assert!(html.contains("Your session has expired"));
        assert!(html.contains("within 5 minutes"));
        assert!(html.contains("value=\"session-expired-return\">Return to Test RP</button>"));
        assert!(!html.contains("Alex") && !html.contains("savings"));

        // The way back is the standard error redirect.
        let fields = base_fields(&browser.csrf, &uri, "session-expired-return");
        let no_csrf = submit(&harness, None, &fields).await;
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        let response = submit(&harness, Some(&browser.csrf), &fields).await;
        let (base, params) = redirect_params(&response);
        assert_eq!(base, "https://rp.example.com/cb");
        assert_eq!(params["error"], "access_denied");
        assert_eq!(
            params["error_description"],
            "session timeout: the user did not complete the request in time"
        );
        assert_eq!(params["state"], "st-1");
        assert_eq!(params["iss"], ISSUER);
        assert!(!params.contains_key("code"));

        // It is recorded as a refusal, and the request is used up.
        let again = submit(&harness, Some(&browser.csrf), &fields).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST);
        assert!(!body_text(again).await.contains("id=\"return\""));
        let history = harness
            .state
            .store
            .consent_history("demo-user-0001")
            .await
            .unwrap();
        assert_eq!(history, Vec::new(), "recorded against no user");
    }

    #[tokio::test]
    async fn the_way_back_is_only_for_expired_sessions() {
        let harness = Harness::new();
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        let fields = base_fields(&csrf, &uri, "session-expired-return");
        let response = submit(&harness, Some(&csrf), &fields).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("id=\"password\""));
    }

    #[tokio::test]
    async fn the_technical_experience_has_the_same_session() {
        let harness = Harness::with_experience(crate::experience::Kind::Technical);
        let uri = harness.push(&json!({})).await;
        let csrf = open_login(&harness, &uri).await;
        harness.clock.advance(299);
        let response = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains(")},1000);"));

        harness.clock.advance(1);
        let fields = base_fields(&csrf, &uri, "send");
        let late = submit(&harness, Some(&csrf), &fields).await;
        assert_eq!(late.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(late).await.contains("id=\"session-expired\""));
        let fields = base_fields(&csrf, &uri, "session-expired-return");
        let response = submit(&harness, Some(&csrf), &fields).await;
        assert_eq!(redirect_params(&response).1["error"], "access_denied");
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
