//! Authorization endpoint: the browser-facing half of the code flow.
//!
//! Only `request_uri` values issued by the PAR endpoint are accepted
//! (FAPI 2.0 §5.3.2.2-3). A `request_uri` is consumed when the user makes a
//! decision, not when the page is loaded, so a reload does not strand the
//! user (§5.3.2.2 note 3).
//!
//! Failures are reported in one of two ways. When the request cannot be tied
//! to a registered redirect URI the user sees an error page and is *not*
//! redirected (the provider must not be an open redirector, §5.3.2.1-7).
//! Otherwise the error goes back to the client's redirect URI.

use std::fmt::Write as _;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use url::Url;
use uuid::Uuid;

use super::{PATH_DECISION, Params, no_store};
use crate::authz::AuthorizationRequest;
use crate::claims::VERIFIED_CLAIMS;
use crate::client::Client;
use crate::error::ErrorCode;
use crate::state::AppState;
use crate::store::{AuthorizationCode, Grant, PushedRequest};
use crate::util::{ct_eq, html_escape, random_token};

/// Double-submit CSRF cookie. The `__Host-` prefix pins it to this origin,
/// `Secure` and path `/` (RFC 6265bis §4.1.3.2).
const CSRF_COOKIE: &str = "__Host-oxid-csrf";

const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";

const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;\
padding:0 1rem;color:#1a1a1a}h1{font-size:1.4rem}label{display:block;margin:.8rem 0 .2rem}\
input{width:100%;padding:.5rem;box-sizing:border-box}button{padding:.6rem 1.2rem;margin:1rem .5rem 0 0}\
.error{color:#b00020}.box{background:#f4f4f4;padding:.8rem;border-radius:.3rem}";

fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} - oxID</title><style>{STYLE}</style></head><body>{body}</body></html>",
        title = html_escape(title),
    );
    let mut response = no_store((status, Html(html)).into_response());
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    response
}

/// An error shown to the user because it is not safe to redirect.
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

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn is_csrf_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The pushed request named by the browser's parameters, or the error page
/// explaining why there is none.
fn load_request(
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
        match load_request(&state, params.get("client_id"), params.get("request_uri")) {
            Ok(found) => found,
            Err(response) => return *response,
        };

    let csrf = cookie(&headers, CSRF_COOKIE)
        .filter(|v| is_csrf_token(v))
        .map_or_else(|| random_token(32), str::to_owned);
    login_page(&client, &request_uri, &pushed.request, &csrf, None)
}

fn login_page(
    client: &Client,
    request_uri: &str,
    request: &AuthorizationRequest,
    csrf: &str,
    error: Option<&str>,
) -> Response {
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
            "<p>Reason given for this request:</p><p id=\"purpose\" class=\"box\">{}</p>",
            html_escape(purpose)
        );
    }

    let mut requested: Vec<String> = request
        .claims
        .id_token
        .keys()
        .chain(request.claims.userinfo.keys())
        .filter(|name| *name != VERIFIED_CLAIMS)
        .cloned()
        .collect();
    for location in [&request.claims.id_token, &request.claims.userinfo] {
        let verified = location.get(VERIFIED_CLAIMS).and_then(|v| v.get("claims"));
        if let Some(claims) = verified.and_then(|c| c.as_object()) {
            requested.extend(claims.keys().map(|name| format!("{name} (verified)")));
        }
    }
    requested.sort();
    requested.dedup();

    body.push_str("<p>This application is asking for:</p><ul id=\"requested\">");
    for scope in &request.scope {
        let _ = write!(body, "<li>scope: {}</li>", html_escape(scope));
    }
    for claim in &requested {
        let _ = write!(body, "<li>{}</li>", html_escape(claim));
    }
    body.push_str("</ul>");

    let _ = write!(
        body,
        "<form method=\"post\" action=\"{PATH_DECISION}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"client_id\" value=\"{client_id}\">\
         <input type=\"hidden\" name=\"request_uri\" value=\"{request_uri}\">\
         <label for=\"username\">Username</label>\
         <input id=\"username\" name=\"username\" autocomplete=\"username\" autofocus>\
         <label for=\"password\">Password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\">\
         <button id=\"approve\" type=\"submit\" name=\"action\" value=\"approve\">Sign in and allow</button>\
         <button id=\"deny\" type=\"submit\" name=\"action\" value=\"deny\" formnovalidate>Cancel</button>\
         </form>",
        csrf = html_escape(csrf),
        client_id = html_escape(&client.id),
        request_uri = html_escape(request_uri),
    );

    let mut response = page(StatusCode::OK, "Sign in", &body);
    let set_cookie = format!("{CSRF_COOKIE}={csrf}; Path=/; Secure; HttpOnly; SameSite=Strict");
    if let Ok(value) = HeaderValue::from_str(&set_cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// `POST /authorize/decision`: the user's sign-in and consent.
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
        match load_request(&state, params.get("client_id"), params.get("request_uri")) {
            Ok(found) => found,
            Err(response) => return *response,
        };
    let request = &pushed.request;
    let used = || {
        error_page(
            StatusCode::BAD_REQUEST,
            "The request_uri is invalid, has expired, or has already been used.",
        )
    };

    match params.get("action") {
        Some("deny") => {
            if state
                .store
                .take_request(&request_uri, state.now())
                .is_none()
            {
                return used();
            }
            tracing::info!(client_id = %client.id, "user denied the authorization request");
            redirect_error(
                &state,
                &request.redirect_uri,
                request.state.as_deref(),
                ErrorCode::AccessDenied,
                "the user denied the request",
            )
        }
        Some("approve") => {
            let username = params.get("username").unwrap_or_default().to_owned();
            let password = params.get("password").unwrap_or_default().to_owned();
            let users = std::sync::Arc::clone(&state.users);
            // Password hashing is CPU-bound; keep it off the async workers.
            let user =
                tokio::task::spawn_blocking(move || users.authenticate(&username, &password))
                    .await
                    .ok()
                    .flatten();

            let Some(user) = user else {
                if state.store.record_failed_login(&request_uri) {
                    return login_page(
                        &client,
                        &request_uri,
                        request,
                        csrf,
                        Some("The username or password is incorrect."),
                    );
                }
                tracing::warn!(client_id = %client.id, "too many failed sign-in attempts");
                return redirect_error(
                    &state,
                    &request.redirect_uri,
                    request.state.as_deref(),
                    ErrorCode::AccessDenied,
                    "too many failed sign-in attempts",
                );
            };

            // One-time use is enforced here, at the point of authorization.
            let now = state.now();
            let Some(pushed) = state.store.take_request(&request_uri, now) else {
                return used();
            };
            let request = pushed.request;
            let code = state.store.create_code(AuthorizationCode {
                grant: Grant {
                    id: random_token(16),
                    client_id: client.id.clone(),
                    user_subject: user.subject.clone(),
                    scope: request.scope,
                    claims: request.claims,
                    auth_time: now,
                    txn: Uuid::new_v4().to_string(),
                },
                redirect_uri: request.redirect_uri.clone(),
                code_challenge: request.code_challenge,
                nonce: request.nonce,
                expires_at: now + state.security.authorization_code_ttl,
            });
            tracing::info!(client_id = %client.id, "user approved the authorization request");

            let mut out = vec![("code", code.as_str())];
            if let Some(client_state) = &request.state {
                out.push(("state", client_state));
            }
            redirect_to_client(&state, &request.redirect_uri, &out)
        }
        _ => error_page(StatusCode::BAD_REQUEST, "No decision was submitted."),
    }
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

    /// Run the browser leg for a pushed request and return the code.
    pub async fn approve(harness: &Harness, request_uri: &str) -> String {
        let csrf = open_login(harness, request_uri).await;
        let response = submit(
            harness,
            Some(&csrf),
            &[
                ("csrf", &csrf),
                ("client_id", "rp"),
                ("request_uri", request_uri),
                ("username", crate::user::DEMO_USERNAME),
                ("password", crate::user::DEMO_PASSWORD),
                ("action", "approve"),
            ],
        )
        .await;
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

    use super::test_support::{approve, authorize_path, open_login, redirect_params, submit};
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
                    "verified_claims": {"verification": {"trust_framework": null}, "claims": {"over18": null}},
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
        assert!(html.contains("<li>given_name</li>"));
        assert!(html.contains("<li>over18 (verified)</li>"));
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

    #[test]
    fn cookie_parsing_finds_the_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-oxid-csrf=tok; b=2"),
        );
        assert_eq!(cookie(&headers, CSRF_COOKIE), Some("tok"));
        assert_eq!(cookie(&headers, "a"), Some("1"));
        assert_eq!(cookie(&headers, "missing"), None);
    }
}
