//! Endpoints of the `ci` experience (`crate::experience::ci`), which exist
//! only when that experience is selected.
//!
//! * `POST /ci/response`: a client chooses the response to a request it has
//!   pushed.
//! * `GET /ci`: what there is to choose from.
//!
//! Choosing a response is something only the client that pushed the request
//! may do, so the endpoint authenticates the client exactly as the pushed
//! authorization request endpoint does: `private_key_jwt` (ConnectID
//! §4.2-3.4), with the same audience and replay rules. A client assertion
//! can be used once, so the client makes a fresh one for this call.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::{OAuthForm, PATH_CI_RESPONSE, Params, authenticate_client, no_store};
use crate::client::Client;
use crate::error::OAuthError;
use crate::experience::ci::default_user;
use crate::experience::{
    ERROR_CONDITIONS, MAX_ERROR_DESCRIPTION, error_condition, is_error_description,
};
use crate::state::AppState;
use crate::store::{PlannedResponse, PushedRequest, Visit};
use crate::user::User;

const OUTCOME_SUCCESS: &str = "success";
const OUTCOME_ERROR: &str = "error";
const OUTCOME_ABANDON: &str = "abandon";

/// `GET /ci`: the choices the response endpoint offers. Nothing here is
/// secret from anyone who may use a provider running this experience.
pub async fn options(State(state): State<AppState>) -> Response {
    let users: Vec<Value> = state
        .users
        .list()
        .iter()
        .map(|user| json!({ "username": user.username, "name": user.display_name() }))
        .collect();
    let errors: Vec<Value> = ERROR_CONDITIONS
        .iter()
        .map(|condition| {
            json!({
                "error": condition.code.as_str(),
                "error_description": condition.description,
                "meaning": condition.label,
            })
        })
        .collect();
    let body = json!({
        "response_endpoint": state.url(PATH_CI_RESPONSE),
        "response_delay": state.ci.response_delay,
        "outcomes": [OUTCOME_SUCCESS, OUTCOME_ERROR, OUTCOME_ABANDON],
        "default_user": default_user(state.users.as_ref()).map(|user| user.username.clone()),
        "users": users,
        "errors": errors,
    });
    no_store(Json(body).into_response())
}

/// `POST /ci/response`: set the response to one pushed request.
///
/// Form parameters, beside the client authentication:
///
/// * `request_uri` (required): the request, which this client pushed and
///   which has not been answered yet.
/// * `outcome`: `success` (the default), `error`, or `abandon`: the user
///   leaves without deciding, so the next visit gets a page instead of a
///   redirect and the request stays pending. That holds for one visit; the
///   one after is answered as if nothing had been chosen. It takes no other
///   parameters.
/// * For a success:
///   * `user`: the username, or the subject, of the user to respond as.
///     Defaults to the first configured user.
///   * `voluntary_claims`: the names, separated by spaces, of the voluntary
///     claims to share. Those left out are declined. Absent means all of
///     them; present but empty means none. Essential claims are always
///     shared.
/// * For an error:
///   * `error`: one of the predefined error codes (`GET /ci` lists them).
///     Defaults to `access_denied`.
///   * `error_description`: replaces that error's default description.
///
/// A parameter that does not apply to the outcome is refused rather than
/// ignored: in a test, a response that is quietly not the one asked for is
/// worse than an error. Setting a response again replaces the earlier one.
pub async fn plan_response(
    State(state): State<AppState>,
    OAuthForm(params): OAuthForm,
) -> Result<Response, OAuthError> {
    let client = authenticate_client(&state, &params).await?;
    let now = state.now();

    let request_uri = params
        .get("request_uri")
        .ok_or_else(|| OAuthError::invalid_request("request_uri is required"))?;
    let pushed = pending_request(&state, &client, request_uri, now)
        .await?
        .ok_or_else(|| {
            OAuthError::invalid_request(
                "request_uri is unknown, has expired, or has already been answered",
            )
        })?;

    let outcome = params.get("outcome").unwrap_or(OUTCOME_SUCCESS);
    let refuse_others = |names: &[&str]| -> Result<(), OAuthError> {
        match names.iter().find(|name| params.contains(name)) {
            Some(name) => Err(OAuthError::invalid_request(format!(
                "{name} does not apply to outcome={outcome}"
            ))),
            None => Ok(()),
        }
    };
    let (plan, mut body) = match outcome {
        OUTCOME_SUCCESS => {
            refuse_others(&["error", "error_description"])?;
            success(&state, &client, &pushed, &params)?
        }
        OUTCOME_ERROR => {
            refuse_others(&["user", "voluntary_claims"])?;
            error(&params)?
        }
        OUTCOME_ABANDON => {
            refuse_others(&["user", "voluntary_claims", "error", "error_description"])?;
            (PlannedResponse::Abandon, json!({}))
        }
        other => {
            return Err(OAuthError::invalid_request(format!(
                "outcome '{other}' is not one of: {OUTCOME_SUCCESS}, {OUTCOME_ERROR}, \
                 {OUTCOME_ABANDON}"
            )));
        }
    };

    // Long enough for the browser to arrive and the session to run its
    // course, whenever in the life of the request this was called.
    let kept_until = now + state.security.request_uri_ttl + state.security.session_ttl;
    state
        .store
        .plan_response(request_uri, &plan, kept_until)
        .await?;
    tracing::info!(client_id = %client.id, outcome, "ci: the client chose the response");

    body["request_uri"] = request_uri.into();
    body["outcome"] = outcome.into();
    Ok(no_store(Json(body).into_response()))
}

/// The pushed request `request_uri` names, if `client` pushed it and it can
/// still be answered: its browser has yet to arrive in time, or is within
/// its session.
async fn pending_request(
    state: &AppState,
    client: &Client,
    request_uri: &str,
    now: i64,
) -> Result<Option<PushedRequest>, OAuthError> {
    let pushed = match state.store.resume(request_uri, now).await? {
        Some(Visit::Active(pushed, _)) => Some(*pushed),
        Some(Visit::Expired(_)) => None,
        // No browser has arrived yet.
        None => state
            .store
            .peek_request(request_uri, now)
            .await?
            .filter(|pushed| pushed.expires_at > now),
    };
    // RFC 9126 §4: a request_uri belongs to the client that pushed it. Another
    // client is told no more than if it did not exist.
    Ok(pushed.filter(|pushed| pushed.request.client_id == client.id))
}

fn find_user(state: &AppState, name: &str) -> Option<std::sync::Arc<User>> {
    state
        .users
        .list()
        .into_iter()
        .find(|user| user.username == name || user.subject == name)
}

fn success(
    state: &AppState,
    client: &Client,
    pushed: &PushedRequest,
    params: &Params,
) -> Result<(PlannedResponse, Value), OAuthError> {
    let user = match params.get("user") {
        Some(name) => find_user(state, name)
            .ok_or_else(|| OAuthError::invalid_request(format!("user '{name}' does not exist")))?,
        None => default_user(state.users.as_ref())
            .ok_or_else(|| OAuthError::server_error("no users are configured"))?,
    };

    let request = &pushed.request;
    let items = request.claims.consentable(client, &request.scope);
    let chosen: Option<BTreeSet<&str>> = params.contains("voluntary_claims").then(|| {
        params
            .get("voluntary_claims")
            .unwrap_or_default()
            .split_ascii_whitespace()
            .collect()
    });
    for name in chosen.iter().flatten() {
        match items.iter().find(|item| item.name == *name) {
            Some(item) if !item.essential => {}
            Some(_) => {
                return Err(OAuthError::invalid_request(format!(
                    "voluntary_claims: '{name}' was requested as essential, so it is always shared"
                )));
            }
            None => {
                return Err(OAuthError::invalid_request(format!(
                    "voluntary_claims: '{name}' is not a claim this request can be given"
                )));
            }
        }
    }
    let shared_claims = crate::claims::shared_claims(&items, |name| {
        chosen.as_ref().is_none_or(|chosen| chosen.contains(name))
    });
    let declined: Vec<String> = items
        .into_iter()
        .map(|item| item.name)
        .filter(|name| !shared_claims.contains(name))
        .collect();

    let body = json!({
        "user": user.username,
        "claims": shared_claims,
        "declined": declined,
    });
    let plan = PlannedResponse::Success {
        user_subject: user.subject.clone(),
        shared_claims,
        declined,
    };
    Ok((plan, body))
}

fn error(params: &Params) -> Result<(PlannedResponse, Value), OAuthError> {
    let condition = match params.get("error") {
        Some(code) => error_condition(code).ok_or_else(|| {
            let known: Vec<&str> = ERROR_CONDITIONS
                .iter()
                .map(|condition| condition.code.as_str())
                .collect();
            OAuthError::invalid_request(format!(
                "error '{code}' is not one of: {}",
                known.join(", ")
            ))
        })?,
        None => &ERROR_CONDITIONS[0],
    };
    let description = match params.get("error_description") {
        // RFC 6749 §4.1.2.1 limits what an error_description may contain.
        Some(text) if text.len() <= MAX_ERROR_DESCRIPTION && is_error_description(text) => text,
        Some(_) => {
            return Err(OAuthError::invalid_request(format!(
                "error_description must be at most {MAX_ERROR_DESCRIPTION} printable ASCII \
                 characters, without double quotes or backslashes"
            )));
        }
        None => condition.description,
    };
    let error = condition.code.as_str();
    let body = json!({ "error": error, "error_description": description });
    let plan = PlannedResponse::Error {
        error: error.to_owned(),
        description: description.to_owned(),
    };
    Ok((plan, body))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Response, StatusCode, header};
    use serde_json::{Value, json};
    use url::Url;

    use crate::client_auth::ASSERTION_TYPE;
    use crate::http::authorize::test_support::authorize_path;
    use crate::http::test_support::{CERT, Harness, json_body};
    use crate::http::{PATH_CI, PATH_CI_RESPONSE};
    use crate::store::{CodeRedemption, ConsentOutcome, Grant};

    /// `given_name` and `over18` voluntary, `beneficiary_account_au`
    /// essential.
    fn request() -> Value {
        json!({
            "state": "s-1",
            "claims": {"id_token": {
                "given_name": null,
                "verified_claims": {
                    "verification": {"trust_framework": {"value": "au_connectid"}},
                    "claims": {"over18": null, "beneficiary_account_au": {"essential": true}},
                },
            }},
        })
    }

    /// Choose a response as the authenticated client `rp`.
    async fn plan(harness: &Harness, fields: &[(&str, &str)]) -> (StatusCode, Value) {
        let assertion = harness.assertion();
        let mut all = vec![
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
        ];
        all.extend_from_slice(fields);
        let response = harness.post_form(Some(CERT), PATH_CI_RESPONSE, &all).await;
        let status = response.status();
        (status, json_body(response).await)
    }

    /// The parameters of the redirect back to the client.
    fn redirect(response: &Response<Body>) -> std::collections::HashMap<String, String> {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("https://rp.example.com/cb?"),
            "{location}"
        );
        Url::parse(location)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    }

    /// Arrive at the authorization endpoint, as a browser or `curl` would,
    /// and return the parameters it redirects back with.
    async fn arrive(harness: &Harness, uri: &str) -> std::collections::HashMap<String, String> {
        redirect(&harness.get(None, &authorize_path(uri)).await)
    }

    /// The grant behind an authorization code.
    async fn grant(harness: &Harness, code: &str) -> Grant {
        let now = harness.state.now();
        match harness.state.store.redeem_code(code, "rp", now).await {
            Ok(CodeRedemption::Valid(code)) => code.grant,
            other => panic!("the code should be valid: {other:?}"),
        }
    }

    fn subject(harness: &Harness, username: &str) -> String {
        let users = harness.state.users.list();
        let user = users.iter().find(|user| user.username == username);
        user.unwrap().subject.clone()
    }

    fn names(claims: &[&str]) -> std::collections::BTreeSet<String> {
        claims.iter().map(|&name| name.to_owned()).collect()
    }

    #[tokio::test]
    async fn with_no_response_chosen_the_first_user_shares_everything() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;
        let params = arrive(&harness, &uri).await;
        assert_eq!(params["state"], "s-1");
        assert_eq!(params["iss"], harness.state.issuer);
        assert!(!params.contains_key("error"));

        let grant = grant(&harness, &params["code"]).await;
        assert_eq!(grant.user_subject, subject(&harness, "demo"));
        assert_eq!(
            grant.shared_claims,
            names(&["beneficiary_account_au", "given_name", "over18"])
        );
        let record = harness.state.store.consent(&grant.txn).await.unwrap();
        assert_eq!(record.unwrap().outcome, ConsentOutcome::Approved);

        // The request_uri is spent, as under any experience.
        let again = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(start_paused = true)]
    async fn the_default_response_waits_for_the_configured_delay() {
        let harness = Harness::ci(5);
        let uri = harness.push(&request()).await;
        let started = tokio::time::Instant::now();
        let params = arrive(&harness, &uri).await;
        assert!(params.contains_key("code"));
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn the_delay_runs_from_the_first_arrival() {
        let harness = Harness::ci(5);
        let uri = harness.push(&request()).await;
        // A browser arrived three seconds ago and went away without waiting.
        let now = harness.state.now();
        harness.state.store.arrive(&uri, now).await.unwrap();
        harness.clock.advance(3);

        let started = tokio::time::Instant::now();
        assert!(arrive(&harness, &uri).await.contains_key("code"));
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_response_chosen_during_the_wait_is_given_at_once() {
        let harness = Harness::ci(5);
        let uri = harness.push(&request()).await;
        let started = tokio::time::Instant::now();
        let (params, (status, _)) = tokio::join!(arrive(&harness, &uri), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            plan(&harness, &[("request_uri", &uri), ("outcome", "error")]).await
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(params["error"], "access_denied");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the rest of the delay is not waited out"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_response_chosen_before_arriving_is_given_without_waiting() {
        let harness = Harness::ci(5);
        let uri = harness.push(&request()).await;
        let (status, body) = plan(
            &harness,
            &[
                ("request_uri", &uri),
                ("outcome", "error"),
                ("error", "login_required"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({
                "request_uri": uri,
                "outcome": "error",
                "error": "login_required",
                "error_description": "the user must authenticate",
            })
        );

        let started = tokio::time::Instant::now();
        let params = arrive(&harness, &uri).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(params["error"], "login_required");
        assert_eq!(params["error_description"], "the user must authenticate");
        assert_eq!(params["state"], "s-1");
        assert_eq!(params["iss"], harness.state.issuer);
        assert!(!params.contains_key("code"));
    }

    #[tokio::test]
    async fn an_error_can_carry_its_own_description() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;
        let (status, _) = plan(
            &harness,
            &[
                ("request_uri", &uri),
                ("outcome", "error"),
                ("error", "temporarily_unavailable"),
                ("error_description", "down for the test"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let params = arrive(&harness, &uri).await;
        assert_eq!(params["error"], "temporarily_unavailable");
        assert_eq!(params["error_description"], "down for the test");
    }

    #[tokio::test]
    async fn the_client_chooses_the_user_and_the_voluntary_claims() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;
        let (status, body) = plan(
            &harness,
            &[
                ("request_uri", &uri),
                ("user", "riley"),
                ("voluntary_claims", "over18"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({
                "request_uri": uri,
                "outcome": "success",
                "user": "riley",
                "claims": ["beneficiary_account_au", "over18"],
                "declined": ["given_name"],
            })
        );

        let params = arrive(&harness, &uri).await;
        let grant = grant(&harness, &params["code"]).await;
        assert_eq!(grant.user_subject, subject(&harness, "riley"));
        assert_eq!(
            grant.shared_claims,
            names(&["beneficiary_account_au", "over18"])
        );
        let record = harness.state.store.consent(&grant.txn).await.unwrap();
        assert_eq!(record.unwrap().declined, ["given_name"]);
    }

    #[tokio::test]
    async fn voluntary_claims_can_be_all_none_or_named_by_subject() {
        let harness = Harness::ci(0);

        // Present but empty: none of them. Essential claims are still shared.
        let uri = harness.push(&request()).await;
        let (_, body) = plan(&harness, &[("request_uri", &uri), ("voluntary_claims", "")]).await;
        assert_eq!(body["claims"], json!(["beneficiary_account_au"]));
        assert_eq!(body["declined"], json!(["given_name", "over18"]));
        let params = arrive(&harness, &uri).await;
        let shared = grant(&harness, &params["code"]).await.shared_claims;
        assert_eq!(shared, names(&["beneficiary_account_au"]));

        // Absent: all of them. The user can be named by subject too.
        let uri = harness.push(&request()).await;
        let sam = subject(&harness, "sam");
        let (_, body) = plan(&harness, &[("request_uri", &uri), ("user", &sam)]).await;
        assert_eq!(body["user"], "sam");
        assert_eq!(body["declined"], json!([]));
        let params = arrive(&harness, &uri).await;
        let grant = grant(&harness, &params["code"]).await;
        assert_eq!(grant.user_subject, sam);
        assert_eq!(grant.shared_claims.len(), 3);
    }

    #[tokio::test]
    async fn an_abandoned_visit_gets_a_page_and_leaves_the_request_pending() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;
        let (status, body) = plan(&harness, &[("request_uri", &uri), ("outcome", "abandon")]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"request_uri": uri, "outcome": "abandon"}));

        let response = harness.get(None, &authorize_path(&uri)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        let html = crate::http::test_support::body_text(response).await;
        assert!(html.contains("id=\"abandoned\""), "{html}");

        // That was for one visit. The next is answered.
        let params = arrive(&harness, &uri).await;
        assert!(params.contains_key("code"));

        let uri = harness.push(&request()).await;
        let (status, _) = plan(
            &harness,
            &[
                ("request_uri", &uri),
                ("outcome", "abandon"),
                ("user", "demo"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_last_response_chosen_wins() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;
        plan(&harness, &[("request_uri", &uri), ("outcome", "error")]).await;
        let (status, _) = plan(&harness, &[("request_uri", &uri), ("user", "margaret")]).await;
        assert_eq!(status, StatusCode::OK);
        let params = arrive(&harness, &uri).await;
        let grant = grant(&harness, &params["code"]).await;
        assert_eq!(grant.user_subject, subject(&harness, "margaret"));
    }

    #[tokio::test]
    async fn the_client_must_authenticate_as_it_does_to_push() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;

        let response = harness
            .post_form(Some(CERT), PATH_CI_RESPONSE, &[("request_uri", &uri)])
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");

        // An assertion is good for one call (replay protection).
        let assertion = harness.assertion();
        let fields = [
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
            ("request_uri", uri.as_str()),
        ];
        let first = harness
            .post_form(Some(CERT), PATH_CI_RESPONSE, &fields)
            .await;
        assert_eq!(first.status(), StatusCode::OK);
        let replay = harness
            .post_form(Some(CERT), PATH_CI_RESPONSE, &fields)
            .await;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn only_a_pending_request_can_be_given_a_response() {
        let harness = Harness::ci(0);
        let expect_refused = |(status, body): (StatusCode, Value)| {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], "invalid_request");
        };

        expect_refused(plan(&harness, &[]).await);
        let unknown = format!("{}nope", crate::store::REQUEST_URI_PREFIX);
        expect_refused(plan(&harness, &[("request_uri", &unknown)]).await);

        // Already answered.
        let uri = harness.push(&request()).await;
        arrive(&harness, &uri).await;
        expect_refused(plan(&harness, &[("request_uri", &uri)]).await);

        // Expired before any browser arrived.
        let uri = harness.push(&request()).await;
        harness
            .clock
            .advance(harness.state.security.request_uri_ttl);
        expect_refused(plan(&harness, &[("request_uri", &uri)]).await);

        // Pushed by another client.
        let uri = harness.push(&request()).await;
        let other = crate::client::test_support::client_with_key(
            "other",
            crate::keys::test_support::shared_key(),
        );
        let now = harness.state.now();
        assert!(
            super::pending_request(&harness.state, &other, &uri, now)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_response_that_cannot_be_given_is_refused() {
        let harness = Harness::ci(0);
        let uri = harness.push(&request()).await;
        let cases: &[&[(&str, &str)]] = &[
            &[("outcome", "maybe")],
            &[("user", "nobody")],
            // Essential, so not the client's to leave out or to name.
            &[("voluntary_claims", "beneficiary_account_au")],
            // Not requested.
            &[("voluntary_claims", "given_name email")],
            &[("outcome", "error"), ("error", "invalid_grant")],
            &[("outcome", "error"), ("error_description", "say \"no\"")],
            // Parameters of the other outcome.
            &[("outcome", "error"), ("user", "demo")],
            &[("outcome", "error"), ("voluntary_claims", "")],
            &[("error", "access_denied")],
            &[("outcome", "success"), ("error_description", "no")],
        ];
        for case in cases {
            let mut fields = vec![("request_uri", uri.as_str())];
            fields.extend_from_slice(case);
            let (status, body) = plan(&harness, &fields).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case:?}: {body}");
            assert_eq!(body["error"], "invalid_request", "{case:?}");
        }
        // Nothing was set by any of them.
        let now = harness.state.now();
        let planned = harness.state.store.planned_response(&uri, now).await;
        assert_eq!(planned.unwrap(), None);
    }

    #[tokio::test]
    async fn the_options_list_users_and_errors() {
        let harness = Harness::ci(0);
        let response = harness.get(None, PATH_CI).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["response_endpoint"],
            "https://op.example.com/ci/response"
        );
        assert_eq!(body["response_delay"], 0);
        assert_eq!(body["default_user"], "demo");
        let users: Vec<&str> = body["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["username"].as_str().unwrap())
            .collect();
        assert_eq!(users, ["demo", "riley", "margaret", "sam"]);
        let errors = body["errors"].as_array().unwrap();
        assert_eq!(errors[0]["error"], "access_denied");
        assert_eq!(errors.len(), crate::experience::ERROR_CONDITIONS.len());
    }

    #[tokio::test]
    async fn the_endpoints_exist_only_under_the_ci_experience() {
        for kind in [
            crate::experience::Kind::Login,
            crate::experience::Kind::Technical,
        ] {
            let harness = Harness::with_experience(kind);
            let uri = harness.push(&request()).await;
            let response = harness
                .post_form(Some(CERT), PATH_CI_RESPONSE, &[("request_uri", &uri)])
                .await;
            let status = response.status();
            assert_eq!(status, StatusCode::NOT_FOUND);
            let options = harness.get(None, PATH_CI).await;
            assert_eq!(options.status(), StatusCode::NOT_FOUND);
        }
    }
}
