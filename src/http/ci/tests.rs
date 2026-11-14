use crate::epoch::Seconds;
use std::time::Duration;

use crate::testing::html::has_id;
use axum::body::Body;
use axum::http::{Response, StatusCode, header};
use serde_json::{Value, json};
use url::Url;

use crate::client_auth::ASSERTION_TYPE;
use crate::http::{PATH_CI, PATH_CI_RESPONSE};
use crate::store::{CodeRedemption, ConsentOutcome, Grant};
use crate::testing::http::authorize_path;
use crate::testing::http::{CERT, Harness, json_body};

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
    let harness = Harness::ci(Seconds::new(0));
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
    let harness = Harness::ci(Seconds::new(5));
    let uri = harness.push(&request()).await;
    let started = tokio::time::Instant::now();
    let params = arrive(&harness, &uri).await;
    assert!(params.contains_key("code"));
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(6));
}

#[tokio::test(start_paused = true)]
async fn the_delay_runs_from_the_first_arrival() {
    let harness = Harness::ci(Seconds::new(5));
    let uri = harness.push(&request()).await;
    // A browser arrived three seconds ago and went away without waiting.
    let now = harness.state.now();
    harness.state.store.arrive(&uri, now).await.unwrap();
    harness.clock.advance(Seconds::new(3));

    let started = tokio::time::Instant::now();
    assert!(arrive(&harness, &uri).await.contains_key("code"));
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn a_response_chosen_during_the_wait_is_given_at_once() {
    let harness = Harness::ci(Seconds::new(5));
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
    let harness = Harness::ci(Seconds::new(5));
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
    let harness = Harness::ci(Seconds::new(0));
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
    let harness = Harness::ci(Seconds::new(0));
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
    let harness = Harness::ci(Seconds::new(0));

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
    let harness = Harness::ci(Seconds::new(0));
    let uri = harness.push(&request()).await;
    let (status, body) = plan(&harness, &[("request_uri", &uri), ("outcome", "abandon")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"request_uri": uri, "outcome": "abandon"}));

    let response = harness.get(None, &authorize_path(&uri)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::LOCATION));
    let html = crate::testing::http::body_text(response).await;
    assert!(has_id(&html, "abandoned"), "{html}");

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
    let harness = Harness::ci(Seconds::new(0));
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
    let harness = Harness::ci(Seconds::new(0));
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
    let harness = Harness::ci(Seconds::new(0));
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
    let other = crate::testing::client_with_key("other", crate::testing::shared_key());
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
    let harness = Harness::ci(Seconds::new(0));
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
    let harness = Harness::ci(Seconds::new(0));
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

#[tokio::test]
async fn an_experience_that_fails_sends_the_browser_back_with_server_error() {
    let harness = Harness::ci(Seconds::new(0));
    let uri = harness.push(&request()).await;
    // A stored choice naming a user who does not exist: the experience
    // cannot answer, and says so with an error rather than a decision.
    let plan = crate::store::PlannedResponse::Success {
        user_subject: "nobody-by-this-name".to_owned(),
        shared_claims: names(&[]),
        declined: Vec::new(),
    };
    harness
        .state
        .store
        .plan_response(&uri, &plan, harness.state.now() + Seconds::new(60))
        .await
        .unwrap();
    let params = arrive(&harness, &uri).await;
    assert_eq!(params["error"], "server_error");
    assert_eq!(params["error_description"], "internal server error");
    assert_eq!(params["state"], "s-1");
}
