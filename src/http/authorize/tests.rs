
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
    // They are logging in to see the request, not to reach the client.
    assert!(html.contains("Log in to review this request:"));
    assert!(html.contains("is asking you to share some of your information."));
    assert!(html.contains("<strong id=\"client-name\">Test RP</strong>"));
    assert!(html.contains("id=\"username\"") && html.contains("id=\"password\""));
    assert!(html.contains("id=\"sign-in\"") && html.contains("id=\"deny\""));
    // Nothing about the request is shown before the user signs in.
    for hidden in ["checkout", "Given name", "data-claim", "Alex", "share_"] {
        assert!(!html.contains(hidden), "{hidden}");
    }
}

#[tokio::test]
async fn pages_carry_the_oxid_theme_in_light_and_dark_by_default() {
    let harness = Harness::new();
    let uri = harness.push(&json!({})).await;
    let response = harness.get(None, &authorize_path(&uri)).await;
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!policy.contains("img-src"), "nothing is loaded: {policy}");
    let html = body_text(response).await;
    assert!(html.contains("<title>Log in - oxID</title>"));
    assert!(html.contains("<i class=\"mark\"></i>") && html.contains("ox<b>ID</b>"));
    assert!(!html.contains("<img"));
    assert!(html.contains("Protected by oxID."));
    // Both palettes are on the page, and the browser picks one from the
    // user's system setting.
    assert!(html.contains("<meta name=\"color-scheme\" content=\"light dark\">"));
    let (light, dark) = html
        .split_once("@media (prefers-color-scheme: dark)")
        .expect("a dark palette");
    assert!(light.contains("--accent: #ff5630;") && light.contains("--surface: #ffffff;"));
    assert!(dark.contains("--accent: #ff6b4a;") && dark.contains("--surface: #161b27;"));
    // The styles use the palette, never a colour of their own.
    assert!(html.contains("background: var(--background);"));
}

fn acme() -> Theme {
    use crate::theme::{Logo, Palette};
    let logo = |bytes: &'static [u8]| Logo {
        content_type: "image/png",
        bytes: Bytes::from_static(bytes),
    };
    Theme {
        name: "Acme <Bank>".to_owned(),
        logo: Some(logo(b"light")),
        logo_dark: Some(logo(b"dark")),
        show_name: false,
        light: Palette {
            accent: "#0055ff".parse().unwrap(),
            ..Palette::light()
        },
        dark: Palette {
            accent: "#88aaff".parse().unwrap(),
            background: "#000".parse().unwrap(),
            ..Palette::dark()
        },
    }
}

#[tokio::test]
async fn a_theme_sets_the_name_logo_and_colours_of_every_page() {
    let harness = Harness::with_theme(acme());
    let uri = harness.push(&json!({})).await;
    let response = harness.get(None, &authorize_path(&uri)).await;
    assert!(
        response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("; img-src 'self'"),
        "the logo may be loaded"
    );
    let html = body_text(response).await;
    assert!(html.contains("<title>Log in - Acme &#60;Bank&#62;</title>"));
    assert!(html.contains("<h1>Log in to Acme &#60;Bank&#62;</h1>"));
    assert!(html.contains("Protected by Acme &#60;Bank&#62;."));
    assert!(
        html.contains(
            "<source srcset=\"/theme/logo-dark\" media=\"(prefers-color-scheme: dark)\">"
        )
    );
    // The logo stands in for the name, so it carries it as its text.
    assert!(html.contains("<img class=\"logo\" src=\"/theme/logo\" alt=\"Acme &#60;Bank&#62;\">"));
    assert!(!html.contains("class=\"name\"") && !html.contains("class=\"mark\""));
    let (light, dark) = html
        .split_once("@media (prefers-color-scheme: dark)")
        .unwrap();
    assert!(light.contains("--accent: #0055ff;") && light.contains("--text: #0e1320;"));
    assert!(dark.contains("--accent: #88aaff;") && dark.contains("--background: #000;"));

    // The consent page, and the pages the endpoint shows itself.
    let browser = sign_in(&harness, &uri).await;
    assert!(browser.html.contains("logged in with Acme &#60;Bank&#62;."));
    harness.clock.advance(harness.state.security.session_ttl);
    let expired = body_text(harness.get(None, &authorize_path(&uri)).await).await;
    let error = body_text(harness.get(None, PATH_AUTHORIZE).await).await;
    for html in [&browser.html, &expired, &error] {
        assert!(html.contains("--accent: #0055ff;"));
        assert!(html.contains("src=\"/theme/logo\""));
        assert!(!html.contains("oxID") && !html.contains("<Bank>"), "{html}");
    }
}

#[tokio::test]
async fn the_technical_experience_is_themed_too() {
    let theme = Theme {
        show_name: true,
        logo_dark: None,
        ..acme()
    };
    let harness = Harness::themed(crate::experience::Kind::Technical, theme);
    let uri = harness.push(&json!({})).await;
    let html = body_text(harness.get(None, &authorize_path(&uri)).await).await;
    assert!(html.contains("id=\"technical-banner\""));
    assert!(html.contains("--accent: #0055ff;") && html.contains("--accent: #88aaff;"));
    assert!(html.contains("<span class=\"name\">Acme &#60;Bank&#62;</span>"));
    // A logo beside the name is decoration, and has no dark variant here.
    assert!(html.contains("<img class=\"logo\" src=\"/theme/logo\" alt=\"\">"));
    assert!(!html.contains("<source") && !html.contains("oxID"));
}

#[tokio::test]
async fn consent_page_shows_client_purpose_and_each_claim_with_its_value() {
    let harness = Harness::new();
    let uri = harness.push(&everything_requested()).await;
    let browser = sign_in(&harness, &uri).await;
    let html = &browser.html;
    assert!(html.contains("Logged in as <strong>Alex Jordan Citizen</strong>"));
    // The purpose completes the sentence it was written for.
    assert!(
        html.contains(
            "<p><strong id=\"client-name\">Test RP</strong> is asking you to share your \
                 information for the purpose of</p>\n  \
                 <p id=\"purpose\" class=\"purpose\">Verify your &#60;age&#62; for checkout</p>"
        ),
        "purpose is shown, escaped"
    );
    // Each claim is listed with the value that would be shared.
    assert!(html.contains("<span class=\"value\" id=\"value-given_name\">Alex</span>"));
    assert!(html.contains("<span class=\"value\" id=\"value-over18\">Yes</span>"));
    assert!(html.contains("Bank account (BSB and account number)"));
    assert!(html.contains("<em>BSB:</em> 123456") && html.contains("12345678"));
    assert!(html.contains("<li data-claim=\"beneficiary_account_au\" data-essential=\"true\">"));
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
        crate::claims::ClaimsRequest::parse(&json!({"id_token": {"given_name": null}})).unwrap();
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
