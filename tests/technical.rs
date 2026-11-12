//! The `technical` experience, end to end against a running instance.

mod common;

use std::collections::HashMap;

use common::{CLIENT_ID, LoginPage, Pkce, REDIRECT_URI, TestOp, redirect_params};
use oxid::experience::Kind;
use reqwest::header::{COOKIE, SET_COOKIE};
use reqwest::{Response, StatusCode};
use serde_json::{Value, json};

const MARGARET: &str = "demo-user-0003";
const RILEY: &str = "demo-user-0002";
const SAM: &str = "demo-user-0004";

async fn start() -> TestOp {
    TestOp::start_with(|config| config.experience = Kind::Technical).await
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}

/// The value of the form field `name` on a page.
fn field(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let value = html
        .split(&marker)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no field {name} in {html}"));
    unescape(value)
}

/// The text of the element with `id`, for elements without nested tags.
fn text_of(html: &str, id: &str) -> String {
    let marker = format!("id=\"{id}\"");
    let rest = html
        .split(&marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no element {id} in {html}"));
    let rest = &rest[rest.find('>').unwrap() + 1..];
    unescape(&rest[..rest.find('<').unwrap()])
}

/// The subject of the customer selected in the page's customer list.
fn selected_customer(html: &str) -> String {
    let select = html.split("<select id=\"customer\"").nth(1).unwrap();
    let select = &select[..select.find("</select>").unwrap()];
    let option = select
        .split("<option value=\"")
        .skip(1)
        .find(|option| option.split('>').next().unwrap().contains(" selected"))
        .expect("an option is selected");
    unescape(option.split('"').next().unwrap())
}

/// Post the experience's form with `fields`.
async fn submit(
    op: &TestOp,
    page: &LoginPage,
    request_uri: &str,
    fields: &[(&str, &str)],
) -> Response {
    let mut form: Vec<(&str, &str)> = vec![
        ("csrf", &page.csrf),
        ("client_id", CLIENT_ID),
        ("request_uri", request_uri),
    ];
    form.extend_from_slice(fields);
    op.browser
        .post(op.url("/authorize/decision"))
        .header(COOKIE, &page.cookie)
        .form(&form)
        .send()
        .await
        .unwrap()
}

/// Exchange the code in a redirect and return the verified ID token claims.
async fn id_token_claims(
    op: &TestOp,
    params: &HashMap<String, String>,
    pkce: &Pkce,
) -> serde_json::Map<String, Value> {
    let response = op.exchange(&params["code"], pkce).await;
    let status = response.status();
    let tokens: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{tokens}");
    op.verify_id_token(tokens["id_token"].as_str().unwrap())
        .await
}

fn identity_request() -> Value {
    json!({
        "purpose": "Checking <your> identity & age",
        "claims": {"id_token": {
            "given_name": {"essential": true},
            "family_name": null,
            "birthdate": null,
            "verified_claims": {
                "verification": {"trust_framework": {"value": "au_connectid"}},
                "claims": {"over18": null, "over65": null},
            },
        }},
    })
}

#[tokio::test]
async fn request_page_shows_the_request_decoded_and_in_its_original_form() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_object = op.request_object(&pkce, &identity_request());
    let body: Value = op.par(&request_object).await.json().await.unwrap();
    let request_uri = body["request_uri"].as_str().unwrap();

    let page = op.open_login(request_uri).await;
    let html = &page.html;
    assert!(html.contains("id=\"technical-banner\""));
    assert!(!html.contains("id=\"password\""), "there is no sign-in");

    // Decoded by default: header and payload as readable JSON.
    let header: Value = serde_json::from_str(&text_of(html, "request-header")).unwrap();
    assert_eq!(header["alg"], "PS256");
    let payload: Value = serde_json::from_str(&text_of(html, "request-payload")).unwrap();
    assert_eq!(payload["client_id"], CLIENT_ID);
    assert_eq!(payload["redirect_uri"], REDIRECT_URI);
    assert_eq!(payload["code_challenge"], pkce.challenge);
    assert_eq!(payload["purpose"], "Checking <your> identity & age");
    assert_eq!(
        payload["claims"]["id_token"]["given_name"]["essential"],
        true
    );

    // The original JWT is available on demand, byte for byte.
    assert!(html.contains("<details id=\"request-original\">"));
    assert_eq!(text_of(html, "request-encoded"), request_object);

    // Purpose is escaped wherever it is shown.
    assert_eq!(text_of(html, "purpose"), "Checking <your> identity & age");
    assert!(!html.contains("<your>"));

    // Every predefined customer is offered, with their attributes.
    for (subject, label) in [
        ("demo-user-0001", "Alex Jordan Citizen (demo)"),
        (RILEY, "Riley Young (riley)"),
        (MARGARET, "Margaret Elder (margaret)"),
        (SAM, "Sam Lee (sam)"),
    ] {
        assert!(
            html.contains(&format!("<option value=\"{subject}\"")),
            "{subject}"
        );
        assert!(html.contains(label), "{label}");
        assert!(html.contains(&format!("data-customer=\"{subject}\"")));
    }
    assert_eq!(
        selected_customer(html),
        "demo-user-0001",
        "first by default"
    );
    assert!(
        html.contains("margaret.elder@example.com"),
        "attributes are shown"
    );

    // Success and each predefined error can be chosen.
    assert!(html.contains("<option value=\"success\" selected>"));
    for code in [
        "access_denied",
        "login_required",
        "consent_required",
        "interaction_required",
        "account_selection_required",
        "invalid_request",
        "invalid_scope",
        "unauthorized_client",
        "server_error",
        "temporarily_unavailable",
    ] {
        assert!(
            html.contains(&format!("<option value=\"{code}\"")),
            "{code}"
        );
    }
    op.stop().await;
}

#[tokio::test]
async fn success_can_be_sent_immediately_for_the_selected_customer() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &identity_request()).await;
    let page = op.open_login(&request_uri).await;
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", RILEY),
            ("outcome", "success"),
            ("action", "approve"),
        ],
    )
    .await;
    let params = redirect_params(&response);
    assert!(params.contains_key("code") && !params.contains_key("error"));
    assert_eq!(params["iss"], op.issuer);

    let claims = id_token_claims(&op, &params, &pkce).await;
    assert_eq!(claims["given_name"], "Riley");
    assert_eq!(claims["family_name"], "Young");
    assert_eq!(
        claims["verified_claims"]["claims"],
        json!({"over18": false, "over65": false})
    );
    // The transaction is recorded like any other.
    let record = op
        .state()
        .store
        .consent(claims["txn"].as_str().unwrap())
        .unwrap();
    assert_eq!(record.user_subject.as_deref(), Some(RILEY));
    assert_eq!(
        record.purpose.as_deref(),
        Some("Checking <your> identity & age")
    );
    op.stop().await;
}

#[tokio::test]
async fn response_is_previewed_and_can_be_edited_before_it_is_sent() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &identity_request()).await;
    let page = op.open_login(&request_uri).await;

    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", MARGARET),
            ("outcome", "success"),
            ("action", "preview"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.unwrap();
    assert_eq!(text_of(&html, "customer-name"), "Margaret Elder (margaret)");
    assert_eq!(text_of(&html, "redirect-uri"), REDIRECT_URI);
    assert_eq!(text_of(&html, "iss"), op.issuer);

    // The anticipated ID token payload, as JSON, before signing.
    let shown = text_of(&html, "id_token");
    let preview: Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(preview["iss"], op.issuer);
    assert_eq!(preview["aud"], CLIENT_ID);
    assert_eq!(preview["given_name"], "Margaret");
    assert_eq!(preview["family_name"], "Elder");
    assert_eq!(preview["birthdate"], "1950-02-03");
    assert_eq!(
        preview["verified_claims"]["claims"],
        json!({"over18": true, "over65": true})
    );
    assert_eq!(preview["at_hash"], "(set when the access token is issued)");
    assert_eq!(preview["nonce"], "nonce-456");
    let previewed_txn = preview["txn"].as_str().unwrap().to_owned();
    let previewed_sub = preview["sub"].as_str().unwrap().to_owned();
    assert_ne!(previewed_sub, MARGARET, "sub is pairwise");

    // Change a value, add a claim, remove a claim; leave the rest alone.
    let mut edited = preview.clone();
    edited["given_name"] = json!("Maggie");
    edited["custom_claim"] = json!({"injected": [1, 2, 3]});
    edited["verified_claims"]["claims"]["over18"] = json!(false);
    edited.as_object_mut().unwrap().remove("family_name");
    let edited_text = serde_json::to_string_pretty(&edited).unwrap();

    op.clock.advance(5);
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", &field(&html, "customer")),
            ("outcome", "success"),
            ("txn", &field(&html, "txn")),
            ("base", &field(&html, "base")),
            ("id_token", &edited_text),
            ("action", "send"),
        ],
    )
    .await;
    let params = redirect_params(&response);
    let claims = id_token_claims(&op, &params, &pkce).await;

    assert_eq!(claims["given_name"], "Maggie");
    assert_eq!(claims["custom_claim"], json!({"injected": [1, 2, 3]}));
    assert_eq!(
        claims["verified_claims"]["claims"],
        json!({"over18": false, "over65": true})
    );
    assert!(!claims.contains_key("family_name"));
    // Untouched claims carry real values.
    assert_eq!(claims["birthdate"], "1950-02-03");
    assert_eq!(claims["sub"], previewed_sub);
    assert_eq!(
        claims["txn"], previewed_txn,
        "the txn that was shown is used"
    );
    assert_eq!(claims["nonce"], "nonce-456");
    assert_eq!(
        claims["iat"],
        op.now(),
        "iat is the time of issue, not of preview"
    );
    let at_hash = claims["at_hash"].as_str().unwrap();
    assert_eq!(at_hash.len(), 22, "a real at_hash replaced the placeholder");
    op.stop().await;
}

#[tokio::test]
async fn protocol_claims_can_be_overridden_for_negative_testing() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let html = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", SAM),
            ("outcome", "success"),
            ("action", "preview"),
        ],
    )
    .await
    .text()
    .await
    .unwrap();
    let mut edited: Value = serde_json::from_str(&text_of(&html, "id_token")).unwrap();
    edited["iss"] = json!("https://wrong-issuer.example.com");
    edited["exp"] = json!(1);
    edited["at_hash"] = json!("deliberately-wrong");
    edited.as_object_mut().unwrap().remove("nonce");

    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", SAM),
            ("txn", &field(&html, "txn")),
            ("base", &field(&html, "base")),
            ("id_token", &edited.to_string()),
            ("action", "send"),
        ],
    )
    .await;
    let params = redirect_params(&response);
    let tokens: Value = op
        .exchange(&params["code"], &pkce)
        .await
        .json()
        .await
        .unwrap();
    // The token is still properly signed; only its content is as edited.
    let jwks = op
        .browser
        .get(op.url("/jwks"))
        .send()
        .await
        .unwrap()
        .json::<jsonwebtoken::jwk::JwkSet>()
        .await
        .unwrap();
    let jws = oxid::jose::Jws::parse(
        tokens["id_token"].as_str().unwrap(),
        &[oxid::jose::SigningAlg::PS256],
    )
    .unwrap();
    jws.verify(&jwks).unwrap();
    assert_eq!(
        jws.str_claim("iss"),
        Some("https://wrong-issuer.example.com")
    );
    assert_eq!(jws.claims["exp"], 1);
    assert_eq!(jws.str_claim("at_hash"), Some("deliberately-wrong"));
    assert!(!jws.claims.contains_key("nonce"));
    op.stop().await;
}

#[tokio::test]
async fn invalid_json_is_reported_and_the_text_is_kept() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let html = submit(
        &op,
        &page,
        &request_uri,
        &[("customer", SAM), ("action", "preview")],
    )
    .await
    .text()
    .await
    .unwrap();
    let txn = field(&html, "txn");
    let base = field(&html, "base");

    for (bad, message) in [
        ("{\"sub\": <oops>", "not valid JSON"),
        ("[1, 2]", "must be a JSON object"),
        ("", "not valid JSON"),
    ] {
        let response = submit(
            &op,
            &page,
            &request_uri,
            &[
                ("customer", SAM),
                ("txn", &txn),
                ("base", &base),
                ("id_token", bad),
                ("action", "send"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{bad}");
        let html = response.text().await.unwrap();
        assert!(text_of(&html, "error").contains(message), "{bad}");
        assert_eq!(
            text_of(&html, "id_token"),
            bad,
            "the text is kept for fixing"
        );
        assert_eq!(field(&html, "txn"), txn);
    }

    // Nothing was consumed: the corrected response can still be sent.
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", SAM),
            ("txn", &txn),
            ("base", &base),
            ("id_token", &base),
            ("action", "send"),
        ],
    )
    .await;
    let claims = id_token_claims(&op, &redirect_params(&response), &pkce).await;
    assert_eq!(claims["txn"], txn);
    op.stop().await;
}

#[tokio::test]
async fn last_customer_used_is_preselected_on_the_next_flow() {
    let op = start().await;
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[("customer", MARGARET), ("action", "approve")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let remembered = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .find(|cookie| cookie.starts_with("__Host-oxid-customer="))
        .expect("the customer is remembered");
    assert!(remembered.contains("Secure") && remembered.contains("HttpOnly"));
    assert!(remembered.contains("Max-Age="));
    let cookie = remembered.split(';').next().unwrap().to_owned();

    // A later flow from the same browser.
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let html = op
        .browser
        .get(op.authorize_url(&request_uri))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(selected_customer(&html), MARGARET);

    // A browser without the cookie, or with a stale one, gets the first.
    let page = op.open_login(&request_uri).await;
    assert_eq!(selected_customer(&page.html), "demo-user-0001");
    let html = op
        .browser
        .get(op.authorize_url(&request_uri))
        .header(COOKIE, "__Host-oxid-customer=bm8tc3VjaC11c2Vy")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(selected_customer(&html), "demo-user-0001");
    op.stop().await;
}

#[tokio::test]
async fn predefined_errors_can_be_returned_instead_of_a_code() {
    let op = start().await;
    for code in [
        "access_denied",
        "login_required",
        "consent_required",
        "interaction_required",
        "account_selection_required",
        "invalid_request",
        "invalid_scope",
        "unauthorized_client",
        "server_error",
        "temporarily_unavailable",
    ] {
        let request_uri = op.push(&Pkce::new(), &json!({})).await;
        let page = op.open_login(&request_uri).await;
        let response = submit(
            &op,
            &page,
            &request_uri,
            &[("customer", SAM), ("outcome", code), ("action", "preview")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{code}");
        let html = response.text().await.unwrap();
        assert_eq!(text_of(&html, "error-code"), code);
        assert_eq!(text_of(&html, "state"), "state-123");
        let default_description = field(&html, "error_description");
        assert_ne!(default_description, "");

        let response = submit(
            &op,
            &page,
            &request_uri,
            &[
                ("outcome", code),
                ("error_description", "simulated for testing"),
                ("action", "send_error"),
            ],
        )
        .await;
        let params = redirect_params(&response);
        assert_eq!(params["error"], code);
        assert_eq!(params["error_description"], "simulated for testing");
        assert_eq!(params["state"], "state-123");
        assert_eq!(params["iss"], op.issuer);
        assert!(!params.contains_key("code"), "{code}");

        // The request is spent: it cannot be turned into a success after.
        let again = submit(
            &op,
            &page,
            &request_uri,
            &[("customer", SAM), ("action", "approve")],
        )
        .await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "{code}");
    }
    op.stop().await;
}

#[tokio::test]
async fn access_denied_can_be_sent_immediately() {
    let op = start().await;
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let response = submit(&op, &page, &request_uri, &[("action", "deny")]).await;
    let params = redirect_params(&response);
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["error_description"], "the user denied the request");
    assert!(
        response.headers().get(SET_COOKIE).is_none(),
        "no customer was used, so none is remembered"
    );
    op.stop().await;
}

#[tokio::test]
async fn bad_selections_return_to_the_request_page() {
    let op = start().await;
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    for fields in [
        vec![("customer", "nobody"), ("action", "approve")],
        vec![("customer", "nobody"), ("action", "preview")],
        vec![
            ("customer", SAM),
            ("outcome", "made_up"),
            ("action", "preview"),
        ],
        vec![("outcome", "made_up"), ("action", "send_error")],
        vec![
            ("customer", SAM),
            ("txn", "x"),
            ("base", "{}"),
            ("action", "send"),
        ],
        vec![("customer", SAM), ("action", "send")],
    ] {
        let response = submit(&op, &page, &request_uri, &fields).await;
        assert_eq!(response.status(), StatusCode::OK, "{fields:?}");
        let html = response.text().await.unwrap();
        assert!(html.contains("id=\"error\""), "{fields:?}");
        assert!(html.contains("id=\"request-payload\""), "{fields:?}");
    }
    // "Back" returns to the request page keeping the selections.
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", RILEY),
            ("outcome", "login_required"),
            ("action", "back"),
        ],
    )
    .await;
    let html = response.text().await.unwrap();
    assert_eq!(selected_customer(&html), RILEY);
    assert!(html.contains("<option value=\"login_required\" selected>"));
    assert!(!html.contains("id=\"error\""));
    op.stop().await;
}

#[tokio::test]
async fn csrf_protection_applies_to_the_technical_forms() {
    let op = start().await;
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let response = op
        .browser
        .post(op.url("/authorize/decision"))
        .form(&[
            ("csrf", page.csrf.as_str()),
            ("client_id", CLIENT_ID),
            ("request_uri", &request_uri),
            ("customer", SAM),
            ("action", "approve"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    op.stop().await;
}
