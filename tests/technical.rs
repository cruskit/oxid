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

/// The page's data block, which its script reads.
fn page_data(html: &str) -> Value {
    let block = html
        .split("<script type=\"application/json\" id=\"oxid-data\">")
        .nth(1)
        .expect("data block");
    serde_json::from_str(&block[..block.find("</script>").unwrap()]).unwrap()
}

/// Send a success for `customer` using the claims on `html`, which must be
/// the page as rendered for that customer. `claims` replaces the editor's
/// text when given.
async fn send_success(
    op: &TestOp,
    page: &LoginPage,
    request_uri: &str,
    html: &str,
    customer: &str,
    claims: Option<&str>,
) -> Response {
    let shown = text_of(html, "id_token");
    submit(
        op,
        page,
        request_uri,
        &[
            ("customer", customer),
            ("outcome", "success"),
            ("txn", &field(html, "txn")),
            ("base", &field(html, "base")),
            ("base_customer", &field(html, "base_customer")),
            ("id_token", claims.unwrap_or(&shown)),
            ("action", "send"),
        ],
    )
    .await
}

/// The page as rendered for `customer`: what a browser without the script
/// gets after choosing them and pressing send.
async fn page_for(op: &TestOp, page: &LoginPage, request_uri: &str, customer: &str) -> String {
    let response = submit(
        op,
        page,
        request_uri,
        &[
            ("customer", customer),
            ("outcome", "success"),
            ("action", "send"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response.text().await.unwrap()
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
async fn one_page_shows_the_request_and_the_response_controls() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_object = op.request_object(&pkce, &identity_request());
    let body: Value = op.par(&request_object).await.json().await.unwrap();
    let request_uri = body["request_uri"].as_str().unwrap();

    let response = op
        .browser
        .get(op.authorize_url(request_uri))
        .send()
        .await
        .unwrap();
    // The page's script runs under a nonce; nothing else may.
    let csp = response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        csp.contains("default-src 'none'") && csp.contains("script-src 'nonce-"),
        "{csp}"
    );
    assert!(!csp.contains("unsafe-inline' 'nonce") && !csp.contains("script-src 'unsafe"));
    let page = LoginPage::from_response(response).await;
    let html = &page.html;
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    assert!(html.contains(&format!("<script nonce=\"{nonce}\">")));
    assert!(html.contains("id=\"technical-banner\""));
    assert!(!html.contains("id=\"password\""), "there is no sign-in");

    // Request, decoded by default: header and payload as readable JSON.
    assert!(html.contains("id=\"view-decoded\" checked"));
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
    // The original JWT is one click away, byte for byte.
    assert!(html.contains("id=\"view-original\""));
    assert_eq!(text_of(html, "request-encoded"), request_object);
    // Purpose is escaped wherever it is shown.
    assert_eq!(text_of(html, "purpose"), "Checking <your> identity & age");
    assert!(!html.contains("<your>"));

    // Response: every predefined customer, with their attributes.
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

    // The anticipated ID token payload for the selected customer is already
    // there to edit, and success is the default outcome.
    assert!(html.contains("id=\"outcome-success\" value=\"success\" checked"));
    assert!(!html.contains("id=\"outcome-error\" value=\"error\" checked"));
    let preview: Value = serde_json::from_str(&text_of(html, "id_token")).unwrap();
    assert_eq!(preview["given_name"], "Alex");
    assert_eq!(preview["at_hash"], "(set when the access token is issued)");
    assert_eq!(field(html, "base_customer"), "demo-user-0001");

    // Each predefined error can be chosen.
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

    // The script's data: every customer's claims, so switching customer
    // needs no round trip, all under one transaction identifier.
    let data = page_data(html);
    let previews = data["previews"].as_object().unwrap();
    assert_eq!(previews.len(), 4);
    let margaret: Value = serde_json::from_str(previews[MARGARET].as_str().unwrap()).unwrap();
    assert_eq!(margaret["given_name"], "Margaret");
    assert_eq!(margaret["txn"], preview["txn"]);
    assert_eq!(previews["demo-user-0001"], text_of(html, "id_token"));
    assert_eq!(
        data["errors"]["access_denied"],
        "the user denied the request"
    );
    assert_eq!(data["redirect_uri"], REDIRECT_URI);
    assert_eq!(data["issuer"], op.issuer);
    assert_eq!(data["remembered"], Value::Null);
    op.stop().await;
}

#[tokio::test]
async fn data_block_cannot_be_broken_out_of() {
    let op = start().await;
    let request_uri = op
        .push(
            &Pkce::new(),
            &json!({"state": "</script><script>alert(1)</script>", "nonce": "<!--"}),
        )
        .await;
    let page = op.open_login(&request_uri).await;
    assert!(!page.html.contains("</script><script>alert(1)"));
    assert!(!page.html.contains("<!--"));
    assert_eq!(
        page_data(&page.html)["state"],
        "</script><script>alert(1)</script>"
    );
    op.stop().await;
}

#[tokio::test]
async fn unedited_success_is_sent_for_the_selected_customer() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &identity_request()).await;
    let page = op.open_login(&request_uri).await;

    // As the script does it: take that customer's claims from the page data.
    let data = page_data(&page.html);
    let riley = data["previews"][RILEY].as_str().unwrap();
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("customer", RILEY),
            ("outcome", "success"),
            ("txn", &field(&page.html, "txn")),
            ("base", riley),
            ("base_customer", RILEY),
            ("id_token", riley),
            ("action", "send"),
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
    assert_eq!(claims["txn"], field(&page.html, "txn"));
    assert_eq!(claims["at_hash"].as_str().unwrap().len(), 22);
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
async fn changing_customer_without_script_regenerates_the_claims_first() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &identity_request()).await;
    let page = op.open_login(&request_uri).await;

    // The page was rendered for the first customer; a browser without the
    // script submits Margaret with the first customer's claims.
    let response = send_success(&op, &page, &request_uri, &page.html, MARGARET, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "nothing mismatched is sent"
    );
    let html = response.text().await.unwrap();
    assert!(text_of(&html, "notice").contains("regenerated for Margaret Elder"));
    assert_eq!(selected_customer(&html), MARGARET);
    assert_eq!(field(&html, "base_customer"), MARGARET);
    let preview: Value = serde_json::from_str(&text_of(&html, "id_token")).unwrap();
    assert_eq!(preview["given_name"], "Margaret");

    // Sending that page completes the flow for Margaret.
    let response = send_success(&op, &page, &request_uri, &html, MARGARET, None).await;
    let claims = id_token_claims(&op, &redirect_params(&response), &pkce).await;
    assert_eq!(claims["given_name"], "Margaret");
    op.stop().await;
}

#[tokio::test]
async fn response_can_be_edited_before_it_is_sent() {
    let op = start().await;
    let pkce = Pkce::new();
    let request_uri = op.push(&pkce, &identity_request()).await;
    let page = op.open_login(&request_uri).await;
    let html = page_for(&op, &page, &request_uri, MARGARET).await;

    // The anticipated ID token payload, as JSON, before signing.
    let preview: Value = serde_json::from_str(&text_of(&html, "id_token")).unwrap();
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
    let response = send_success(
        &op,
        &page,
        &request_uri,
        &html,
        MARGARET,
        Some(&edited_text),
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
    let html = page_for(&op, &page, &request_uri, SAM).await;
    let mut edited: Value = serde_json::from_str(&text_of(&html, "id_token")).unwrap();
    edited["iss"] = json!("https://wrong-issuer.example.com");
    edited["exp"] = json!(1);
    edited["at_hash"] = json!("deliberately-wrong");
    edited.as_object_mut().unwrap().remove("nonce");

    let response = send_success(
        &op,
        &page,
        &request_uri,
        &html,
        SAM,
        Some(&edited.to_string()),
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
    let first = page_for(&op, &page, &request_uri, SAM).await;
    let txn = field(&first, "txn");
    let base = field(&first, "base");

    for (bad, message) in [
        ("{\"sub\": <oops>", "not valid JSON"),
        ("[1, 2]", "must be a JSON object"),
        ("", "not valid JSON"),
    ] {
        let response = send_success(&op, &page, &request_uri, &first, SAM, Some(bad)).await;
        assert_eq!(response.status(), StatusCode::OK, "{bad}");
        let html = response.text().await.unwrap();
        assert!(text_of(&html, "error").contains(message), "{bad}");
        assert_eq!(
            text_of(&html, "id_token"),
            bad,
            "the text is kept for fixing"
        );
        assert_eq!(field(&html, "txn"), txn);
        assert_eq!(
            field(&html, "base"),
            base,
            "edits are still measured from the original"
        );
        assert_eq!(selected_customer(&html), SAM);
    }

    // Nothing was consumed: the corrected response can still be sent.
    let response = send_success(&op, &page, &request_uri, &first, SAM, None).await;
    let claims = id_token_claims(&op, &redirect_params(&response), &pkce).await;
    assert_eq!(claims["txn"], txn);
    op.stop().await;
}

#[tokio::test]
async fn last_customer_used_is_preselected_on_the_next_flow() {
    let op = start().await;
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    assert!(page.html.contains("id=\"remembered\" hidden"));
    let html = page_for(&op, &page, &request_uri, MARGARET).await;
    let response = send_success(&op, &page, &request_uri, &html, MARGARET, None).await;
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

    // A later flow from the same browser: Margaret and her claims are ready.
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
    assert_eq!(field(&html, "base_customer"), MARGARET);
    assert!(html.contains("id=\"remembered\">Used on your last flow"));
    assert_eq!(page_data(&html)["remembered"], MARGARET);
    let preview: Value = serde_json::from_str(&text_of(&html, "id_token")).unwrap();
    assert_eq!(preview["sub"].as_str().unwrap().len(), 43);

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
            &[
                ("customer", SAM),
                ("outcome", "error"),
                ("error", code),
                ("error_description", "simulated for testing"),
                ("action", "send"),
            ],
        )
        .await;
        let params = redirect_params(&response);
        assert_eq!(params["error"], code);
        assert_eq!(params["error_description"], "simulated for testing");
        assert_eq!(params["state"], "state-123");
        assert_eq!(params["iss"], op.issuer);
        assert!(!params.contains_key("code"), "{code}");
        assert!(
            response.headers().get(SET_COOKIE).is_none(),
            "no customer was used, so none is remembered"
        );

        // The request is spent: it cannot be turned into a success after.
        let again =
            send_success(&op, &page, &request_uri, &page.html, "demo-user-0001", None).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "{code}");
    }
    op.stop().await;
}

#[tokio::test]
async fn error_defaults_are_access_denied_with_its_description() {
    let op = start().await;
    // What the page posts if only the Error outcome is chosen.
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    assert_eq!(
        field(&page.html, "error_description"),
        "the user denied the request"
    );
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("outcome", "error"),
            ("error", "access_denied"),
            ("error_description", ""),
            ("action", "send"),
        ],
    )
    .await;
    let params = redirect_params(&response);
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["error_description"], "the user denied the request");
    op.stop().await;
}

#[tokio::test]
async fn bad_submissions_show_the_page_again() {
    let op = start().await;
    let request_uri = op.push(&Pkce::new(), &json!({})).await;
    let page = op.open_login(&request_uri).await;
    let base = field(&page.html, "base");
    for fields in [
        vec![("customer", "nobody"), ("action", "send")],
        vec![
            ("outcome", "error"),
            ("error", "made_up"),
            ("action", "send"),
        ],
        vec![("outcome", "error"), ("action", "send")],
        vec![("customer", SAM), ("action", "something-else")],
        vec![
            ("customer", SAM),
            ("base_customer", SAM),
            ("txn", "not-a-uuid"),
            ("base", &base),
            ("id_token", &base),
            ("action", "send"),
        ],
        vec![
            ("customer", SAM),
            ("base_customer", SAM),
            ("txn", "9f00df0c-ce59-4b91-a2b5-e22913c41432"),
            ("base", "not json"),
            ("id_token", "{}"),
            ("action", "send"),
        ],
    ] {
        let response = submit(&op, &page, &request_uri, &fields).await;
        assert_eq!(response.status(), StatusCode::OK, "{fields:?}");
        let html = response.text().await.unwrap();
        assert!(html.contains("id=\"error\""), "{fields:?}");
        assert!(html.contains("id=\"request-payload\""), "{fields:?}");
        assert!(html.contains("id=\"id_token\""), "{fields:?}");
    }
    // The error outcome stays selected when the page comes back.
    let response = submit(
        &op,
        &page,
        &request_uri,
        &[
            ("outcome", "error"),
            ("error", "made_up"),
            ("action", "send"),
        ],
    )
    .await;
    let html = response.text().await.unwrap();
    assert!(html.contains("id=\"outcome-error\" value=\"error\" checked"));
    op.stop().await;
}

#[tokio::test]
async fn csrf_protection_applies_to_the_technical_form() {
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
            ("outcome", "error"),
            ("error", "access_denied"),
            ("action", "send"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    op.stop().await;
}
