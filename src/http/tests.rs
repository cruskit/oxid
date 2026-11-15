use axum::body::Body;
use axum::http::{Request, StatusCode};

use super::*;
use crate::testing::http::Harness;

#[test]
fn params_reject_duplicates_and_treat_empty_as_absent() {
    let params = Params::parse(b"a=1&b=&c=x%20y").unwrap();
    assert_eq!(params.get("a"), Some("1"));
    assert_eq!(params.get("b"), None);
    assert_eq!(params.get("c"), Some("x y"));
    assert_eq!(params.get("missing"), None);
    assert!(Params::parse(b"a=1&a=2").is_err());
}

#[test]
fn interaction_id_validation() {
    assert!(is_valid_interaction_id(
        "c770aef3-6784-41f7-8e0e-ff5f97bddb3a"
    ));
    assert!(!is_valid_interaction_id(""));
    assert!(!is_valid_interaction_id("has space"));
    assert!(!is_valid_interaction_id("line\nbreak"));
    assert!(!is_valid_interaction_id(&"a".repeat(129)));
}

#[tokio::test]
async fn interaction_id_is_echoed_or_generated() {
    let harness = Harness::new();
    let request = Request::get(PATH_HEALTH)
        .header(
            &X_FAPI_INTERACTION_ID,
            "c770aef3-6784-41f7-8e0e-ff5f97bddb3a",
        )
        .body(Body::empty())
        .unwrap();
    let response = harness.send(None, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[&X_FAPI_INTERACTION_ID],
        "c770aef3-6784-41f7-8e0e-ff5f97bddb3a"
    );

    let generated = harness.get(None, PATH_HEALTH).await;
    let id = generated.headers()[&X_FAPI_INTERACTION_ID]
        .to_str()
        .unwrap();
    assert!(Uuid::parse_str(id).is_ok(), "{id}");
}

#[tokio::test]
async fn security_headers_are_set_on_every_response() {
    let response = Harness::new().get(None, "/does-not-exist").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let headers = response.headers();
    assert!(
        headers[header::STRICT_TRANSPORT_SECURITY]
            .to_str()
            .unwrap()
            .contains("max-age=")
    );
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert!(headers.contains_key(&X_FAPI_INTERACTION_ID));
}

#[tokio::test]
async fn non_form_bodies_get_an_oauth_error() {
    let harness = Harness::new();
    let request = Request::post(PATH_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = harness.send(None, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        crate::testing::http::json_body(response).await["error"],
        "invalid_request"
    );
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let harness = Harness::new();
    let big = "a".repeat(MAX_BODY_BYTES + 1);
    let response = harness.post_form(None, PATH_TOKEN, &[("x", &big)]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
