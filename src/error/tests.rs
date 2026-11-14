use super::*;

#[test]
fn status_codes_follow_rfc_6749() {
    assert_eq!(ErrorCode::InvalidClient.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(ErrorCode::InvalidGrant.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        ErrorCode::InvalidRequestObject.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ErrorCode::ServerError.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn response_is_uncacheable_json() {
    let response = OAuthError::invalid_grant("code expired").into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
}

#[test]
fn server_error_hides_detail() {
    let err = OAuthError::server_error("database password is hunter2");
    assert_eq!(err.description, "internal server error");
}

#[test]
fn display_includes_code_and_description() {
    assert_eq!(
        OAuthError::invalid_scope("nope").to_string(),
        "invalid_scope: nope"
    );
}

#[test]
fn server_error_keeps_its_cause_for_the_log_only() {
    let store = crate::store::StoreError::Corrupt("bad json".into());
    let err = OAuthError::server_error(store);
    // The cause chain is there for the log line...
    let cause = std::error::Error::source(&err).unwrap();
    assert_eq!(
        Report(cause).to_string(),
        "a stored item is corrupt: bad json"
    );
    // ...and the client sees only the generic error.
    assert_eq!(err, OAuthError::new(ErrorCode::ServerError, "internal server error"));
    assert_eq!(err.to_string(), "server_error: internal server error");
}
