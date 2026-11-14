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
