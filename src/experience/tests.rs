use axum::http::HeaderValue;
use axum::http::header;

use super::*;

#[test]
fn kinds_parse_from_their_configuration_names() {
    for kind in Kind::ALL {
        assert_eq!(kind.as_str().parse::<Kind>().unwrap(), *kind);
        assert_eq!(kind.to_string(), kind.as_str());
        let from_toml: Kind = serde_json::from_value(serde_json::json!(kind.as_str())).unwrap();
        assert_eq!(from_toml, *kind);
    }
    let err = "wizard".parse::<Kind>().unwrap_err();
    assert!(
        err.contains("technical") && err.contains("login") && err.contains("ci"),
        "{err}"
    );
}

#[test]
fn technical_is_the_default_experience() {
    assert_eq!(Kind::default(), Kind::Technical);
}

#[test]
fn cookie_parsing_finds_the_named_cookie() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("a=1; __Host-oxid-csrf=tok; b=2"),
    );
    assert_eq!(cookie(&headers, "__Host-oxid-csrf"), Some("tok"));
    assert_eq!(cookie(&headers, "a"), Some("1"));
    assert_eq!(cookie(&headers, "missing"), None);
}

#[test]
fn durations_read_naturally() {
    assert_eq!(duration_text(300), "5 minutes");
    assert_eq!(duration_text(60), "1 minute");
    assert_eq!(duration_text(90), "90 seconds");
}

#[test]
fn host_cookies_are_secure_and_origin_bound() {
    let session = host_cookie("__Host-x", "v", None);
    assert_eq!(
        session,
        "__Host-x=v; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
    assert!(host_cookie("__Host-x", "v", Some(60)).ends_with("; Max-Age=60"));
}
