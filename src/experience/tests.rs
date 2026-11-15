use axum::http::HeaderValue;
use axum::http::header;

use super::*;
use axum::http::HeaderMap;
use crate::epoch::Seconds;

#[test]
fn kinds_parse_from_their_configuration_names() {
    for kind in Kind::ALL {
        assert_eq!(kind.as_str().parse::<Kind>().unwrap(), *kind);
        assert_eq!(kind.to_string(), kind.as_str());
        let from_toml: Kind = serde_json::from_value(serde_json::json!(kind.as_str())).unwrap();
        assert_eq!(from_toml, *kind);
    }
    let err = "wizard".parse::<Kind>().unwrap_err().to_string();
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
    assert_eq!(crate::cookie::get(&headers, "__Host-oxid-csrf"), Some("tok"));
    assert_eq!(crate::cookie::get(&headers, "a"), Some("1"));
    assert_eq!(crate::cookie::get(&headers, "missing"), None);
}

#[test]
fn durations_read_naturally() {
    assert_eq!(duration_text(Seconds::new(300)), "5 minutes");
    assert_eq!(duration_text(Seconds::new(60)), "1 minute");
    assert_eq!(duration_text(Seconds::new(90)), "90 seconds");
}

