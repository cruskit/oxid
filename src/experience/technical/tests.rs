use super::*;

#[test]
fn decodes_a_jwt_for_display() {
    let header = b64url(br#"{"alg":"PS256","kid":"k1"}"#);
    let payload = b64url(br#"{"iss":"rp","scope":"openid"}"#);
    let (h, p) = decode_jwt(&format!("{header}.{payload}.sig"));
    assert!(h.contains("\"alg\": \"PS256\""), "{h}");
    assert!(p.contains("\"scope\": \"openid\""), "{p}");

    let (h, p) = decode_jwt("not-a-jwt");
    assert_eq!(h, "(not valid base64url JSON)");
    assert_eq!(p, "(missing)");
}

#[test]
fn error_conditions_are_distinct_and_well_formed() {
    let mut codes: Vec<&str> = ERROR_CONDITIONS.iter().map(|c| c.code.as_str()).collect();
    assert_eq!(
        codes[0], "access_denied",
        "the deny shortcut uses the first"
    );
    for condition in ERROR_CONDITIONS {
        assert!(is_error_description(condition.description));
        assert!(error_condition(condition.code.as_str()).is_some());
    }
    codes.sort_unstable();
    let total = codes.len();
    codes.dedup();
    assert_eq!(codes.len(), total);
    assert!(error_condition("success").is_none());
    assert!(error_condition("made_up").is_none());
}

#[test]
fn custom_error_descriptions_must_be_safe() {
    let condition = &ERROR_CONDITIONS[0];
    let description = |input: Option<&str>| match deny(condition, input).decision {
        Decision::Deny { description, .. } => description,
        other => panic!("{other:?}"),
    };
    assert_eq!(description(Some("custom reason")), "custom reason");
    assert_eq!(description(Some("  padded  ")), "padded");
    assert_eq!(description(None), condition.description);
    assert_eq!(description(Some("   ")), condition.description);
    assert_eq!(description(Some("quote \" here")), condition.description);
    assert_eq!(description(Some("line\nbreak")), condition.description);
    assert_eq!(description(Some("caf\u{e9}")), condition.description);
    assert_eq!(description(Some(&"x".repeat(501))), condition.description);
}
