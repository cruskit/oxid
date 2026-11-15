use super::*;

// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn accepts_the_rfc_example() {
    assert!(is_valid_challenge(CHALLENGE));
    assert!(is_valid_verifier(VERIFIER));
    assert!(verify(VERIFIER, CHALLENGE));
}

#[test]
fn rejects_a_wrong_verifier() {
    let wrong = VERIFIER.replace('d', "e");
    assert!(!verify(&wrong, CHALLENGE));
}

#[test]
fn plain_method_does_not_verify() {
    // With `plain`, challenge == verifier. That must never pass.
    assert!(!verify(VERIFIER, VERIFIER));
}

#[test]
fn rejects_malformed_verifiers() {
    assert!(!is_valid_verifier("too-short"));
    assert!(!is_valid_verifier(&"a".repeat(129)));
    assert!(!is_valid_verifier(&format!("{}!", "a".repeat(50))));
    assert!(is_valid_verifier(&"a".repeat(43)));
    assert!(is_valid_verifier(&"a-._~".repeat(20)));
}

#[test]
fn rejects_malformed_challenges() {
    assert!(!is_valid_challenge(""));
    assert!(!is_valid_challenge(&CHALLENGE[1..]));
    assert!(!is_valid_challenge(&format!("{}=", &CHALLENGE[1..])));
    assert!(!is_valid_challenge(&format!("{CHALLENGE}x")));
}
