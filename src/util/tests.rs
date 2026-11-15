use crate::epoch::{Seconds, Timestamp};
use super::*;

#[test]
fn b64url_round_trips_without_padding() {
    let encoded = b64url([0xfb, 0xff, 0x01]);
    assert_eq!(encoded, "-_8B");
    assert_eq!(b64url_decode(&encoded).unwrap(), vec![0xfb, 0xff, 0x01]);
    assert!(b64url_decode("not base64!").is_none());
    assert!(b64url_decode("-_8B==").is_none(), "padding is rejected");
}

#[test]
fn sha256_matches_known_vector() {
    // RFC 7636 appendix B: the S256 challenge for this verifier.
    let digest = sha256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(
        b64url(digest),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn random_tokens_are_unique_and_long_enough() {
    let a = random_token(32);
    let b = random_token(32);
    assert_ne!(a, b);
    assert_eq!(b64url_decode(&a).unwrap().len(), 32);
}

#[test]
fn ct_eq_compares_content() {
    assert!(ct_eq("abc", "abc"));
    assert!(!ct_eq("abc", "abd"));
    assert!(!ct_eq("abc", "abcd"));
}

#[test]
fn manual_clock_moves_only_on_request() {
    let clock = ManualClock::new(Timestamp::from_unix(100));
    assert_eq!(clock.now(), Timestamp::from_unix(100));
    clock.advance(Seconds::new(5));
    assert_eq!(clock.now(), Timestamp::from_unix(105));
    clock.set(Timestamp::from_unix(7));
    assert_eq!(clock.now(), Timestamp::from_unix(7));
}

#[test]
fn system_clock_is_after_2024() {
    assert!(SystemClock.now() > Timestamp::from_unix(1_704_067_200));
}
