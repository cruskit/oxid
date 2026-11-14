
use serde_json::json;

use super::*;
use crate::keys::SigningKey;

const PS256: &[SigningAlg] = &[SigningAlg::PS256];

fn key() -> &'static SigningKey {
    crate::keys::test_support::shared_key()
}

fn jwks(key: &SigningKey) -> JwkSet {
    JwkSet {
        keys: vec![key.public_jwk().clone()],
    }
}

fn token(claims: &Value) -> String {
    key().sign(Some("JWT"), claims).unwrap()
}

#[test]
fn sign_then_verify_round_trips() {
    let jws = Jws::parse(&token(&json!({"sub": "a", "exp": 10})), PS256).unwrap();
    assert_eq!(jws.alg, SigningAlg::PS256);
    assert_eq!(jws.kid.as_deref(), Some(key().kid()));
    assert_eq!(jws.typ.as_deref(), Some("JWT"));
    assert_eq!(jws.str_claim("sub"), Some("a"));
    assert_eq!(jws.time_claim("exp"), Some(10));
    jws.verify(&jwks(key())).unwrap();
}

#[test]
fn tampered_payload_fails_verification() {
    let good = token(&json!({"sub": "a"}));
    let mut parts: Vec<&str> = good.split('.').collect();
    let forged = b64url(br#"{"sub":"b"}"#);
    parts[1] = &forged;
    let jws = Jws::parse(&parts.join("."), PS256).unwrap();
    assert_eq!(jws.verify(&jwks(key())), Err(JoseError::BadSignature));
}

#[test]
fn signature_from_another_key_is_rejected() {
    let other = SigningKey::generate().unwrap();
    let jws = Jws::parse(&other.sign(None, &json!({})).unwrap(), PS256).unwrap();
    // Different kid, so no key is even a candidate.
    assert_eq!(jws.verify(&jwks(key())), Err(JoseError::NoMatchingKey));
}

#[test]
fn alg_none_and_unlisted_algs_are_rejected() {
    for alg in ["none", "RS256", "HS256", "PS512"] {
        let header = b64url(json!({"alg": alg}).to_string());
        let token = format!("{header}.{}.sig", b64url("{}"));
        assert_eq!(
            Jws::parse(&token, PS256).unwrap_err(),
            JoseError::UnsupportedAlg(alg.to_owned()),
            "{alg}"
        );
    }
    // A FAPI algorithm that this deployment has not enabled.
    let header = b64url(json!({"alg": "ES256"}).to_string());
    let token = format!("{header}.{}.sig", b64url("{}"));
    assert!(matches!(
        Jws::parse(&token, PS256),
        Err(JoseError::UnsupportedAlg(_))
    ));
}

#[test]
fn malformed_tokens_are_rejected() {
    let h = b64url(json!({"alg": "PS256"}).to_string());
    let p = b64url("{}");
    for bad in [
        String::new(),
        "a.b".into(),
        "a.b.c.d".into(),
        format!("!!!.{p}.sig"),
        format!("{h}.!!!.sig"),
        format!("{h}.{}.sig", b64url("[1,2]")),
        format!("{h}.{p}."),
        format!("{}.{p}.sig", b64url(json!({"kid": "x"}).to_string())),
        format!(
            "{}.{p}.sig",
            b64url(json!({"alg": "PS256", "crit": ["x"]}).to_string())
        ),
    ] {
        assert!(
            matches!(Jws::parse(&bad, PS256), Err(JoseError::Malformed(_))),
            "{bad}"
        );
    }
}

#[test]
fn key_selection_honours_use_alg_and_kid() {
    let jws = Jws::parse(&token(&json!({})), PS256).unwrap();

    let mut enc_only = key().public_jwk().clone();
    enc_only.common.public_key_use = Some(PublicKeyUse::Encryption);
    assert_eq!(
        jws.verify(&JwkSet {
            keys: vec![enc_only]
        }),
        Err(JoseError::NoMatchingKey)
    );

    let mut wrong_alg = key().public_jwk().clone();
    wrong_alg.common.key_algorithm = Some(jsonwebtoken::jwk::KeyAlgorithm::RS256);
    assert_eq!(
        jws.verify(&JwkSet {
            keys: vec![wrong_alg]
        }),
        Err(JoseError::NoMatchingKey)
    );

    let mut wrong_kid = key().public_jwk().clone();
    wrong_kid.common.key_id = Some("other".into());
    assert_eq!(
        jws.verify(&JwkSet {
            keys: vec![wrong_kid]
        }),
        Err(JoseError::NoMatchingKey)
    );
}

#[test]
fn duplicate_kids_are_resolved_by_trying_each_candidate() {
    let other = SigningKey::generate().unwrap();
    let mut impostor = other.public_jwk().clone();
    impostor.common.key_id = Some(key().kid().to_owned());
    let set = JwkSet {
        keys: vec![impostor, key().public_jwk().clone()],
    };
    Jws::parse(&token(&json!({})), PS256)
        .unwrap()
        .verify(&set)
        .unwrap();
}

#[test]
fn weak_rsa_keys_are_not_usable() {
    let mut weak = key().public_jwk().clone();
    if let AlgorithmParameters::RSA(rsa) = &mut weak.algorithm {
        rsa.n = b64url([0xffu8; 128]); // 1024-bit modulus
    }
    assert!(!key_supports_alg(&weak, SigningAlg::PS256));
    assert!(key_supports_alg(key().public_jwk(), SigningAlg::PS256));
    assert!(!key_supports_alg(key().public_jwk(), SigningAlg::ES256));
}

#[test]
fn time_claims_accept_integers_and_floats_only() {
    let jws = Jws::parse(&token(&json!({"a": 5, "b": 5.9, "c": "5"})), PS256).unwrap();
    assert_eq!(jws.time_claim("a"), Some(5));
    assert_eq!(jws.time_claim("b"), Some(5));
    assert_eq!(jws.time_claim("c"), None);
    assert_eq!(jws.time_claim("missing"), None);
}
