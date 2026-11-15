use super::*;
use crate::config::RawConfig;
use crate::epoch::{Seconds, Timestamp};

fn raw(extra: &str) -> RawConfig {
    toml::from_str(&format!(
            "issuer = \"https://op.example.com:9443\"\nmtls_base_url = \"https://mtls.example.com:9444\"\n{extra}"
        ))
        .unwrap()
}

fn config(extra: &str) -> Config {
    raw(extra).validate().unwrap()
}

#[tokio::test]
async fn builds_from_minimal_config_with_development_fallbacks() {
    let state = AppState::from_config(&config("")).await.unwrap();
    assert_eq!(state.url("/token"), "https://op.example.com:9443/token");
    assert_eq!(
        state.mtls_url("/token"),
        "https://mtls.example.com:9444/token"
    );
    assert!(
        state
            .users
            .authenticate(crate::user::DEMO_USERNAME, crate::user::DEMO_PASSWORD)
            .is_some()
    );
    assert!(state.clients.get("anything").is_none());
    assert!(state.now() > Timestamp::from_unix(1_704_067_200));
}

#[tokio::test]
async fn configured_salt_is_used_verbatim() {
    let state = AppState::from_config(&config("[keys]\npairwise_salt = \"0123456789abcdef\""))
        .await
        .unwrap();
    assert_eq!(state.pairwise_salt.expose(), b"0123456789abcdef");
}

#[tokio::test]
async fn secrets_are_not_in_debug_output() {
    let config_without_salt = || config("");
    let salt = "0123456789abcdef";
    let hash = crate::user::hash_password("pw").unwrap();
    let raw = raw(&format!(
        "[keys]\npairwise_salt = \"{salt}\"\n\
             [[users]]\nusername = \"sam\"\nsubject = \"s\"\npassword_hash = \"{hash}\"\n"
    ));
    let salt_bytes = format!("{:?}", salt.as_bytes());
    let salt_bytes = salt_bytes.trim_matches(['[', ']']);

    for printed in [format!("{raw:?}"), format!("{:?}", raw.clone().validate().unwrap())] {
        assert!(
            !printed.contains(salt) && !printed.contains(&hash),
            "{printed}"
        );
    }
    let config = raw.validate().unwrap();

    let state = AppState::from_config(&config).await.unwrap();
    let printed = format!("{state:?}");
    assert!(!printed.contains(salt), "{printed}");
    assert!(!printed.contains(salt_bytes), "{printed}");
    assert!(!printed.contains(&hash), "{printed}");

    // A generated salt lives in the store, which must not print it either.
    let state = AppState::from_config(&config_without_salt()).await.unwrap();
    let generated = state
        .store
        .secret("pairwise-salt", || unreachable!("already generated"))
        .await
        .unwrap();
    let printed = format!("{state:?}");
    assert!(!printed.contains(&generated), "{printed}");
}

#[tokio::test]
async fn invalid_config_is_rejected() {
    let mut bad = raw("");
    bad.security.access_token_ttl = Seconds::new(3600);
    assert!(bad.validate().is_err());

    let missing_key = config("[keys]\nsigning_key = \"/nonexistent/key.pem\"");
    assert!(AppState::from_config(&missing_key).await.is_err());
}

#[test]
fn certificate_names_include_configured_hosts_once() {
    let names = certificate_names(&config(""));
    assert_eq!(
        names,
        [
            "localhost",
            "127.0.0.1",
            "op.example.com",
            "mtls.example.com"
        ]
    );
    let local = toml::from_str::<RawConfig>(
        "issuer = \"https://localhost:9443\"\nmtls_base_url = \"https://localhost:9444\"",
    )
    .unwrap()
    .validate()
    .unwrap();
    assert_eq!(certificate_names(&local), ["localhost", "127.0.0.1"]);
}
