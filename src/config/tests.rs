use super::*;
use crate::epoch::Seconds;

fn minimal() -> RawConfig {
    toml::from_str(
        r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            "#,
    )
    .unwrap()
}

#[test]
fn minimal_config_gets_compliant_defaults() {
    let config = minimal();
    config.clone().validate().unwrap();
    assert_eq!(config.security.access_token_ttl, Seconds::new(300));
    assert_eq!(config.security.authorization_code_ttl, Seconds::new(60));
    assert_eq!(
        config.security.request_object_max_lifetime,
        Seconds::new(600)
    );
    assert!(config.clients.is_empty());
    assert!(config.users.is_empty());
    assert_eq!(config.experience, crate::experience::Kind::Technical);

    let login: RawConfig = toml::from_str(
        "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n\
             experience = \"login\"",
    )
    .unwrap();
    assert_eq!(login.experience, crate::experience::Kind::Login);
    assert!(
        toml::from_str::<RawConfig>(
            "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n\
                 experience = \"wizard\"",
        )
        .is_err()
    );
}

#[test]
fn store_defaults_to_memory_and_dynamodb_needs_a_table() {
    let config = minimal();
    assert_eq!(config.store.backend, StoreBackend::Memory);

    let with = |store: &str| -> RawConfig {
        toml::from_str(&format!(
                "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n[store]\n{store}"
            ))
            .unwrap()
    };
    let no_table = with("backend = \"dynamodb\"");
    assert!(no_table.clone().validate().is_err());
    let table = with("backend = \"dynamodb\"\ntable = \"oxid\"\nregion = \"ap-southeast-2\"");
    assert_eq!(table.store.backend, StoreBackend::Dynamodb);
    // Usable only when the binary was built with DynamoDB support.
    assert_eq!(table.clone().validate().is_ok(), cfg!(feature = "aws"));
    let stray = with("table = \"oxid\"");
    assert!(
        stray.clone().validate().is_err(),
        "a table without the backend"
    );
    assert!(
        toml::from_str::<RawConfig>(
            "issuer = \"https://op.example.com\"\nmtls_base_url = \"https://m.example.com\"\n\
                 [store]\nbackend = \"redis\"",
        )
        .is_err()
    );
}

#[test]
fn unknown_fields_are_rejected() {
    let err = toml::from_str::<RawConfig>(
        r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            isuer = "typo"
            "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("isuer"), "{err}");
}

#[test]
fn issuer_must_be_a_clean_https_url() {
    for bad in [
        "http://op.example.com",
        "https://op.example.com/",
        "https://op.example.com?x=1",
        "https://op.example.com#frag",
        "not a url",
    ] {
        let mut config = minimal();
        config.issuer = bad.to_owned();
        assert!(config.clone().validate().is_err(), "{bad}");
    }
}

#[test]
fn lifetimes_cannot_exceed_profile_limits() {
    type Setter = fn(&mut SecurityConfig);
    let cases: [(&str, Setter); 9] = [
        ("access token over 10 minutes", |s| {
            s.access_token_ttl = Seconds::new(601);
        }),
        ("code over 60 seconds", |s| {
            s.authorization_code_ttl = Seconds::new(61);
        }),
        ("request_uri at 600 seconds", |s| {
            s.request_uri_ttl = Seconds::new(600);
        }),
        ("no session time", |s| s.session_ttl = Seconds::new(0)),
        ("session over an hour", |s| {
            s.session_ttl = Seconds::new(3601);
        }),
        ("request object lifetime", |s| {
            s.request_object_max_lifetime = Seconds::new(601);
        }),
        ("request object age", |s| {
            s.request_object_max_age = Seconds::new(601);
        }),
        ("skew below 10", |s| s.clock_skew = Seconds::new(9)),
        ("skew above 60", |s| s.clock_skew = Seconds::new(61)),
    ];
    for (name, set) in cases {
        let mut config = minimal();
        set(&mut config.security);
        assert!(config.clone().validate().is_err(), "{name}");
    }
}

#[test]
fn tls_cert_and_key_must_come_as_a_pair() {
    let mut config = minimal();
    config.server.tls_cert = Some("cert.pem".into());
    assert!(config.clone().validate().is_err());
    config.server.tls_key = Some("key.pem".into());
    config.clone().validate().unwrap();
}

#[test]
fn users_and_clients_carry_connectid_claim_settings() {
    let config: RawConfig = toml::from_str(
        r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"

            [[clients]]
            client_id = "c"
            redirect_uris = ["https://rp.example.com/cb"]
            jwks_file = "c.jwks.json"
            claims = ["given_name", "over18", "beneficiary_account_au"]

            [[clients]]
            client_id = "d"
            redirect_uris = ["https://rp2.example.com/cb"]
            jwks_file = "d.jwks.json"
            profile = "oidc"
            scopes = ["openid", "profile", "email"]

            [[users]]
            username = "alex"
            password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
            subject = "user-0001"

            [users.claims]
            given_name = "Alex"

            [users.claims.address]
            locality = "Sydney"

            [users.bank_account]
            beneficiary_name = "Alex Jordan Citizen"
            bsb = "123456"
            account_number = "12345678"
            payid = "0400000321"
            payid_type = "/TELI"
            bic_swift_code = "OXIDAU2SXXX"
            "#,
    )
    .unwrap();
    assert_eq!(
        config.clients[0].claims.as_deref().unwrap(),
        ["given_name", "over18", "beneficiary_account_au"]
    );
    assert_eq!(config.clients[0].profile, crate::client::Profile::Connectid);
    assert_eq!(config.clients[1].profile, crate::client::Profile::Oidc);
    let user = &config.users[0];
    assert_eq!(user.claims["address"]["locality"], "Sydney");
    let account = user.bank_account.as_ref().unwrap();
    account.clone().validate().unwrap();
    assert_eq!(account.payid_type, Some(crate::user::PayIdType::Mobile));
    assert_eq!(account.international_number(), "12345612345678");

    let typo = toml::from_str::<RawConfig>(
        r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            [[users]]
            username = "alex"
            subject = "s"
            [users.bank_account]
            beneficiary_name = "A"
            bsb = "123456"
            account_number = "1"
            payid_type = "/CARD"
            "#,
    );
    assert!(typo.is_err(), "unknown PayID types are refused");
}

#[test]
fn short_pairwise_salt_is_rejected() {
    let mut config = minimal();
    config.keys.pairwise_salt = Some(String::from("short").into());
    assert!(config.clone().validate().is_err());
}

#[test]
fn the_theme_is_configured_and_validated() {
    let config = minimal();
    assert_eq!(config.theme.name, None, "the default is the oxID theme");
    assert!(config.theme.show_name && config.theme.logo.is_none());

    let mut config: RawConfig = toml::from_str(
        r##"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            [theme]
            name = "Acme Bank"
            logo = "theme/logo.svg"
            logo_dark = "/abs/logo-dark.png"
            [theme.light]
            accent = "#0055ff"
            [theme.dark]
            accent = "#7aa2ff"
            "##,
    )
    .unwrap();
    // The theme's own rules; validating the whole configuration would also
    // read the (fictional) logo files.
    config.theme.validate().unwrap();
    config.resolve_paths(Path::new("/etc/oxid"));
    assert_eq!(
        config.theme.logo.as_deref().unwrap(),
        Path::new("/etc/oxid/theme/logo.svg")
    );
    assert_eq!(
        config.theme.logo_dark.as_deref().unwrap(),
        Path::new("/abs/logo-dark.png")
    );
    assert_eq!(
        config.theme.light.accent.as_ref().unwrap().as_str(),
        "#0055ff"
    );

    config.theme.name = Some(String::new());
    let error = config.clone().validate().unwrap_err();
    assert!(format!("{error:#}").starts_with("theme: "), "{error:#}");

    // Only hexadecimal colours, and only the colours there are.
    for bad in [
        "[theme.light]\naccent = \"blue\"",
        "[theme]\ncolour = \"#fff\"",
    ] {
        let text =
            format!("issuer = \"https://a.example\"\nmtls_base_url = \"https://b.example\"\n{bad}");
        assert!(toml::from_str::<RawConfig>(&text).is_err(), "{bad}");
    }
}

#[test]
fn relative_paths_resolve_against_the_config_directory() {
    let mut config: RawConfig = toml::from_str(
        r#"
            issuer = "https://op.example.com"
            mtls_base_url = "https://mtls.op.example.com"
            [keys]
            signing_key = "keys/signing.pem"
            [server]
            tls_cert = "/abs/cert.pem"
            tls_key = "tls/key.pem"
            [[clients]]
            client_id = "c"
            redirect_uris = ["https://rp.example.com/cb"]
            jwks_file = "c.jwks.json"
            "#,
    )
    .unwrap();
    config.resolve_paths(Path::new("/etc/oxid"));
    assert_eq!(
        config.keys.signing_key.unwrap(),
        Path::new("/etc/oxid/keys/signing.pem")
    );
    assert_eq!(config.server.tls_cert.unwrap(), Path::new("/abs/cert.pem"));
    assert_eq!(
        config.server.tls_key.unwrap(),
        Path::new("/etc/oxid/tls/key.pem")
    );
    assert_eq!(
        config.clients[0].jwks_file.as_deref().unwrap(),
        Path::new("/etc/oxid/c.jwks.json")
    );
    assert_eq!(config.clients[0].scopes, ["openid"]);
    assert_eq!(config.clients[0].grant_types, ["authorization_code"]);
}

#[test]
fn token_lifetimes_have_upper_bounds() {
    let mut config = minimal();
    config.security.refresh_token_ttl = MAX_REFRESH_TOKEN_TTL + Seconds::new(1);
    assert!(
        config.clone().validate().is_err(),
        "refresh_token_ttl is bounded"
    );
    config.security.refresh_token_ttl = MAX_REFRESH_TOKEN_TTL;
    config.clone().validate().unwrap();

    config.security.id_token_ttl = MAX_ID_TOKEN_TTL + Seconds::new(1);
    assert!(
        config.clone().validate().is_err(),
        "id_token_ttl is bounded"
    );
}
