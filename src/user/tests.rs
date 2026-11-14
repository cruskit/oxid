
use super::test_support::demo_store;
use super::*;

#[test]
fn demo_user_authenticates_with_the_right_password_only() {
    let store = demo_store();
    let user = store
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .expect("valid credentials");
    assert_eq!(user.username, DEMO_USERNAME);
    assert!(store.authenticate(DEMO_USERNAME, "wrong").is_none());
    assert!(store.authenticate(DEMO_USERNAME, "").is_none());
    assert!(store.authenticate("nobody", DEMO_PASSWORD).is_none());
}

#[test]
fn demo_user_has_the_connectid_mandatory_claims() {
    let user = demo_store()
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    for claim in [
        "given_name",
        "middle_name",
        "family_name",
        "email",
        "birthdate",
        "phone_number",
        "address",
    ] {
        assert!(user.claims.contains_key(claim), "{claim}");
    }
}

#[test]
fn finds_users_by_internal_subject() {
    let store = demo_store();
    assert_eq!(
        store.find_by_subject("demo-user-0001").unwrap().username,
        DEMO_USERNAME
    );
    assert!(store.find_by_subject("missing").is_none());
}

#[test]
fn built_in_customers_cover_different_situations() {
    let users = demo_store().list();
    let usernames: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
    assert_eq!(usernames, [DEMO_USERNAME, "riley", "margaret", "sam"]);
    for user in &users {
        assert!(
            demo_store()
                .authenticate(&user.username, DEMO_PASSWORD)
                .is_some(),
            "{}",
            user.username
        );
    }
    assert_eq!(users[0].display_name(), "Alex Jordan Citizen");
    assert_eq!(users[3].display_name(), "Sam Lee", "built from name parts");
    assert!(users[1].bank_account.as_ref().unwrap().payid.is_none());
    assert!(users[3].bank_account.is_none());
    assert!(!users[3].claims.contains_key("birthdate"));
}

#[test]
fn users_without_a_password_cannot_sign_in_but_are_listed() {
    let claims = json!({"given_name": "No"}).as_object().unwrap().clone();
    let user = User::new("s", "nopass", None, claims).unwrap();
    assert_eq!(user.display_name(), "No");
    let store = StaticUserStore::new([user]).unwrap();
    assert!(store.authenticate("nopass", "").is_none());
    assert!(store.authenticate("nopass", "anything").is_none());
    assert_eq!(store.list().len(), 1);
    let bare = User::new("s2", "bare", None, Map::new()).unwrap();
    assert_eq!(bare.display_name(), "bare");
}

#[test]
fn hashes_are_salted_phc_strings() {
    let a = hash_password("secret").unwrap();
    let b = hash_password("secret").unwrap();
    assert!(a.starts_with("$argon2id$"));
    assert_ne!(a, b, "each hash has its own salt");
}

#[test]
fn debug_output_is_safe_to_log() {
    // The hash is a PHC string, not the password, but check the password
    // itself can never appear.
    let user = demo_store()
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    assert!(!format!("{user:?}").contains(DEMO_PASSWORD));
}

#[test]
fn rejects_invalid_users() {
    let hash = hash_password("x").unwrap();
    let hash = Some(hash);
    assert!(User::new("", "u", hash.clone(), Map::new()).is_err());
    assert!(User::new("s", "", hash, Map::new()).is_err());
    let plaintext = Some("plaintext-is-not-a-hash".to_owned());
    assert!(User::new("s", "u", plaintext, Map::new()).is_err());
}

#[test]
fn store_rejects_duplicates() {
    let hash = hash_password("x").unwrap();
    let user =
        |sub: &str, name: &str| User::new(sub, name, Some(hash.clone()), Map::new()).unwrap();
    assert!(StaticUserStore::new([user("1", "a"), user("2", "a")]).is_err());
    assert!(StaticUserStore::new([user("1", "a"), user("1", "b")]).is_err());
    assert_eq!(
        StaticUserStore::new([user("1", "a"), user("2", "b")])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn precomputed_hashes_match_the_current_parameters() {
    // If the argon2 defaults change, regenerate both constants with
    // `oxid hash-password` so the decoy costs what a real check costs.
    // Algorithm, version and parameters: everything before the salt.
    let settings = |hash: &str| hash.split('$').take(4).collect::<Vec<_>>().join("$");
    let current = settings(&hash_password("x").unwrap());
    for constant in [DECOY_HASH, DEMO_PASSWORD_HASH] {
        assert_eq!(settings(constant), current);
    }
    let demo = PasswordHash::new(DEMO_PASSWORD_HASH).unwrap();
    assert!(
        Argon2::default()
            .verify_password(DEMO_PASSWORD.as_bytes(), &demo)
            .is_ok()
    );
}

#[test]
fn malformed_birthdates_and_time_zones_are_refused() {
    let with = |claims: Value| User::new("s", "u", None, claims.as_object().unwrap().clone());
    assert!(with(json!({"birthdate": "1985-04-12"})).is_ok());
    assert!(with(json!({"birthdate": "12/04/1985"})).is_err());
    assert!(with(json!({"birthdate": 1985})).is_err());
    assert!(with(json!({"zoneinfo": "Australia/Perth"})).is_ok());
    assert!(with(json!({"zoneinfo": "Mars/Olympus_Mons"})).is_err());
}

#[test]
fn loads_users_from_config() {
    let config = UserConfig {
        username: "sam".into(),
        password_hash: Some(hash_password("pw").unwrap().into()),
        subject: "u-9".into(),
        claims: Map::new(),
        bank_account: None,
    };
    let store =
        StaticUserStore::from_config(std::slice::from_ref(&config), &default_time_zone()).unwrap();
    let user = store.authenticate("sam", "pw").unwrap();
    assert!(user.bank_account.is_none());

    let with_account = UserConfig {
        bank_account: Some(account()),
        ..config.clone()
    };
    let store = StaticUserStore::from_config(&[with_account], &default_time_zone()).unwrap();
    let user = store.authenticate("sam", "pw").unwrap();
    assert_eq!(user.bank_account.as_ref().unwrap().bsb, "100200");

    let invalid = UserConfig {
        bank_account: Some(BankAccount {
            bsb: "100-200".into(),
            ..account()
        }),
        ..config
    };
    let err = StaticUserStore::from_config(&[invalid], &default_time_zone()).unwrap_err();
    assert!(err.to_string().contains("sam"), "{err}");
}

fn account() -> BankAccount {
    BankAccount {
        beneficiary_name: "Sam Smith".into(),
        bsb: "100200".into(),
        account_number: "12345678".into(),
        payid: None,
        payid_type: None,
        bic_swift_code: None,
        account_number_international: None,
    }
}

#[test]
fn bank_account_details_are_validated() {
    type Edit = fn(&mut BankAccount);
    account().validate().unwrap();
    let bad: [(&str, Edit); 9] = [
        ("blank name", |a| a.beneficiary_name = "  ".into()),
        ("bsb with a dash", |a| a.bsb = "100-200".into()),
        ("short bsb", |a| a.bsb = "10020".into()),
        ("account with letters", |a| a.account_number = "12A".into()),
        ("empty account", |a| a.account_number = String::new()),
        ("payid without a type", |a| {
            a.payid = Some("0400000321".into());
        }),
        ("type without a payid", |a| {
            a.payid_type = Some(PayIdType::Mobile);
        }),
        ("malformed bic", |a| a.bic_swift_code = Some("abc".into())),
        ("blank international number", |a| {
            a.account_number_international = Some(" ".into());
        }),
    ];
    for (name, edit) in bad {
        let mut account = account();
        edit(&mut account);
        assert!(account.validate().is_err(), "{name}");
    }
}

#[test]
fn international_number_defaults_to_bsb_and_account() {
    assert_eq!(account().international_number(), "10020012345678");
    let explicit = BankAccount {
        account_number_international: Some("AU99".into()),
        ..account()
    };
    assert_eq!(explicit.international_number(), "AU99");
}

#[test]
fn payid_types_use_connectid_notation() {
    for (text, kind) in [
        ("/EMAL", PayIdType::Email),
        ("/TELI", PayIdType::Mobile),
        ("/AUBN", PayIdType::Abn),
        ("/ORGN", PayIdType::Organisation),
    ] {
        assert_eq!(kind.as_str(), text);
        let parsed: PayIdType = serde_json::from_value(json!(text)).unwrap();
        assert_eq!(parsed, kind);
    }
    assert!(serde_json::from_value::<PayIdType>(json!("/CARD")).is_err());
}

#[test]
fn demo_user_has_a_bank_account_for_every_beneficiary_claim() {
    let user = demo_store()
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let account = user.bank_account.as_ref().unwrap();
    account.validate().unwrap();
    assert!(account.payid.is_some() && account.bic_swift_code.is_some());
}
