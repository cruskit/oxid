use super::*;
use crate::testing::client_with_key;
use crate::testing::demo_store;
use crate::testing::shared_key;
use crate::user::{BankAccount, DEMO_PASSWORD, DEMO_USERNAME, UserStore};

/// 2026-11-11T00:00:00Z. The demo user was born 1985-04-12, so is 41.
const NOW: i64 = 1_794_355_200;

fn user() -> std::sync::Arc<User> {
    demo_store()
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap()
}

/// A ConnectID client provisioned for every claim of its profile.
fn client() -> Client {
    client_with_key("rp", shared_key())
}

fn oidc_client() -> Client {
    let mut client = client();
    client.profile = Profile::Oidc;
    client
}

/// Release with no claim scopes and the user sharing everything.
fn release(
    user: &User,
    client: &Client,
    requested: &Map<String, Value>,
    now: i64,
) -> Map<String, Value> {
    super::release(
        user,
        client,
        requested,
        &[],
        &crate::testing::everything(),
        now,
    )
}

fn names(items: &[ConsentItem]) -> Vec<&str> {
    items.iter().map(|item| item.name.as_str()).collect()
}

fn client_allowed(claims: &[&str]) -> Client {
    let mut client = client();
    client.claims = Some(claims.iter().map(|&c| c.to_owned()).collect());
    client
}

#[expect(clippy::needless_pass_by_value, reason = "called with json! literals")]
fn obj(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// A `verified_claims` request for `claims` under the ConnectID framework.
#[expect(clippy::needless_pass_by_value, reason = "called with json! literals")]
fn verified(claims: Value) -> Map<String, Value> {
    obj(json!({"verified_claims": {
        "verification": {"trust_framework": {"value": TRUST_FRAMEWORK}},
        "claims": claims,
    }}))
}

#[test]
fn parses_object_and_string_forms() {
    let value =
        json!({"id_token": {"email": null}, "userinfo": {"given_name": {"essential": true}}});
    let from_object = ClaimsRequest::parse(&value).unwrap();
    let from_string = ClaimsRequest::parse(&Value::String(value.to_string())).unwrap();
    assert_eq!(from_object, from_string);
    assert!(from_object.id_token.contains_key("email"));
    assert!(from_object.userinfo.contains_key("given_name"));
    assert!(!from_object.is_empty());
    assert!(ClaimsRequest::parse(&json!({})).unwrap().is_empty());
}

#[test]
fn rejects_malformed_claims_parameters() {
    for bad in [
        json!("not json"),
        json!("[1]"),
        json!(42),
        json!({"id_token": "x"}),
        json!({"id_token": {"email": true}}),
        json!({"userinfo": {"email": [1]}}),
    ] {
        assert!(ClaimsRequest::parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn unknown_request_members_are_ignored() {
    let request = obj(json!({"given_name": {"some_future_member": "x"}}));
    assert_eq!(
        release(&user(), &client(), &request, NOW)["given_name"],
        "Alex"
    );
}

#[test]
fn releases_every_standard_claim_of_the_profile() {
    let request: Map<String, Value> = CONNECTID_STANDARD_CLAIMS
        .iter()
        .map(|&name| (name.to_owned(), Value::Null))
        .collect();
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(
        released.len(),
        CONNECTID_STANDARD_CLAIMS.len(),
        "{released:?}"
    );
    assert_eq!(released["given_name"], "Alex");
    assert_eq!(released["middle_name"], "Jordan");
    assert_eq!(released["family_name"], "Citizen");
    assert_eq!(released["email"], "alex.citizen@example.com");
    assert_eq!(released["birthdate"], "1985-04-12");
    assert_eq!(released["phone_number"], "+61 400 000 000");
    assert_eq!(
        released["address"],
        json!({
            "street_address": "1 Example Street",
            "locality": "Sydney",
            "region": "NSW",
            "postal_code": "2000",
            "country": "Australia",
        })
    );
}

#[test]
fn claims_outside_the_profile_are_ignored() {
    let request = obj(json!({
        "given_name": null,
        "name": null,
        "nickname": {"essential": true},
        "email_verified": null,
        "acr": {"essential": true},
        "sub": {"value": "someone-else"},
    }));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(released.len(), 1, "{released:?}");
    assert_eq!(released["given_name"], "Alex");
}

#[test]
fn essential_claims_the_user_lacks_are_omitted_without_error() {
    let mut user = (*user()).clone();
    user.claims.remove("middle_name");
    let request = obj(json!({
        "middle_name": {"essential": true},
        "family_name": {"essential": true},
    }));
    let released = release(&user, &client(), &request, NOW);
    assert_eq!(released.len(), 1);
    assert_eq!(released["family_name"], "Citizen");
}

#[test]
fn nothing_requested_releases_nothing() {
    assert!(release(&user(), &client(), &Map::new(), NOW).is_empty());
}

#[test]
fn only_claims_the_client_is_provisioned_for_are_released() {
    let client = client_allowed(&["given_name", "over18"]);
    let mut request =
        verified(json!({"over18": null, "over21": null, "beneficiary_account_au": null}));
    request.extend(obj(
        json!({"given_name": null, "email": {"essential": true}}),
    ));
    let released = release(&user(), &client, &request, NOW);
    assert_eq!(released.len(), 2, "{released:?}");
    assert_eq!(released["given_name"], "Alex");
    assert_eq!(released[VERIFIED_CLAIMS]["claims"], json!({"over18": true}));

    // With no verified claim allowed, the element disappears entirely.
    let none = release(&user(), &client_allowed(&["email"]), &request, NOW);
    assert_eq!(none.len(), 1);
    assert!(none.contains_key("email"));
}

#[test]
fn verified_claims_carry_requested_age_attestations() {
    let request = verified(json!({
        "over16": null,
        "over18": {"essential": true},
        "over21": null,
        "over25": {},
        "over65": null,
        "over30": null,
        "over018": null,
    }));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(
        released[VERIFIED_CLAIMS],
        json!({
            "verification": {"trust_framework": TRUST_FRAMEWORK},
            "claims": {
                "over16": true, "over18": true, "over21": true,
                "over25": true, "over65": false,
            },
        })
    );
}

#[test]
fn beneficiary_account_au_carries_bsb_and_account_number() {
    let request = verified(json!({"beneficiary_account_au": {"essential": true}}));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(
        released[VERIFIED_CLAIMS]["claims"],
        json!({"beneficiary_account_au": {
            "beneficiary_name": "Alex Jordan Citizen",
            "account_bsb": "123456",
            "account_number": "12345678",
        }})
    );
}

#[test]
fn beneficiary_account_payid_falls_back_to_bsb_and_account_number() {
    let request = verified(json!({"beneficiary_account_au_payid": null}));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(
        released[VERIFIED_CLAIMS]["claims"]["beneficiary_account_au_payid"],
        json!({
            "beneficiary_name": "Alex Jordan Citizen",
            "payid": "alex.citizen@example.com",
            "payid_type": "/EMAL",
        })
    );

    let mut without_payid = (*user()).clone();
    let account = without_payid.bank_account.as_mut().unwrap();
    account.payid = None;
    account.payid_type = None;
    let released = release(&without_payid, &client(), &request, NOW);
    assert_eq!(
        released[VERIFIED_CLAIMS]["claims"]["beneficiary_account_au_payid"],
        json!({
            "beneficiary_name": "Alex Jordan Citizen",
            "account_bsb": "123456",
            "account_number": "12345678",
        })
    );
}

#[test]
fn beneficiary_account_international_carries_bic_and_address() {
    let request = verified(json!({"beneficiary_account_international": null}));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(
        released[VERIFIED_CLAIMS]["claims"]["beneficiary_account_international"],
        json!({
            "beneficiary_name": "Alex Jordan Citizen",
            "bic_swift_code": "OXIDAU2SXXX",
            "account_number_international": "12345612345678",
            "beneficiary_residential_address": "1 Example Street, Sydney, NSW 2000, Australia",
        })
    );

    // Without a BIC the claim cannot be provided, so it is omitted.
    let mut no_bic = (*user()).clone();
    no_bic.bank_account.as_mut().unwrap().bic_swift_code = None;
    assert!(release(&no_bic, &client(), &request, NOW).is_empty());
}

#[test]
fn beneficiary_claims_are_omitted_without_a_bank_account() {
    let mut user = (*user()).clone();
    user.bank_account = None;
    let request = verified(json!({
        "beneficiary_account_au": null,
        "beneficiary_account_au_payid": null,
        "beneficiary_account_international": null,
    }));
    assert!(release(&user, &client(), &request, NOW).is_empty());
}

#[test]
fn address_is_flattened_to_one_line() {
    let full = json!({
        "street_address": "Unit 4\r\n255 George St",
        "locality": "Sydney", "region": "NSW", "postal_code": "2000",
        "country": "Australia",
    });
    assert_eq!(
        one_line_address(&full).unwrap(),
        "Unit 4, 255 George St, Sydney, NSW 2000, Australia"
    );
    assert_eq!(
        one_line_address(&json!({"locality": "Perth", "country": "Australia"})).unwrap(),
        "Perth, Australia"
    );
    assert!(one_line_address(&json!({})).is_none());
    assert!(one_line_address(&json!("1 Example Street")).is_none());
}

#[test]
fn bank_account_type_is_usable_from_tests() {
    // Guards the fields the beneficiary claims are built from.
    let account: BankAccount = serde_json::from_value(json!({
        "beneficiary_name": "John Smith",
        "bsb": "100200",
        "account_number": "12345678",
        "payid": "0400000321",
        "payid_type": "/TELI",
    }))
    .unwrap();
    account.validate().unwrap();
}

#[test]
fn verified_claims_are_ignored_for_another_trust_framework() {
    for framework in [
        json!({"value": "uk_tfida"}),
        json!({"value": "AU_CONNECTID"}),
        json!({"values": ["de_aml", "eidas"]}),
    ] {
        let request = obj(json!({"verified_claims": {
            "verification": {"trust_framework": framework},
            "claims": {"over18": null},
        }}));
        assert!(release(&user(), &client(), &request, NOW).is_empty());
    }
}

#[test]
fn verified_claims_are_ignored_without_a_valid_trust_framework() {
    for verification in [
        json!({"trust_framework": null}),
        json!({"trust_framework": {}}),
        json!({"trust_framework": {"essential": true}}),
        json!({"trust_framework": TRUST_FRAMEWORK}),
        json!({"trust_framework": {"value": null}}),
        json!({"trust_framework": {"value": 7}}),
        json!({}),
        Value::Null,
    ] {
        let request = obj(json!({"verified_claims": {
            "verification": verification,
            "claims": {"over21": null},
        }}));
        assert!(
            release(&user(), &client(), &request, NOW).is_empty(),
            "{request:?}"
        );
    }
    let no_verification = obj(json!({"verified_claims": {"claims": {"over21": null}}}));
    assert!(release(&user(), &client(), &no_verification, NOW).is_empty());
}

#[test]
fn trust_framework_may_be_one_of_several_acceptable_values() {
    let request = obj(json!({"verified_claims": {
        "verification": {"trust_framework": {"values": ["eidas", TRUST_FRAMEWORK]}},
        "claims": {"over21": null},
    }}));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(
        released[VERIFIED_CLAIMS],
        json!({
            "verification": {"trust_framework": TRUST_FRAMEWORK},
            "claims": {"over21": true},
        })
    );
}

#[test]
fn verified_claims_are_omitted_when_none_can_be_provided() {
    let request = verified(json!({"place_of_birth": null, "nationalities": null}));
    assert!(release(&user(), &client(), &request, NOW).is_empty());

    let mut no_birthdate = (*user()).clone();
    no_birthdate.claims.remove("birthdate");
    let request = verified(json!({"over18": {"essential": true}}));
    assert!(release(&no_birthdate, &client(), &request, NOW).is_empty());
}

#[test]
fn verified_claims_array_uses_first_acceptable_alternative() {
    let request = obj(json!({"verified_claims": [
        {"verification": {"trust_framework": {"value": "eidas"}}, "claims": {"over18": null}},
        {"verification": {"trust_framework": {"value": TRUST_FRAMEWORK}}, "claims": {"over16": null}},
    ]}));
    let released = release(&user(), &client(), &request, NOW);
    assert_eq!(released[VERIFIED_CLAIMS]["claims"], json!({"over16": true}));
}

#[test]
fn consentable_lists_only_what_can_be_released() {
    let request = ClaimsRequest::parse(&json!({
        "id_token": {
            "given_name": null,
            "nickname": null,
            "txn": null,
            "verified_claims": {
                "verification": {"trust_framework": {"value": TRUST_FRAMEWORK}},
                "claims": {"over18": null, "beneficiary_account_au": null, "place_of_birth": null},
            },
        },
        "userinfo": {"given_name": null, "email": null},
    }))
    .unwrap();
    let items = request.consentable(&client(), &[]);
    assert_eq!(
        names(&items),
        ["beneficiary_account_au", "email", "given_name", "over18"]
    );
    assert_eq!(items[0].label, "Bank account (BSB and account number)");
    assert_eq!(items[3].label, "Confirmation that you are 18 or older");
    assert!(items.iter().all(|item| !item.essential));

    let limited = request.consentable(&client_allowed(&["email", "over18"]), &[]);
    assert_eq!(names(&limited), ["email", "over18"]);

    // A verified_claims request under another framework is not shown.
    let other = ClaimsRequest::parse(&json!({"id_token": {"verified_claims": {
        "verification": {"trust_framework": null},
        "claims": {"over18": null},
    }}}))
    .unwrap();
    assert_eq!(other.consentable(&client(), &[]).len(), 0);
}

#[test]
fn consentable_marks_claims_essential_if_any_request_says_so() {
    let request = ClaimsRequest::parse(&json!({
        "id_token": {
            "given_name": null,
            "family_name": {"essential": true},
            "email": {"essential": false},
            "birthdate": {"essential": "true"},
            "verified_claims": {
                "verification": {"trust_framework": {"value": TRUST_FRAMEWORK}},
                "claims": {"over18": {"essential": true}, "over21": null},
            },
        },
        "userinfo": {"given_name": {"essential": true}, "family_name": null},
    }))
    .unwrap();
    let essential: Vec<(String, bool)> = request
        .consentable(&client(), &[])
        .into_iter()
        .map(|item| (item.name, item.essential))
        .collect();
    assert_eq!(
        essential,
        [
            ("birthdate".to_owned(), false),
            ("email".to_owned(), false),
            ("family_name".to_owned(), true),
            ("given_name".to_owned(), true),
            ("over18".to_owned(), true),
            ("over21".to_owned(), false),
        ]
    );
}

#[test]
fn essential_claims_are_shared_whatever_the_user_selects() {
    let request = ClaimsRequest::parse(&json!({"id_token": {
        "given_name": {"essential": true},
        "email": null,
        "phone_number": null,
    }}))
    .unwrap();
    let items = request.consentable(&client(), &[]);

    let nothing_ticked = shared_claims(&items, |_| false);
    assert_eq!(
        nothing_ticked.into_iter().collect::<Vec<_>>(),
        ["given_name"]
    );

    let one_ticked = shared_claims(&items, |name| name == "email");
    assert_eq!(
        one_ticked.into_iter().collect::<Vec<_>>(),
        ["email", "given_name"]
    );
    // Names that were never offered cannot be smuggled in.
    let extra = shared_claims(&items, |_| true);
    assert!(!extra.contains("birthdate"));
    assert_eq!(extra.len(), 3);
}

#[test]
fn only_shared_claims_are_released() {
    let mut request = verified(json!({"over18": {"essential": true}, "over21": null}));
    request.extend(obj(json!({"given_name": null, "email": null})));
    let shared: BTreeSet<String> = ["given_name", "over18"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let released = super::release(&user(), &client(), &request, &[], &shared, NOW);
    assert_eq!(released.len(), 2, "{released:?}");
    assert_eq!(released["given_name"], "Alex");
    assert_eq!(released[VERIFIED_CLAIMS]["claims"], json!({"over18": true}));

    // Declining every verified claim removes the element.
    let shared: BTreeSet<String> = ["email".to_owned()].into();
    let released = super::release(&user(), &client(), &request, &[], &shared, NOW);
    assert_eq!(released.len(), 1);
    assert!(released.contains_key("email"));
}

#[test]
fn oidc_profile_releases_every_standard_claim() {
    let request: Map<String, Value> = OIDC_STANDARD_CLAIMS
        .iter()
        .map(|&name| (name.to_owned(), Value::Null))
        .collect();
    let released = release(&user(), &oidc_client(), &request, NOW);
    for name in OIDC_STANDARD_CLAIMS {
        assert!(released.contains_key(*name), "{name}");
    }
    assert_eq!(released["name"], "Alex Jordan Citizen");
    assert_eq!(released["email_verified"], true);
    assert_eq!(released["phone_number_verified"], true);
    assert_eq!(released["preferred_username"], "alex");
    assert_eq!(released["locale"], "en-AU");
    assert_eq!(released["zoneinfo"], "Australia/Sydney");
    assert!(released["updated_at"].is_number());

    // The same request from a ConnectID client yields only its subset.
    let connectid = release(&user(), &client(), &request, NOW);
    assert_eq!(connectid.len(), CONNECTID_STANDARD_CLAIMS.len());
    assert!(!connectid.contains_key("name"));
    assert!(!connectid.contains_key("email_verified"));
}

#[test]
fn oidc_profile_has_no_connectid_verified_claims() {
    let request = verified(json!({"over18": null, "beneficiary_account_au": null}));
    assert!(release(&user(), &oidc_client(), &request, NOW).is_empty());
    let parsed = ClaimsRequest {
        id_token: request,
        userinfo: Map::new(),
    };
    assert_eq!(parsed.consentable(&oidc_client(), &[]).len(), 0);
}

#[test]
fn claim_scopes_apply_to_the_oidc_profile_only() {
    let scopes = ["openid".to_owned(), "email".to_owned(), "phone".to_owned()];
    let everything = crate::testing::everything();
    let released = super::release(
        &user(),
        &oidc_client(),
        &Map::new(),
        &scopes,
        &everything,
        NOW,
    );
    assert_eq!(released.len(), 4, "{released:?}");
    assert_eq!(released["email"], "alex.citizen@example.com");
    assert_eq!(released["phone_number_verified"], true);

    let items = ClaimsRequest::default().consentable(&oidc_client(), &scopes);
    assert_eq!(
        names(&items),
        [
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified"
        ]
    );
    assert!(
        items.iter().all(|item| !item.essential),
        "scope claims are voluntary"
    );

    let profile = ["profile".to_owned(), "address".to_owned()];
    let released = super::release(
        &user(),
        &oidc_client(),
        &Map::new(),
        &profile,
        &everything,
        NOW,
    );
    assert!(released.contains_key("name") && released.contains_key("address"));
    assert!(!released.contains_key("email"));

    // ConnectID clients request claims with the claims parameter only.
    let connectid = super::release(&user(), &client(), &Map::new(), &scopes, &everything, NOW);
    assert!(connectid.is_empty());
    assert_eq!(
        ClaimsRequest::default()
            .consentable(&client(), &scopes)
            .len(),
        0
    );
}

#[test]
fn profiles_define_which_claims_exist() {
    for name in CONNECTID_STANDARD_CLAIMS {
        assert!(profile_allows(Profile::Connectid, name), "{name}");
        assert!(profile_allows(Profile::Oidc, name), "{name}");
    }
    for name in verified_claims_supported() {
        assert!(profile_allows(Profile::Connectid, &name), "{name}");
        assert!(!profile_allows(Profile::Oidc, &name), "{name}");
    }
    for name in ["name", "nickname", "email_verified", "locale", "updated_at"] {
        assert!(profile_allows(Profile::Oidc, name), "{name}");
        assert!(!profile_allows(Profile::Connectid, name), "{name}");
    }
    for name in ["txn", "sub", "acr", "over30", "verified_claims", ""] {
        assert!(!profile_allows(Profile::Oidc, name), "{name}");
        assert!(!profile_allows(Profile::Connectid, name), "{name}");
    }
}

#[test]
fn age_is_reached_at_the_start_of_the_birthday() {
    let born = parse_date("2008-11-12").unwrap();
    let day_before = parse_date("2026-11-11").unwrap();
    let birthday = parse_date("2026-11-12").unwrap();
    assert_eq!(age_on(born, day_before), Some(17));
    assert_eq!(age_on(born, birthday), Some(18));
    assert_eq!(age_on(birthday, born), None, "born in the future");
}

/// A user born on 15 June 2008, who turns 18 on 15 June 2026.
fn born_2008_06_15(zoneinfo: Option<&str>) -> User {
    let mut claims = obj(json!({"birthdate": "2008-06-15"}));
    if let Some(zone) = zoneinfo {
        claims.insert("zoneinfo".to_owned(), zone.into());
    }
    User::new("minor", "minor", None, claims).unwrap()
}

fn over18(user: &User, now: i64) -> Value {
    let request = verified(json!({"over18": null}));
    release(user, &client(), &request, now)[VERIFIED_CLAIMS]["claims"]["over18"].clone()
}

#[test]
fn age_turns_over_at_local_midnight() {
    // 2026-06-14T14:00:00Z is midnight on the 15th in Sydney (AEST, +10).
    let sydney_midnight = 1_781_445_600;
    let user = born_2008_06_15(None);
    assert_eq!(over18(&user, sydney_midnight - 1), json!(false));
    assert_eq!(over18(&user, sydney_midnight), json!(true));
    // Still the 14th in UTC: the old UTC reading would have said false.
    assert_eq!(over18(&user, sydney_midnight + 9 * 3600), json!(true));
}

#[test]
fn age_uses_the_users_own_time_zone() {
    // Perth (AWST, +8) reaches the 15th two hours after Sydney.
    let perth_midnight = 1_781_452_800;
    let user = born_2008_06_15(Some("Australia/Perth"));
    assert_eq!(over18(&user, perth_midnight - 1), json!(false));
    assert_eq!(over18(&user, perth_midnight), json!(true));

    // A configured default applies to users without `zoneinfo`.
    let utc = jiff::tz::TimeZone::UTC;
    let user = born_2008_06_15(None).with_default_time_zone(&utc);
    assert_eq!(over18(&user, perth_midnight), json!(false));
    assert_eq!(over18(&user, 1_781_481_600), json!(true));
}

#[test]
fn rejects_malformed_birthdates() {
    for bad in ["", "1985", "1985-13-01", "1985-02-30", "12/04/1985", "0000"] {
        assert!(parse_date(bad).is_none(), "{bad}");
    }
    assert!(parse_date("1985-04-12").is_some());
}

#[test]
fn discovery_lists_follow_the_profiles_in_use() {
    let connectid = BTreeSet::from([Profile::Connectid]);
    let both = BTreeSet::from([Profile::Connectid, Profile::Oidc]);

    // ConnectID alone: exactly the claims and scope of that profile.
    assert_eq!(
        claims_supported(&connectid),
        [
            "sub",
            "txn",
            "auth_time",
            "given_name",
            "family_name",
            "middle_name",
            "email",
            "birthdate",
            "phone_number",
            "address",
        ]
    );
    assert_eq!(scopes_supported(&connectid), ["openid"]);

    let supported = claims_supported(&both);
    for name in OIDC_STANDARD_CLAIMS
        .iter()
        .chain(&["sub", "txn", "auth_time"])
    {
        assert!(supported.contains(name), "{name}");
    }
    assert!(!supported.contains(&"acr"));
    assert_eq!(
        scopes_supported(&both),
        ["openid", "profile", "email", "phone", "address"]
    );
    assert_eq!(
        verified_claims_supported(),
        [
            "over16",
            "over18",
            "over21",
            "over25",
            "over65",
            "beneficiary_account_au",
            "beneficiary_account_au_payid",
            "beneficiary_account_international",
        ]
    );
}
