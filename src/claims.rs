//! Identity claims: parsing the OpenID Connect `claims` request parameter and
//! deciding which of a user's claims to release.
//!
//! Besides the standard claims, this implements the slice of OpenID Connect
//! for Identity Assurance that ConnectID uses: `verified_claims` under the
//! `au_connectid` trust framework, carrying age-over attestations derived from
//! the user's date of birth.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::{Date, Month, OffsetDateTime};

use crate::user::User;

/// The trust framework ConnectID identity assurance is issued under.
pub const TRUST_FRAMEWORK: &str = "au_connectid";

pub const VERIFIED_CLAIMS: &str = "verified_claims";

/// Identity claims that can be released about a user. `sub`, `txn` and
/// `auth_time` are also supported but are produced by the token logic.
pub const IDENTITY_CLAIMS: &[&str] = &[
    "name",
    "given_name",
    "middle_name",
    "family_name",
    "email",
    "email_verified",
    "birthdate",
    "phone_number",
    "phone_number_verified",
    "address",
];

/// Age thresholds available as `over{N}` verified claims.
const AGE_THRESHOLDS: &[u8] = &[16, 18, 21, 25, 65];

/// Names advertised in `claims_supported`.
pub fn claims_supported() -> Vec<&'static str> {
    let mut claims = vec!["sub", "txn", "auth_time"];
    claims.extend_from_slice(IDENTITY_CLAIMS);
    claims
}

/// Names advertised in `claims_in_verified_claims_supported`.
pub fn verified_claims_supported() -> Vec<String> {
    AGE_THRESHOLDS.iter().map(|n| format!("over{n}")).collect()
}

/// Scopes that imply claims (OpenID Connect Core §5.4).
pub const CLAIM_SCOPES: &[&str] = &["profile", "email", "phone", "address"];

fn claims_for_scope(scope: &str) -> &'static [&'static str] {
    match scope {
        "profile" => &[
            "name",
            "given_name",
            "middle_name",
            "family_name",
            "birthdate",
        ],
        "email" => &["email", "email_verified"],
        "phone" => &["phone_number", "phone_number_verified"],
        "address" => &["address"],
        _ => &[],
    }
}

/// The parsed `claims` authorization request parameter (OIDC Core §5.5).
///
/// Individual claim requests are kept as raw JSON: a request is either `null`
/// or an object, and members we do not understand must be ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimsRequest {
    #[serde(default)]
    pub id_token: Map<String, Value>,
    #[serde(default)]
    pub userinfo: Map<String, Value>,
}

impl ClaimsRequest {
    /// Parse the parameter. Inside a request object it is a JSON object; as a
    /// plain parameter it is that object serialised to a string.
    pub fn parse(value: &Value) -> Result<Self, String> {
        let owned;
        let object = match value {
            Value::Object(object) => object,
            Value::String(text) => {
                owned = serde_json::from_str::<Value>(text)
                    .map_err(|_| "claims is not valid JSON".to_owned())?;
                owned.as_object().ok_or("claims must be a JSON object")?
            }
            _ => return Err("claims must be a JSON object".to_owned()),
        };

        let section = |name: &str| -> Result<Map<String, Value>, String> {
            match object.get(name) {
                None | Some(Value::Null) => Ok(Map::new()),
                Some(Value::Object(requests)) => {
                    for (claim, request) in requests {
                        let valid = match request {
                            Value::Null | Value::Object(_) => true,
                            // verified_claims may also be an array of requests.
                            Value::Array(_) => claim == VERIFIED_CLAIMS,
                            _ => false,
                        };
                        if !valid {
                            return Err(format!("claims.{name}.{claim} must be null or an object"));
                        }
                    }
                    Ok(requests.clone())
                }
                Some(_) => Err(format!("claims.{name} must be a JSON object")),
            }
        };
        Ok(Self {
            id_token: section("id_token")?,
            userinfo: section("userinfo")?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.id_token.is_empty() && self.userinfo.is_empty()
    }
}

/// The claims to release for one delivery location (ID token or `UserInfo`).
///
/// `requested` is that location's member of the `claims` parameter and
/// `scopes` the granted scopes whose implied claims go to this location.
/// Only claims the user actually has are returned; an unavailable claim is
/// omitted rather than being an error (OIDC Core §5.5.1).
pub fn release(
    user: &User,
    requested: &Map<String, Value>,
    scopes: &[String],
    now: i64,
) -> Map<String, Value> {
    let mut out = Map::new();
    let scope_claims = scopes
        .iter()
        .flat_map(|s| claims_for_scope(s).iter().copied());
    let wanted = requested.keys().map(String::as_str).chain(scope_claims);
    for name in wanted {
        if IDENTITY_CLAIMS.contains(&name)
            && let Some(value) = user.claims.get(name)
        {
            out.insert(name.to_owned(), value.clone());
        }
    }
    if let Some(request) = requested.get(VERIFIED_CLAIMS)
        && let Some(verified) = verified_claims(user, request, now)
    {
        out.insert(VERIFIED_CLAIMS.to_owned(), verified);
    }
    out
}

/// Build the `verified_claims` response for a request, if it can be satisfied.
fn verified_claims(user: &User, request: &Value, now: i64) -> Option<Value> {
    match request {
        Value::Object(request) => verified_claims_for(user, request, now),
        // With several alternatives, answer the first one we can satisfy.
        Value::Array(alternatives) => alternatives
            .iter()
            .filter_map(Value::as_object)
            .find_map(|request| verified_claims_for(user, request, now)),
        _ => None,
    }
}

fn verified_claims_for(user: &User, request: &Map<String, Value>, now: i64) -> Option<Value> {
    // If the RP constrains the trust framework to one we do not operate
    // under, the whole element must be omitted (OIDC IDA §6.5).
    let framework = request
        .get("verification")
        .and_then(|v| v.get("trust_framework"));
    if !constraint_allows(framework, TRUST_FRAMEWORK) {
        return None;
    }

    let requested = request.get("claims").and_then(Value::as_object)?;
    let age = user
        .claims
        .get("birthdate")
        .and_then(Value::as_str)
        .and_then(parse_date)
        .and_then(|born| age_on(born, date_of(now)?));

    let mut claims = Map::new();
    for name in requested.keys() {
        let threshold = AGE_THRESHOLDS.iter().find(|n| *name == format!("over{n}"));
        if let (Some(threshold), Some(age)) = (threshold, age) {
            claims.insert(name.clone(), Value::Bool(age >= i32::from(*threshold)));
        }
    }
    // An empty `claims` element is not permitted, so omit the lot.
    if claims.is_empty() {
        return None;
    }
    Some(json!({
        "verification": { "trust_framework": TRUST_FRAMEWORK },
        "claims": claims,
    }))
}

/// Whether a `{"value": ..}` / `{"values": [..]}` constraint permits `actual`.
/// No constraint (absent, `null`, or an object with neither member) permits
/// anything.
fn constraint_allows(constraint: Option<&Value>, actual: &str) -> bool {
    let Some(Value::Object(constraint)) = constraint else {
        return true;
    };
    if let Some(value) = constraint.get("value") {
        return value.as_str() == Some(actual);
    }
    if let Some(Value::Array(values)) = constraint.get("values") {
        return values.iter().any(|v| v.as_str() == Some(actual));
    }
    true
}

fn date_of(unix_seconds: i64) -> Option<Date> {
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .ok()
        .map(OffsetDateTime::date)
}

/// Parse an OpenID Connect `birthdate` (`YYYY-MM-DD`).
fn parse_date(text: &str) -> Option<Date> {
    let mut parts = text.splitn(3, '-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

/// Whole years between `born` and `today`; `None` if born in the future.
fn age_on(born: Date, today: Date) -> Option<i32> {
    let had_birthday = (today.month() as u8, today.day()) >= (born.month() as u8, born.day());
    let age = today.year() - born.year() - i32::from(!had_birthday);
    (age >= 0).then_some(age)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::test_support::demo_store;
    use crate::user::{DEMO_PASSWORD, DEMO_USERNAME, UserStore};

    /// 2026-11-11T00:00:00Z. The demo user was born 1985-04-12, so is 41.
    const NOW: i64 = 1_794_355_200;

    fn user() -> std::sync::Arc<User> {
        demo_store()
            .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
            .unwrap()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn obj(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn parses_object_and_string_forms() {
        let value = json!({"id_token": {"email": null}, "userinfo": {"name": {"essential": true}}});
        let from_object = ClaimsRequest::parse(&value).unwrap();
        let from_string = ClaimsRequest::parse(&Value::String(value.to_string())).unwrap();
        assert_eq!(from_object, from_string);
        assert!(from_object.id_token.contains_key("email"));
        assert!(from_object.userinfo.contains_key("name"));
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
        assert_eq!(release(&user(), &request, &[], NOW)["given_name"], "Alex");
    }

    #[test]
    fn releases_only_requested_claims_the_user_has() {
        let request = obj(json!({
            "given_name": null,
            "family_name": {"essential": true},
            "address": {},
            "nickname": null,
            "sub": {"value": "someone-else"},
        }));
        let released = release(&user(), &request, &[], NOW);
        assert_eq!(released["given_name"], "Alex");
        assert_eq!(released["family_name"], "Citizen");
        assert_eq!(released["address"]["postal_code"], "2000");
        assert_eq!(
            released.len(),
            3,
            "nickname and sub are not released here: {released:?}"
        );
    }

    #[test]
    fn nothing_requested_releases_nothing() {
        assert!(release(&user(), &Map::new(), &["openid".to_owned()], NOW).is_empty());
    }

    #[test]
    fn scopes_imply_their_standard_claims() {
        let released = release(
            &user(),
            &Map::new(),
            &["openid".into(), "email".into()],
            NOW,
        );
        assert_eq!(released.len(), 2);
        assert_eq!(released["email"], "alex.citizen@example.com");
        assert_eq!(released["email_verified"], true);

        let profile = release(&user(), &Map::new(), &["profile".into()], NOW);
        assert!(profile.contains_key("birthdate") && profile.contains_key("middle_name"));
        assert!(!profile.contains_key("email"));
    }

    #[test]
    fn verified_claims_carry_requested_age_attestations() {
        let request = obj(json!({"verified_claims": {
            "verification": {"trust_framework": {"value": TRUST_FRAMEWORK}},
            "claims": {
                "over18": {"essential": true},
                "over65": null,
                "beneficiary_account_au": {"essential": false},
            },
        }}));
        let released = release(&user(), &request, &[], NOW);
        assert_eq!(
            released[VERIFIED_CLAIMS],
            json!({
                "verification": {"trust_framework": TRUST_FRAMEWORK},
                "claims": {"over18": true, "over65": false},
            })
        );
    }

    #[test]
    fn verified_claims_are_omitted_for_another_trust_framework() {
        for framework in [
            json!({"value": "uk_tfida"}),
            json!({"values": ["de_aml", "eidas"]}),
        ] {
            let request = obj(json!({"verified_claims": {
                "verification": {"trust_framework": framework},
                "claims": {"over18": null},
            }}));
            assert!(release(&user(), &request, &[], NOW).is_empty());
        }
    }

    #[test]
    fn trust_framework_may_be_unconstrained_or_listed() {
        for verification in [
            json!({"trust_framework": null}),
            json!({"trust_framework": {"values": ["eidas", TRUST_FRAMEWORK]}}),
            json!({}),
        ] {
            let request = obj(json!({"verified_claims": {
                "verification": verification,
                "claims": {"over21": null},
            }}));
            let released = release(&user(), &request, &[], NOW);
            assert_eq!(released[VERIFIED_CLAIMS]["claims"]["over21"], true);
        }
    }

    #[test]
    fn verified_claims_are_omitted_when_none_can_be_provided() {
        let request = obj(json!({"verified_claims": {
            "verification": {"trust_framework": null},
            "claims": {"beneficiary_account_au": null},
        }}));
        assert!(release(&user(), &request, &[], NOW).is_empty());
    }

    #[test]
    fn verified_claims_array_uses_first_satisfiable_alternative() {
        let request = obj(json!({"verified_claims": [
            {"verification": {"trust_framework": {"value": "eidas"}}, "claims": {"over18": null}},
            {"verification": {"trust_framework": {"value": TRUST_FRAMEWORK}}, "claims": {"over16": null}},
        ]}));
        let released = release(&user(), &request, &[], NOW);
        assert_eq!(released[VERIFIED_CLAIMS]["claims"], json!({"over16": true}));
    }

    #[test]
    fn age_respects_whether_the_birthday_has_passed() {
        let born = parse_date("2008-11-12").unwrap();
        let day_before = parse_date("2026-11-11").unwrap();
        let birthday = parse_date("2026-11-12").unwrap();
        assert_eq!(age_on(born, day_before), Some(17));
        assert_eq!(age_on(born, birthday), Some(18));
        assert_eq!(age_on(birthday, born), None, "born in the future");
    }

    #[test]
    fn rejects_malformed_birthdates() {
        for bad in ["", "1985", "1985-13-01", "1985-02-30", "12/04/1985", "0000"] {
            assert!(parse_date(bad).is_none(), "{bad}");
        }
        assert!(parse_date("1985-04-12").is_some());
    }

    #[test]
    fn discovery_lists_cover_connectid_requirements() {
        let supported = claims_supported();
        for claim in [
            "given_name",
            "middle_name",
            "family_name",
            "email",
            "birthdate",
            "phone_number",
            "address",
            "txn",
        ] {
            assert!(supported.contains(&claim), "{claim}");
        }
        assert_eq!(
            verified_claims_supported(),
            ["over16", "over18", "over21", "over25", "over65"]
        );
    }
}
