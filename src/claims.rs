//! Identity claims: parsing the OpenID Connect `claims` request parameter and
//! deciding which of a user's claims to release.
//!
//! What a client may receive depends on its [`Profile`]:
//!
//! - `connectid`: exactly the claims of the ConnectID Identity Assurance
//!   Profile. A small set of standard claims, requested with the `claims`
//!   parameter only, and `verified_claims` under the `au_connectid` trust
//!   framework carrying age-over attestations and bank account details.
//! - `oidc`: every standard claim of OpenID Connect Core §5.1, requested
//!   with the `claims` parameter or the `profile`, `email`, `phone` and
//!   `address` scopes.
//!
//! Requests for claims outside the client's profile, or that the client is
//! not provisioned for, are ignored rather than rejected. The user chooses
//! which voluntary claims to share; essential ones can only be refused by
//! cancelling the request.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::{Date, Month, OffsetDateTime};

use crate::client::{Client, Profile};
use crate::user::User;

/// The trust framework ConnectID identity assurance is issued under.
pub const TRUST_FRAMEWORK: &str = "au_connectid";

pub const VERIFIED_CLAIMS: &str = "verified_claims";

/// The standard claims of OpenID Connect Core §5.1, other than `sub`.
pub const OIDC_STANDARD_CLAIMS: &[&str] = &[
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
];

/// Scopes that imply claims (OpenID Connect Core §5.4).
pub const CLAIM_SCOPES: &[&str] = &["profile", "email", "phone", "address"];

fn claims_for_scope(scope: &str) -> &'static [&'static str] {
    match scope {
        "profile" => &[
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
        "email" => &["email", "email_verified"],
        "phone" => &["phone_number", "phone_number_verified"],
        "address" => &["address"],
        _ => &[],
    }
}

/// The standard claims of the ConnectID profile (§5.3.2), a subset of the
/// `OpenID` Connect ones. `txn` is also defined there but, like `sub` and
/// `auth_time`, it is produced by the token logic.
pub const CONNECTID_STANDARD_CLAIMS: &[&str] = &[
    "given_name",
    "middle_name",
    "family_name",
    "email",
    "birthdate",
    "phone_number",
    "address",
];

/// Age thresholds available as `over{N}` verified claims (§5.3.3).
const AGE_THRESHOLDS: &[u8] = &[16, 18, 21, 25, 65];

pub const BENEFICIARY_ACCOUNT_AU: &str = "beneficiary_account_au";
pub const BENEFICIARY_ACCOUNT_AU_PAYID: &str = "beneficiary_account_au_payid";
pub const BENEFICIARY_ACCOUNT_INTERNATIONAL: &str = "beneficiary_account_international";

const BENEFICIARY_CLAIMS: &[&str] = &[
    BENEFICIARY_ACCOUNT_AU,
    BENEFICIARY_ACCOUNT_AU_PAYID,
    BENEFICIARY_ACCOUNT_INTERNATIONAL,
];

/// Names advertised in `claims_supported` when clients of `profiles` are
/// registered.
pub fn claims_supported(profiles: &BTreeSet<Profile>) -> Vec<&'static str> {
    let mut claims = vec!["sub", "txn", "auth_time"];
    claims.extend(
        OIDC_STANDARD_CLAIMS
            .iter()
            .filter(|name| profiles.iter().any(|&p| profile_allows(p, name))),
    );
    claims
}

/// Names advertised in `scopes_supported`. The claim scopes exist only for
/// the `oidc` profile.
pub fn scopes_supported(profiles: &BTreeSet<Profile>) -> Vec<&'static str> {
    let mut scopes = vec!["openid"];
    if profiles.contains(&Profile::Oidc) {
        scopes.extend_from_slice(CLAIM_SCOPES);
    }
    scopes
}

/// Names advertised in `claims_in_verified_claims_supported`.
pub fn verified_claims_supported() -> Vec<String> {
    AGE_THRESHOLDS
        .iter()
        .map(|n| format!("over{n}"))
        .chain(BENEFICIARY_CLAIMS.iter().map(|&name| name.to_owned()))
        .collect()
}

/// The age threshold of an `over{N}` claim name.
fn age_threshold(name: &str) -> Option<u8> {
    let threshold = name.strip_prefix("over")?.parse().ok()?;
    // Compare the canonical spelling so "over018" is not accepted.
    (AGE_THRESHOLDS.contains(&threshold) && name == format!("over{threshold}")).then_some(threshold)
}

fn is_verified_claim(name: &str) -> bool {
    age_threshold(name).is_some() || BENEFICIARY_CLAIMS.contains(&name)
}

/// Whether clients of `profile` can be given the claim `name`.
pub fn profile_allows(profile: Profile, name: &str) -> bool {
    match profile {
        Profile::Connectid => CONNECTID_STANDARD_CLAIMS.contains(&name) || is_verified_claim(name),
        Profile::Oidc => OIDC_STANDARD_CLAIMS.contains(&name),
    }
}

/// The claims `scopes` imply for `client`. Only the `oidc` profile has claim
/// scopes; ConnectID clients use the `claims` parameter alone (§5.2).
fn scope_claims(client: &Client, scopes: &[String]) -> Vec<&'static str> {
    if client.profile != Profile::Oidc {
        return Vec::new();
    }
    scopes
        .iter()
        .flat_map(|scope| claims_for_scope(scope).iter().copied())
        .collect()
}

/// Whether an individual claim request marks the claim as essential.
fn is_essential(request: &Value) -> bool {
    request.get("essential").and_then(Value::as_bool) == Some(true)
}

/// A short description of a claim for the consent page.
fn label(name: &str) -> String {
    let text = match name {
        "name" => "Full name",
        "nickname" => "Nickname",
        "preferred_username" => "Username",
        "profile" => "Profile page",
        "picture" => "Profile picture",
        "website" => "Website",
        "email_verified" => "Whether your email address is verified",
        "gender" => "Gender",
        "zoneinfo" => "Time zone",
        "locale" => "Language and region",
        "phone_number_verified" => "Whether your phone number is verified",
        "updated_at" => "When your details were last updated",
        "given_name" => "Given name",
        "middle_name" => "Middle name",
        "family_name" => "Family name",
        "email" => "Email address",
        "birthdate" => "Date of birth",
        "phone_number" => "Phone number",
        "address" => "Address",
        BENEFICIARY_ACCOUNT_AU => "Bank account (BSB and account number)",
        BENEFICIARY_ACCOUNT_AU_PAYID => "Bank account (PayID, or BSB and account number)",
        BENEFICIARY_ACCOUNT_INTERNATIONAL => "Bank account for international payments",
        _ => {
            return age_threshold(name).map_or_else(
                || name.to_owned(),
                |n| format!("Confirmation that you are {n} or older"),
            );
        }
    };
    text.to_owned()
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

/// One claim the user is asked to share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentItem {
    pub name: String,
    /// A short description for the consent page.
    pub label: String,
    /// Requested as essential: the user cannot decline it individually, only
    /// cancel the whole request.
    pub essential: bool,
}

impl ClaimsRequest {
    /// The claims `client` can actually be given for this request and
    /// `scopes`, sorted by name. This is what the user is asked to consent
    /// to; requests that will be ignored are left out. A claim is essential
    /// if any part of the request marks it so.
    pub fn consentable(&self, client: &Client, scopes: &[String]) -> Vec<ConsentItem> {
        let mut found: Vec<(&str, bool)> = Vec::new();
        for location in [&self.id_token, &self.userinfo] {
            found.extend(
                location
                    .iter()
                    .filter(|(name, _)| OIDC_STANDARD_CLAIMS.contains(&name.as_str()))
                    .map(|(name, request)| (name.as_str(), is_essential(request))),
            );
            if let Some(requested) = location.get(VERIFIED_CLAIMS).and_then(verified_request) {
                found.extend(
                    requested
                        .iter()
                        .filter(|(name, _)| is_verified_claim(name))
                        .map(|(name, request)| (name.as_str(), is_essential(request))),
                );
            }
        }
        found.extend(
            scope_claims(client, scopes)
                .into_iter()
                .map(|name| (name, false)),
        );
        found.retain(|(name, _)| client.allows_claim(name));
        // Sorting puts an essential request for a name first, so that
        // de-duplication keeps it.
        found.sort_unstable_by(|a, b| a.0.cmp(b.0).then(b.1.cmp(&a.1)));
        found.dedup_by_key(|(name, _)| *name);
        found
            .into_iter()
            .map(|(name, essential)| ConsentItem {
                name: name.to_owned(),
                label: label(name),
                essential,
            })
            .collect()
    }
}

impl ClaimsRequest {
    /// The value `user` would share for each claim in
    /// [`ClaimsRequest::consentable`], for showing on the consent page.
    /// Verified claims are listed under their own names. A claim the user
    /// does not have is absent: it would not be released.
    pub fn shareable_values(
        &self,
        user: &User,
        client: &Client,
        scopes: &[String],
        now: i64,
    ) -> Map<String, Value> {
        let everything: BTreeSet<String> = self
            .consentable(client, scopes)
            .into_iter()
            .map(|item| item.name)
            .collect();
        let mut out = Map::new();
        // As they are released: scopes add claims to UserInfo only.
        for (location, scopes) in [(&self.id_token, &[][..]), (&self.userinfo, scopes)] {
            for (name, value) in release(user, client, location, scopes, &everything, now) {
                if name == VERIFIED_CLAIMS {
                    if let Some(Value::Object(claims)) = value.get("claims") {
                        out.extend(claims.clone());
                    }
                } else {
                    out.insert(name, value);
                }
            }
        }
        out
    }
}

/// The claims the user agreed to share, given the names they left selected.
/// Essential claims are always included: they cannot be declined one by one.
pub fn shared_claims(
    items: &[ConsentItem],
    mut selected: impl FnMut(&str) -> bool,
) -> BTreeSet<String> {
    items
        .iter()
        .filter(|item| item.essential || selected(&item.name))
        .map(|item| item.name.clone())
        .collect()
}

/// The claims to release for one delivery location (ID token or `UserInfo`).
///
/// `requested` is that location's member of the `claims` parameter and
/// `scopes` the granted scopes whose implied claims go to this location. A
/// claim is released only if `client`'s profile defines it, the client is
/// provisioned for it, the user agreed to share it (`shared`) and the user
/// has it. Anything else is omitted rather than being an error, including
/// claims requested as essential (ConnectID identity assurance §5.1).
pub fn release(
    user: &User,
    client: &Client,
    requested: &Map<String, Value>,
    scopes: &[String],
    shared: &BTreeSet<String>,
    now: i64,
) -> Map<String, Value> {
    let mut out = Map::new();
    let wanted = requested
        .keys()
        .map(String::as_str)
        .chain(scope_claims(client, scopes));
    for name in wanted {
        if OIDC_STANDARD_CLAIMS.contains(&name)
            && client.allows_claim(name)
            && shared.contains(name)
            && let Some(value) = user.claims.get(name)
        {
            out.insert(name.to_owned(), value.clone());
        }
    }
    if let Some(requested) = requested.get(VERIFIED_CLAIMS).and_then(verified_request) {
        let claims = verified_claims(user, client, requested, shared, now);
        // An empty `claims` element is not permitted, so omit the lot.
        if !claims.is_empty() {
            out.insert(
                VERIFIED_CLAIMS.to_owned(),
                json!({
                    "verification": { "trust_framework": TRUST_FRAMEWORK },
                    "claims": claims,
                }),
            );
        }
    }
    out
}

/// The `claims` member of a `verified_claims` request made under the
/// ConnectID trust framework.
///
/// §5.1: a request whose `trust_framework` is absent, null, malformed or
/// names another framework is ignored. When several alternatives are given,
/// the first acceptable one is used.
fn verified_request(request: &Value) -> Option<&Map<String, Value>> {
    fn acceptable(request: &Value) -> Option<&Map<String, Value>> {
        let framework = request.get("verification")?.get("trust_framework")?;
        if !names_trust_framework(framework) {
            return None;
        }
        request.get("claims")?.as_object()
    }
    match request {
        Value::Object(_) => acceptable(request),
        Value::Array(alternatives) => alternatives.iter().find_map(acceptable),
        _ => None,
    }
}

/// Whether a `{"value": ..}` / `{"values": [..]}` claim request (OIDC Core
/// §5.5.1) asks for the ConnectID trust framework. The comparison is
/// case-sensitive.
fn names_trust_framework(constraint: &Value) -> bool {
    let Some(constraint) = constraint.as_object() else {
        return false;
    };
    match (constraint.get("value"), constraint.get("values")) {
        (Some(value), _) => value.as_str() == Some(TRUST_FRAMEWORK),
        (None, Some(Value::Array(values))) => {
            values.iter().any(|v| v.as_str() == Some(TRUST_FRAMEWORK))
        }
        _ => false,
    }
}

fn verified_claims(
    user: &User,
    client: &Client,
    requested: &Map<String, Value>,
    shared: &BTreeSet<String>,
    now: i64,
) -> Map<String, Value> {
    let age = user
        .claims
        .get("birthdate")
        .and_then(Value::as_str)
        .and_then(parse_date)
        .and_then(|born| age_on(born, date_of(now)?));

    let mut claims = Map::new();
    for name in requested.keys() {
        if !client.allows_claim(name) || !shared.contains(name) {
            continue;
        }
        let value = match age_threshold(name) {
            Some(threshold) => age.map(|age| Value::Bool(age >= i32::from(threshold))),
            None => beneficiary_account(user, name),
        };
        if let Some(value) = value {
            claims.insert(name.clone(), value);
        }
    }
    claims
}

/// A `beneficiary_account_*` claim value (§5.3.3.1), if the user has the
/// details it needs.
fn beneficiary_account(user: &User, claim: &str) -> Option<Value> {
    let account = user.bank_account.as_ref()?;
    let bsb_and_number = || {
        json!({
            "beneficiary_name": account.beneficiary_name,
            "account_bsb": account.bsb,
            "account_number": account.account_number,
        })
    };
    match claim {
        BENEFICIARY_ACCOUNT_AU => Some(bsb_and_number()),
        // The PayID when there is one, otherwise BSB and account number.
        BENEFICIARY_ACCOUNT_AU_PAYID => Some(match (&account.payid, account.payid_type) {
            (Some(payid), Some(kind)) => json!({
                "beneficiary_name": account.beneficiary_name,
                "payid": payid,
                "payid_type": kind.as_str(),
            }),
            _ => bsb_and_number(),
        }),
        BENEFICIARY_ACCOUNT_INTERNATIONAL => {
            let mut value = json!({
                "beneficiary_name": account.beneficiary_name,
                "bic_swift_code": account.bic_swift_code.as_ref()?,
                "account_number_international": account.international_number(),
            });
            if let Some(address) = user.claims.get("address").and_then(one_line_address) {
                value["beneficiary_residential_address"] = address.into();
            }
            Some(value)
        }
        _ => None,
    }
}

/// An address claim as one string: `street, locality, region postcode,
/// country`, leaving out whatever is missing.
pub(crate) fn one_line_address(address: &Value) -> Option<String> {
    let part = |name: &str| {
        address
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let street = part("street_address").map(|street| {
        street
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    });
    let region = [part("region"), part("postal_code")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let parts: Vec<String> = [
        street,
        part("locality").map(str::to_owned),
        Some(region).filter(|r| !r.is_empty()),
        part("country").map(str::to_owned),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
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
pub(crate) mod test_support {
    use std::collections::BTreeSet;

    /// A consent in which the user shares every claim that exists.
    pub fn everything() -> BTreeSet<String> {
        super::OIDC_STANDARD_CLAIMS
            .iter()
            .map(|&name| name.to_owned())
            .chain(super::verified_claims_supported())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_support::client_with_key;
    use crate::keys::test_support::shared_key;
    use crate::user::test_support::demo_store;
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
            &test_support::everything(),
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

    #[allow(clippy::needless_pass_by_value)]
    fn obj(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    /// A `verified_claims` request for `claims` under the ConnectID framework.
    #[allow(clippy::needless_pass_by_value)]
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
        let everything = test_support::everything();
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
}
