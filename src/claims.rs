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
use time::{Date, Month};

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
        .and_then(|born| age_on(born, local_date(now, user.time_zone())?));

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

/// The calendar date in `zone` at `unix_seconds`. Ages turn over at local
/// midnight, not at midnight UTC, which in Australia is 8 to 11 hours later.
fn local_date(unix_seconds: i64, zone: &jiff::tz::TimeZone) -> Option<Date> {
    let date = jiff::Timestamp::from_second(unix_seconds)
        .ok()?
        .to_zoned(zone.clone())
        .date();
    let month = Month::try_from(u8::try_from(date.month()).ok()?).ok()?;
    let day = u8::try_from(date.day()).ok()?;
    Date::from_calendar_date(i32::from(date.year()), month, day).ok()
}

/// Parse an OpenID Connect `birthdate` (`YYYY-MM-DD`).
pub(crate) fn parse_date(text: &str) -> Option<Date> {
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
mod tests;
