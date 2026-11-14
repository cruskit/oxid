//! Deciding which of a user's claims to release, and their values.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use super::catalogue::{
    BENEFICIARY_ACCOUNT_AU, BENEFICIARY_ACCOUNT_AU_PAYID, BENEFICIARY_ACCOUNT_INTERNATIONAL,
    TRUST_FRAMEWORK, VERIFIED_CLAIMS, age_threshold, is_standard, scope_claims,
};
use super::dates::{age_on, local_date, parse_date};
use crate::epoch::Timestamp;
use crate::client::Client;
use crate::user::User;

/// The claims to release for one delivery location (ID token or `UserInfo`).
///
/// `requested` is that location's member of the `claims` parameter and
/// `scopes` the granted scopes whose implied claims go to this location. A
/// claim is released only if `client`'s profile defines it, the client is
/// provisioned for it, the user agreed to share it (`shared`) and the user
/// has it. Anything else is omitted rather than being an error, including
/// claims requested as essential (ConnectID identity assurance §5.1).
pub(crate) fn release(
    user: &User,
    client: &Client,
    requested: &Map<String, Value>,
    scopes: &[String],
    shared: &BTreeSet<String>,
    now: Timestamp,
) -> Map<String, Value> {
    let mut out = Map::new();
    let wanted = requested
        .keys()
        .map(String::as_str)
        .chain(scope_claims(client, scopes));
    for name in wanted {
        if is_standard(name)
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
pub(super) fn verified_request(request: &Value) -> Option<&Map<String, Value>> {
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
pub(super) fn names_trust_framework(constraint: &Value) -> bool {
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

pub(super) fn verified_claims(
    user: &User,
    client: &Client,
    requested: &Map<String, Value>,
    shared: &BTreeSet<String>,
    now: Timestamp,
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
pub(super) fn beneficiary_account(user: &User, claim: &str) -> Option<Value> {
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
