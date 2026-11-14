//! Which claims exist, who may receive them, and how they are described.
//!
//! Everything known about a standard claim is one row of [`STANDARD`]: its
//! name, its label on the consent page, the scope that implies it and
//! whether the ConnectID profile defines it. The verified claims are
//! generated from [`AGE_THRESHOLDS`] and [`BENEFICIARY`].

use std::collections::BTreeSet;

use crate::client::{Client, Profile};

/// The trust framework ConnectID identity assurance is issued under.
pub const TRUST_FRAMEWORK: &str = "au_connectid";

pub const VERIFIED_CLAIMS: &str = "verified_claims";

/// A standard claim (OpenID Connect Core §5.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaimDef {
    pub name: &'static str,
    /// A short description for the consent page.
    pub label: &'static str,
    /// The scope that implies the claim (OpenID Connect Core §5.4), for
    /// `oidc` clients.
    pub scope: Option<&'static str>,
    /// Whether the ConnectID profile defines it (§5.3.2).
    pub connectid: bool,
}

const fn claim(
    name: &'static str,
    label: &'static str,
    scope: Option<&'static str>,
    connectid: bool,
) -> ClaimDef {
    ClaimDef {
        name,
        label,
        scope,
        connectid,
    }
}

const PROFILE: Option<&str> = Some("profile");
const EMAIL: Option<&str> = Some("email");
const PHONE: Option<&str> = Some("phone");
const ADDRESS: Option<&str> = Some("address");

/// The standard claims of OpenID Connect Core §5.1, other than `sub`, in
/// the order of that section. ConnectID also defines `txn`, but like `sub`
/// and `auth_time` it is produced by the token logic.
pub(crate) const STANDARD: &[ClaimDef] = &[
    claim("name", "Full name", PROFILE, false),
    claim("given_name", "Given name", PROFILE, true),
    claim("family_name", "Family name", PROFILE, true),
    claim("middle_name", "Middle name", PROFILE, true),
    claim("nickname", "Nickname", PROFILE, false),
    claim("preferred_username", "Username", PROFILE, false),
    claim("profile", "Profile page", PROFILE, false),
    claim("picture", "Profile picture", PROFILE, false),
    claim("website", "Website", PROFILE, false),
    claim("email", "Email address", EMAIL, true),
    claim(
        "email_verified",
        "Whether your email address is verified",
        EMAIL,
        false,
    ),
    claim("gender", "Gender", PROFILE, false),
    claim("birthdate", "Date of birth", PROFILE, true),
    claim("zoneinfo", "Time zone", PROFILE, false),
    claim("locale", "Language and region", PROFILE, false),
    claim("phone_number", "Phone number", PHONE, true),
    claim(
        "phone_number_verified",
        "Whether your phone number is verified",
        PHONE,
        false,
    ),
    claim("address", "Address", ADDRESS, true),
    claim(
        "updated_at",
        "When your details were last updated",
        PROFILE,
        false,
    ),
];

/// Scopes that imply claims (OpenID Connect Core §5.4).
pub const CLAIM_SCOPES: &[&str] = &["profile", "email", "phone", "address"];

/// Age thresholds available as `over{N}` verified claims (§5.3.3).
pub(crate) const AGE_THRESHOLDS: &[u8] = &[16, 18, 21, 25, 65];

pub const BENEFICIARY_ACCOUNT_AU: &str = "beneficiary_account_au";
pub const BENEFICIARY_ACCOUNT_AU_PAYID: &str = "beneficiary_account_au_payid";
pub const BENEFICIARY_ACCOUNT_INTERNATIONAL: &str = "beneficiary_account_international";

/// The bank account verified claims (§5.3.3.1) and their labels.
pub(crate) const BENEFICIARY: &[(&str, &str)] = &[
    (
        BENEFICIARY_ACCOUNT_AU,
        "Bank account (BSB and account number)",
    ),
    (
        BENEFICIARY_ACCOUNT_AU_PAYID,
        "Bank account (PayID, or BSB and account number)",
    ),
    (
        BENEFICIARY_ACCOUNT_INTERNATIONAL,
        "Bank account for international payments",
    ),
];

/// The definition of the standard claim `name`, if it is one.
pub(crate) fn standard(name: &str) -> Option<&'static ClaimDef> {
    STANDARD.iter().find(|def| def.name == name)
}

/// Whether `name` is a standard claim.
pub(crate) fn is_standard(name: &str) -> bool {
    standard(name).is_some()
}

/// The names of the standard claims of OpenID Connect Core §5.1.
pub fn oidc_standard_claims() -> impl Iterator<Item = &'static str> {
    STANDARD.iter().map(|def| def.name)
}

/// The names of the standard claims of the ConnectID profile (§5.3.2).
pub fn connectid_standard_claims() -> impl Iterator<Item = &'static str> {
    STANDARD
        .iter()
        .filter(|def| def.connectid)
        .map(|def| def.name)
}

/// Names advertised in `claims_supported` when clients of `profiles` are
/// registered.
pub fn claims_supported(profiles: &BTreeSet<Profile>) -> Vec<&'static str> {
    let mut claims = vec!["sub", "txn", "auth_time"];
    claims.extend(
        oidc_standard_claims().filter(|name| profiles.iter().any(|&p| profile_allows(p, name))),
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
        .chain(BENEFICIARY.iter().map(|&(name, _)| name.to_owned()))
        .collect()
}

/// The age threshold of an `over{N}` claim name.
pub(crate) fn age_threshold(name: &str) -> Option<u8> {
    let threshold = name.strip_prefix("over")?.parse().ok()?;
    // Compare the canonical spelling so "over018" is not accepted.
    (AGE_THRESHOLDS.contains(&threshold) && name == format!("over{threshold}")).then_some(threshold)
}

pub(crate) fn is_verified_claim(name: &str) -> bool {
    age_threshold(name).is_some() || BENEFICIARY.iter().any(|&(claim, _)| claim == name)
}

/// Whether clients of `profile` can be given the claim `name`.
pub fn profile_allows(profile: Profile, name: &str) -> bool {
    match profile {
        Profile::Connectid => {
            standard(name).is_some_and(|def| def.connectid) || is_verified_claim(name)
        }
        Profile::Oidc => is_standard(name),
    }
}

/// The claims `scopes` imply for `client`. Only the `oidc` profile has claim
/// scopes; ConnectID clients use the `claims` parameter alone (§5.2).
pub(crate) fn scope_claims(client: &Client, scopes: &[String]) -> Vec<&'static str> {
    if client.profile != Profile::Oidc {
        return Vec::new();
    }
    STANDARD
        .iter()
        .filter(|def| {
            def.scope
                .is_some_and(|scope| scopes.iter().any(|s| s == scope))
        })
        .map(|def| def.name)
        .collect()
}

/// A short description of a claim for the consent page.
pub(crate) fn label(name: &str) -> String {
    if let Some(def) = standard(name) {
        return def.label.to_owned();
    }
    if let Some(&(_, label)) = BENEFICIARY.iter().find(|&&(claim, _)| claim == name) {
        return label.to_owned();
    }
    age_threshold(name).map_or_else(
        || name.to_owned(),
        |n| format!("Confirmation that you are {n} or older"),
    )
}
