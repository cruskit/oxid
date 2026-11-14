//! The `claims` request parameter (OpenID Connect Core §5.5) and the
//! user's consent to it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::catalogue::{VERIFIED_CLAIMS, is_standard, is_verified_claim, label, scope_claims};
use super::release::{release, verified_request};
use crate::client::Client;
use crate::user::User;

/// Why a `claims` parameter was refused (OIDC Core §5.5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ClaimsError {
    #[error("claims is not valid JSON")]
    NotJson,
    #[error("claims must be a JSON object")]
    NotAnObject,
    #[error("claims.{0} must be a JSON object")]
    SectionNotAnObject(&'static str),
    #[error("claims.{section}.{claim} must be null or an object")]
    BadClaimRequest { section: &'static str, claim: String },
}

/// The parsed `claims` authorization request parameter (OIDC Core §5.5).
///
/// Individual claim requests are kept as raw JSON: a request is either `null`
/// or an object, and members we do not understand must be ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClaimsRequest {
    #[serde(default)]
    pub id_token: Map<String, Value>,
    #[serde(default)]
    pub userinfo: Map<String, Value>,
}

impl ClaimsRequest {
    /// Parse the parameter. Inside a request object it is a JSON object; as a
    /// plain parameter it is that object serialised to a string.
    pub(crate) fn parse(value: &Value) -> Result<Self, ClaimsError> {
        let owned;
        let object = match value {
            Value::Object(object) => object,
            Value::String(text) => {
                owned = serde_json::from_str::<Value>(text).map_err(|_| ClaimsError::NotJson)?;
                owned.as_object().ok_or(ClaimsError::NotAnObject)?
            }
            _ => return Err(ClaimsError::NotAnObject),
        };

        let section = |name: &'static str| -> Result<Map<String, Value>, ClaimsError> {
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
                            return Err(ClaimsError::BadClaimRequest {
                                section: name,
                                claim: claim.clone(),
                            });
                        }
                    }
                    Ok(requests.clone())
                }
                Some(_) => Err(ClaimsError::SectionNotAnObject(name)),
            }
        };
        Ok(Self {
            id_token: section("id_token")?,
            userinfo: section("userinfo")?,
        })
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.id_token.is_empty() && self.userinfo.is_empty()
    }
}

/// One claim the user is asked to share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsentItem {
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
    pub(crate) fn consentable(&self, client: &Client, scopes: &[String]) -> Vec<ConsentItem> {
        let mut found: Vec<(&str, bool)> = Vec::new();
        for location in [&self.id_token, &self.userinfo] {
            found.extend(
                location
                    .iter()
                    .filter(|(name, _)| is_standard(name))
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
    pub(crate) fn shareable_values(
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
pub(crate) fn shared_claims(
    items: &[ConsentItem],
    mut selected: impl FnMut(&str) -> bool,
) -> BTreeSet<String> {
    items
        .iter()
        .filter(|item| item.essential || selected(&item.name))
        .map(|item| item.name.clone())
        .collect()
}

/// Whether an individual claim request marks the claim as essential.
fn is_essential(request: &Value) -> bool {
    request.get("essential").and_then(Value::as_bool) == Some(true)
}
