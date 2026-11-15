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

pub(crate) mod catalogue;
mod dates;
mod release;
mod request;

pub(crate) use catalogue::{
    TRUST_FRAMEWORK, claims_supported, profile_allows, scopes_supported, verified_claims_supported,
};
pub(crate) use dates::parse_date;
pub(crate) use release::one_line_address;
pub(crate) use release::release;
pub(crate) use request::{ClaimsRequest, ConsentItem, shared_claims};

#[cfg(test)]
use catalogue::{VERIFIED_CLAIMS, connectid_standard_claims, oidc_standard_claims};
#[cfg(test)]
use dates::*;

#[cfg(test)]
mod tests;
