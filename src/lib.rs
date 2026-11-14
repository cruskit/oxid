//! oxID — an OpenID Provider implementing the FAPI 2.0 Security Profile and
//! the ConnectID FAPI 2.0 Security Profile.
//!
//! The crate is built for its two binaries, so its public API is small: the
//! configuration ([`Config`]), the server ([`ServerBuilder`]) and, with the
//! `aws` feature, [`lambda::run`]. Everything else is internal. The
//! `test-util` feature makes the internals public for the integration tests
//! in `tests/`, which enable it through a dev-dependency on this crate.

/// Declares modules that are internal to the crate, but public when the
/// `test-util` feature is on so the integration tests can reach them.
macro_rules! internal {
    ($($(#[$attr:meta])* $name:ident;)*) => {$(
        $(#[$attr])*
        #[cfg(feature = "test-util")]
        pub mod $name;
        $(#[$attr])*
        #[cfg(not(feature = "test-util"))]
        pub(crate) mod $name;
    )*};
}

pub mod config;
#[cfg(feature = "aws")]
pub mod lambda;
pub mod server;

internal! {
    authz;
    claims;
    client;
    client_auth;
    client_sync;
    cookie;
    epoch;
    error;
    experience;
    http;
    id_token;
    jose;
    keys;
    pkce;
    request_object;
    state;
    store;
    subject;
    theme;
    tls;
    user;
    util;
}

#[cfg(test)]
pub(crate) mod testing;

pub use client::Profile;
pub use client_sync::ClientSyncConfig;
pub use config::Config;
pub use epoch::{Seconds, Timestamp};
pub use experience::{Kind, UnknownExperience};
pub use server::{Server, ServerBuilder};
pub use theme::{NotAColor, ThemeConfig};
pub use user::hash_password;
pub use util::{Clock, Secret, SystemClock};
