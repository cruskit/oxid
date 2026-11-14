//! An [`AppState`] for unit tests, on a manual clock.

use std::sync::Arc;

use crate::client::StaticClientRegistry;
use crate::config::{CiConfig, SecurityConfig};
use crate::experience::{self, Kind};
use crate::keys::SigningKey;
use crate::state::{AppState, Inner};
use crate::store::Store;
use crate::theme::Theme;
use crate::user::UserStore;
use crate::util::{Clock, ManualClock, Secret};

pub use super::ISSUER;
use super::{client_with_key, demo_store, shared_key};

pub const MTLS: &str = "https://mtls.op.example.com";
pub const NOW: i64 = 1_800_000_000;

#[derive(Debug)]
struct SharedUsers;

impl UserStore for SharedUsers {
    fn authenticate(&self, username: &str, password: &str) -> Option<Arc<crate::user::User>> {
        demo_store().authenticate(username, password)
    }

    fn find_by_subject(&self, subject: &str) -> Option<Arc<crate::user::User>> {
        demo_store().find_by_subject(subject)
    }

    fn list(&self) -> &[Arc<crate::user::User>] {
        demo_store().list()
    }
}

/// State with client `rp` (keyed by the shared test key), the demo user
/// and a manual clock at [`NOW`]. The client and the provider share one
/// key purely to keep tests fast.
pub fn state() -> (AppState, Arc<ManualClock>) {
    state_with(Kind::Login)
}

/// As [`state`], with the given user experience.
pub fn state_with(kind: Kind) -> (AppState, Arc<ManualClock>) {
    state_with_ci(kind, CiConfig::default())
}

/// As [`state_with`], with the given settings for the `ci` experience.
pub fn state_with_ci(kind: Kind, ci: CiConfig) -> (AppState, Arc<ManualClock>) {
    state_from(kind, ci, Theme::default())
}

/// As [`state_with_ci`], with the given theme.
pub fn state_from(kind: Kind, ci: CiConfig, theme: Theme) -> (AppState, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(NOW));
    let users: Arc<dyn UserStore> = Arc::new(SharedUsers);
    let clients = StaticClientRegistry::new([client_with_key("rp", shared_key())]).unwrap();
    let state = AppState::from_inner(Inner {
        issuer: ISSUER.to_owned(),
        mtls_base_url: MTLS.to_owned(),
        security: SecurityConfig::default(),
        ci,
        signing_key: SigningKey::generate().unwrap(),
        clients: Arc::new(clients),
        experience: experience::build(kind, Arc::clone(&users)),
        users,
        theme,
        store: Store::default(),
        clock: Arc::clone(&clock) as Arc<dyn Clock>,
        pairwise_salt: Secret::new(b"unit-test-pairwise-salt".to_vec()),
    });
    (state, clock)
}
