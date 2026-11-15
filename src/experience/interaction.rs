//! What an experience is given about the request in hand.
//!
//! [`Interaction`] lives in a module of its own so that its link to the
//! provider's state stays private: the experiences (sibling modules) see
//! only the methods here, not the signing key, the salt, other clients or
//! the whole store.

use axum::http::HeaderMap;

use super::FormTarget;
use crate::authz::AuthorizationRequest;
use crate::client::Client;
use crate::epoch::{Seconds, Timestamp};
use crate::id_token::IssuerContext;
use crate::state::AppState;
use crate::store::{PlannedResponse, PushedRequest, Session, StoreResult};
use crate::theme::Theme;

/// Everything an experience may need to know about the request in hand.
#[derive(Debug)]
pub(crate) struct Interaction<'a> {
    state: &'a AppState,
    pub client: &'a Client,
    pub request_uri: &'a str,
    /// The pushed request, including the request object as it was received.
    pub pushed: &'a PushedRequest,
    /// The user's session for this request: how long they have left, and
    /// whether they have signed in.
    pub session: &'a Session,
    /// CSRF token to embed in forms; [`Interaction::form`] carries it.
    pub csrf: &'a str,
    /// The browser's request headers, for reading cookies.
    pub headers: &'a HeaderMap,
}

impl<'a> Interaction<'a> {
    pub(crate) fn new(
        state: &'a AppState,
        client: &'a Client,
        request_uri: &'a str,
        pushed: &'a PushedRequest,
        session: &'a Session,
        csrf: &'a str,
        headers: &'a HeaderMap,
    ) -> Self {
        Self {
            state,
            client,
            request_uri,
            pushed,
            session,
            csrf,
            headers,
        }
    }
}

impl Interaction<'_> {
    pub(crate) fn request(&self) -> &AuthorizationRequest {
        &self.pushed.request
    }

    /// The value of a cookie the browser sent.
    pub(crate) fn cookie(&self, name: &str) -> Option<&str> {
        crate::cookie::get(self.headers, name)
    }

    /// Where a form on a page of this experience posts to. A template with
    /// this in its `form` field opens the form with
    /// `{% include "form_open.html" %}`.
    pub(crate) fn form(&self) -> FormTarget<'_> {
        FormTarget::new(self.csrf, &self.client.id, self.request_uri)
    }

    /// The name, logo and colours the pages are shown with.
    pub(crate) fn theme(&self) -> &Theme {
        &self.state.theme
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.state.now()
    }

    /// How long a user has once their browser arrives.
    pub(crate) fn session_ttl(&self) -> Seconds {
        self.state.security.session_ttl
    }

    /// How long the `ci` experience holds its default response back.
    pub(crate) fn ci_response_delay(&self) -> Seconds {
        self.state.ci.response_delay
    }

    /// The provider's issuer identifier.
    pub(crate) fn issuer(&self) -> &str {
        &self.state.issuer
    }

    /// What issuing an ID token needs, for previewing one.
    pub(crate) fn issuer_context(&self) -> IssuerContext<'_> {
        self.state.issuer_context()
    }

    /// The store operations an experience may perform, all on this request.
    pub(crate) fn store(&self) -> InteractionStore<'_> {
        InteractionStore {
            interaction: self,
        }
    }
}

/// The store, as far as an experience may use it: only on the request in
/// hand, and only these operations.
#[derive(Debug)]
pub(crate) struct InteractionStore<'a> {
    interaction: &'a Interaction<'a>,
}

impl InteractionStore<'_> {
    fn store(&self) -> &crate::store::Store {
        &self.interaction.state.store
    }

    /// Count a failed sign-in; `false` once the attempts are used up.
    pub(crate) async fn record_failed_login(&self) -> StoreResult<bool> {
        self.store()
            .record_failed_login(self.interaction.request_uri)
            .await
    }

    /// Record that `user_subject` signed in during this session, from the
    /// browser holding `browser_secret`. `false` if the session changed
    /// since this request read it, so the sign-in did not take effect.
    pub(crate) async fn sign_in(&self, user_subject: &str, browser_secret: &str) -> StoreResult<bool> {
        let interaction = self.interaction;
        self.store()
            .sign_in(
                interaction.request_uri,
                interaction.session,
                user_subject,
                browser_secret,
            )
            .await
            .map(|session| session.is_some())
    }

    /// The response the client chose for this request, if it chose one.
    pub(crate) async fn planned_response(&self) -> StoreResult<Option<PlannedResponse>> {
        self.store()
            .planned_response(self.interaction.request_uri, self.interaction.now())
            .await
    }

    /// Forget the response the client chose.
    pub(crate) async fn clear_planned_response(&self) -> StoreResult<()> {
        self.store()
            .clear_planned_response(self.interaction.request_uri)
            .await
    }
}
