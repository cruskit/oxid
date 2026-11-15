//! Cookies: reading them from a request and writing `Set-Cookie`.
//!
//! Every cookie oxID sets is a `__Host-` cookie (RFC 6265bis §4.1.3.2):
//! `Secure`, `Path=/`, no `Domain`, so it is pinned to this origin. They are
//! all `HttpOnly`. Only `SameSite` differs, and [`SameSite`] says why.

use crate::epoch::Seconds;
use std::fmt;

use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;

/// When the browser sends a cookie on a request that another site started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SameSite {
    /// Never on a cross-site request. For cookies that only this origin's
    /// own pages need, such as the CSRF token checked when a form posts.
    Strict,
    /// Also on a top-level navigation from another site. For cookies that
    /// must survive the client sending the browser to the authorization
    /// endpoint, such as the sign-in and the remembered customer.
    Lax,
}

impl SameSite {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
        }
    }
}

/// One `Set-Cookie` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetCookie {
    name: &'static str,
    value: String,
    same_site: SameSite,
    /// Seconds until the browser drops it; `None` for the session.
    max_age: Option<Seconds>,
}

impl SetCookie {
    /// A `__Host-` cookie. `name` must carry that prefix.
    pub(crate) fn host(name: &'static str, value: impl Into<String>, same_site: SameSite) -> Self {
        debug_assert!(name.starts_with("__Host-"), "{name} is not a __Host- cookie");
        Self {
            name,
            value: value.into(),
            same_site,
            max_age: None,
        }
    }

    /// Expire the cookie after `seconds`; 0 deletes it.
    #[must_use]
    pub(crate) fn max_age(mut self, seconds: Seconds) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Delete the cookie `name`.
    pub(crate) fn delete(name: &'static str, same_site: SameSite) -> Self {
        Self::host(name, "", same_site).max_age(Seconds::ZERO)
    }
}

impl fmt::Display for SetCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}={}; Path=/; Secure; HttpOnly; SameSite={}",
            self.name,
            self.value,
            self.same_site.as_str()
        )?;
        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={max_age}")?;
        }
        Ok(())
    }
}

/// Add `Set-Cookie` headers to a response. A cookie whose value cannot be a
/// header is left out; every value set here is base64url or a token.
pub(crate) fn set(response: &mut Response, cookies: &[SetCookie]) {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// The value of the cookie `name` in a request's headers.
pub(crate) fn get<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cookies_are_secure_and_origin_bound() {
        assert_eq!(
            SetCookie::host("__Host-x", "v", SameSite::Lax).to_string(),
            "__Host-x=v; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            SetCookie::host("__Host-x", "v", SameSite::Strict)
                .max_age(Seconds::new(60))
                .to_string(),
            "__Host-x=v; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=60"
        );
        assert!(
            SetCookie::delete("__Host-x", SameSite::Lax)
                .to_string()
                .starts_with("__Host-x=; ")
        );
    }

    #[test]
    fn cookies_are_read_by_name() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("a=1; b=2"));
        assert_eq!(get(&headers, "b"), Some("2"));
        assert_eq!(get(&headers, "c"), None);
    }
}
