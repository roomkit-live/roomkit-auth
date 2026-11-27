//! The identity a server process calls Google Cloud APIs as, and the
//! bearer token it is asked with: what google-auth gives RoomKit's Python
//! provider of Gemini on Vertex AI.
//!
//! A service-account key signs an assertion, which Google's token endpoint
//! exchanges for a token of the `cloud-platform` scope. The token is kept
//! until three minutes and 45 seconds before it expires, as google-auth
//! keeps it, and asked again then; one refresh runs at a time, whatever the
//! number of calls waiting on it.
//!
//! The token requests are google-auth's: a form posted on a client of
//! their own, which reads the proxies of the environment, trusts the webpki
//! roots and waits up to 120 seconds to connect and for each read. They are
//! named by the client the caller says it is.

mod json;
mod key;
mod token;

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderValue;

use crate::{Error, Secret, tls::tls_config};
use key::Key;
#[doc(hidden)]
pub use token::{Clock, Pace, Wait};
use token::{Granted, Sender};

/// How long before it expires a token is asked again, in seconds:
/// google-auth's `REFRESH_THRESHOLD`.
const REFRESHED_BEFORE: f64 = 225.0;

/// How long a token request waits to connect and for each read: the
/// default of google-auth's transport on `requests`.
const TIMEOUT: Duration = Duration::from_secs(120);

/// The grant an assertion is exchanged under.
const JWT_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// A Google Cloud identity: who the process calls Google Cloud as, and the
/// token it calls with. Cloning it shares its token.
#[derive(Clone, Debug)]
pub struct GoogleCloud {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    identity: Identity,
    /// The `User-Agent` of the token requests.
    agent: HeaderValue,
    sender: Sender,
    held: tokio::sync::Mutex<Option<Granted>>,
}

/// Who the identity is.
#[derive(Debug)]
enum Identity {
    /// A service-account key.
    Key(Key),
}

impl GoogleCloud {
    /// The identity of a service-account key, from a key file's `contents`;
    /// its token requests name `client` in their `User-Agent`. Nothing is
    /// asked yet.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for contents that are no service-account
    /// key, or a `client` that is no value of a header.
    pub fn service_account(contents: &str, client: &str) -> Result<Self, Error> {
        let key = Key::read(contents)?;
        Self::of(Identity::Key(key), client)
    }

    fn of(identity: Identity, client: &str) -> Result<Self, Error> {
        let agent = HeaderValue::from_str(client).map_err(|_| Error::Configuration)?;
        let http = client_named(agent.clone(), false)?;
        let sender = Sender {
            http,
            origin: None,
            pace: Pace::default(),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                identity,
                agent,
                sender,
                held: tokio::sync::Mutex::new(None),
            }),
        })
    }

    /// A token for the `cloud-platform` scope: the one kept, while it has
    /// more than three minutes and 45 seconds left, else a new one.
    ///
    /// # Errors
    ///
    /// [`Error::Network`] for a token request that got no answer,
    /// [`Error::Http`] for one refused, [`Error::Protocol`] for an answer
    /// that holds no token. None of them says what was answered.
    pub async fn access_token(&self) -> Result<Secret, Error> {
        let mut held = self.inner.held.lock().await;
        let now = (self.inner.sender.pace.now)();
        if let Some(kept) = held.as_ref().filter(|kept| fresh(kept, now)) {
            return Ok(kept.token.clone());
        }
        let granted = self.granted(now).await?;
        let token = granted.token.clone();
        *held = Some(granted);
        Ok(token)
    }

    async fn granted(&self, now: f64) -> Result<Granted, Error> {
        match &self.inner.identity {
            Identity::Key(key) => {
                let assertion = key.assertion(now)?;
                let form = [("assertion", assertion.as_str()), ("grant_type", JWT_GRANT)];
                self.inner.sender.granted(&key.token_uri, &form, now).await
            }
        }
    }

    /// The identity as a replay of recorded cases drives it: every token
    /// request sent to `origin`, a loopback address, over plain HTTP, through
    /// no proxy, each to its path; its clock and its waits `pace`'s.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for an origin that is no loopback URL, or an
    /// identity already shared by a clone.
    #[doc(hidden)]
    pub fn replaying(mut self, origin: &str, pace: Pace) -> Result<Self, Error> {
        let origin = reqwest::Url::parse(origin).map_err(|_| Error::Configuration)?;
        let loopback = match origin.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        let inner = Arc::get_mut(&mut self.inner).ok_or(Error::Configuration)?;
        if !loopback || origin.scheme() != "http" {
            return Err(Error::Configuration);
        }
        inner.sender = Sender {
            http: client_named(inner.agent.clone(), true)?,
            origin: Some(origin),
            pace,
        };
        Ok(self)
    }
}

/// Whether `kept` may still be sent at `now`.
fn fresh(kept: &Granted, now: f64) -> bool {
    kept.expires_at
        .is_none_or(|expires_at| now < expires_at - REFRESHED_BEFORE)
}

/// The client of the token requests, named `agent`; `direct`, through no
/// proxy.
fn client_named(agent: HeaderValue, direct: bool) -> Result<reqwest::Client, Error> {
    let builder = reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config().ok_or(Error::Configuration)?)
        .no_gzip()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .user_agent(agent);
    let builder = if direct { builder.no_proxy() } else { builder };
    builder.build().map_err(|_| Error::Configuration)
}

#[cfg(test)]
mod tests;
