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
//! The identity is a service-account key, Application Default Credentials
//! found as google-auth finds them (a key, a user's credentials, a
//! borrowed account, or the machine's metadata server), or a service
//! account borrowed with either of them.
//!
//! The token requests are google-auth's: a form posted on a client of
//! their own, which reads the proxies of the environment, trusts the webpki
//! roots and waits up to 120 seconds to connect and for each read. They are
//! named by the client the caller says it is.

mod adc;
mod borrowed;
mod environment;
mod json;
mod key;
mod metadata;
mod token;
mod user;

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderValue;

use crate::{Error, Secret, tls::tls_config};
use borrowed::Borrowing;
#[doc(hidden)]
pub use environment::{Environment, File, Variable};
use key::Key;
use metadata::Machine;
#[doc(hidden)]
pub use token::{Clock, Pace, Wait};
use token::{Granted, Sender};
use user::User;

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
    Key(Box<Key>),
    /// A user's credentials.
    User(User),
    /// A service account borrowed with `source`'s token.
    Borrowed {
        source: Box<Identity>,
        borrowing: Borrowing,
        /// The project a request is billed to, when the file names one.
        quota_project: Option<String>,
    },
    /// The machine's account, from its metadata server.
    Machine(Machine),
    /// Application Default Credentials that could not be read: the first
    /// token fails with this.
    Unresolved(Error),
}

impl Identity {
    /// A token of the identity, at `now`.
    fn granted<'a>(
        &'a self,
        sender: &'a Sender,
        now: f64,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Granted, Error>> + Send + 'a>> {
        Box::pin(async move {
            match self {
                Self::Key(key) => {
                    let assertion = key.assertion(now)?;
                    let form = [("assertion", assertion.as_str()), ("grant_type", JWT_GRANT)];
                    sender.granted(&key.token_uri, &form, now).await
                }
                Self::User(user) => user.granted(sender, now).await,
                Self::Borrowed {
                    source, borrowing, ..
                } => {
                    let lent = source.granted(sender, now).await?;
                    borrowing.granted(sender, &lent.token).await
                }
                Self::Machine(machine) => machine.granted(sender, now).await,
                Self::Unresolved(error) => Err(*error),
            }
        })
    }

    /// The project a request is billed to, when the credentials name one.
    fn quota_project(&self) -> Option<&str> {
        match self {
            Self::Key(key) => key.quota_project.as_deref(),
            Self::User(user) => user.quota_project.as_deref(),
            Self::Borrowed { quota_project, .. } => quota_project.as_deref(),
            Self::Machine(_) | Self::Unresolved(_) => None,
        }
    }
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
        Self::of(Identity::Key(Box::new(key)), client)
    }

    /// The identity of Application Default Credentials, found as google-auth
    /// finds them in the process's environment; its token requests name
    /// `client`. A file is read now; the metadata server, if it comes to
    /// that, is asked at the first token, and a file that cannot be read
    /// fails that token.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for a `client` that is no value of a header.
    pub fn application_default(client: &str) -> Result<Self, Error> {
        Self::application_default_in(&Environment::of_the_process(), client)
    }

    /// As [`application_default`](Self::application_default), in
    /// `environment`: a replay's or a test's.
    ///
    /// # Errors
    ///
    /// As `application_default`.
    #[doc(hidden)]
    pub fn application_default_in(environment: &Environment, client: &str) -> Result<Self, Error> {
        Self::of(adc::found(environment), client)
    }

    /// The service account `target` (its email), borrowed with this
    /// identity's token, as IAM Credentials lends it.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for an identity a clone already shares.
    pub fn borrowing(self, target: &str) -> Result<Self, Error> {
        let inner = Arc::try_unwrap(self.inner).map_err(|_| Error::Configuration)?;
        let identity = Identity::Borrowed {
            source: Box::new(inner.identity),
            borrowing: Borrowing::of(target),
            quota_project: None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                identity,
                agent: inner.agent,
                sender: inner.sender,
                held: tokio::sync::Mutex::new(None),
            }),
        })
    }

    /// The project the requests made with the identity are billed to, when
    /// its credentials name one (`quota_project_id`): what a request
    /// carries in `x-goog-user-project`.
    #[must_use]
    pub fn quota_project(&self) -> Option<&str> {
        self.inner.identity.quota_project()
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
        self.inner.identity.granted(&self.inner.sender, now).await
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
mod adc_tests;
#[cfg(test)]
mod tests;
