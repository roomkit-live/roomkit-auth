//! A one-use manual callback, bound to the pending browser sign-in.

use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;

use crate::{
    Error, Secret,
    callback::{self, Callback},
};

/// Sign in using a browser on another computer, without exposing a listener.
/// Keep this handle while awaiting [`SignIn::wait`](crate::SignIn::wait).
/// Clones share one submission; cancelling or expiring the sign-in invalidates
/// all handles. Debug hides the URL and state.
#[derive(Clone)]
pub struct RemoteSignIn {
    url: url::Url,
    redirect: url::Url,
    state: Secret,
    sender: Arc<Mutex<Option<oneshot::Sender<Callback>>>>,
}

impl RemoteSignIn {
    pub(crate) fn cancel(&self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
    }

    pub(crate) fn new(
        mut url: url::Url,
        redirect: url::Url,
        state: Secret,
    ) -> (Self, oneshot::Receiver<Callback>) {
        // A copied authorization link must not carry a retained identity
        // token or email. Returning users choose their account in the browser;
        // the token exchange still verifies the originally selected identity.
        let fields: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "id_token_hint" && key != "login_hint")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(fields);
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                url,
                redirect,
                state,
                sender: Arc::new(Mutex::new(Some(sender))),
            },
            receiver,
        )
    }

    /// Open this authorization URL in the other computer's browser. It has
    /// no token, code or identity hint. Keep its temporary state out of logs.
    /// After consent, copy the entire callback URL from the address bar even
    /// if the browser cannot connect to its loopback address.
    pub fn url(&self) -> &url::Url {
        &self.url
    }

    /// Submit the copied callback URL once. This performs no HTTP request to
    /// the pasted URL. [`SignIn::wait`](crate::SignIn::wait) then exchanges the
    /// code and verifies the identity before saving any credentials.
    ///
    /// # Errors
    /// [`Error::InvalidCallback`] leaves the attempt open for a corrected URL.
    /// [`Error::Cancelled`] means it was submitted, cancelled, or expired.
    pub fn submit_callback(&self, value: &str) -> Result<(), Error> {
        let callback = callback::parse(value, &self.redirect, self.state.expose_secret())?;
        let sender = self
            .sender
            .lock()
            .map_err(|_| Error::Cancelled)?
            .take()
            .ok_or(Error::Cancelled)?;
        sender.send(callback).map_err(|_| Error::Cancelled)
    }
}

impl fmt::Debug for RemoteSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSignIn").finish_non_exhaustive()
    }
}
