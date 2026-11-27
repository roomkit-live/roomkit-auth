use crate::{
    Account, ChatGpt, Error, RemoteSignIn, Secret, loopback,
    store::{MAX_ACCOUNTS, Record},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};

mod exchange;
use exchange::Exchange;

/// Pending sign-in. Debug hides URLs. Drop cancels; expires after ten minutes.
pub struct SignIn<A = Account> {
    url: url::Url,
    remote: RemoteSignIn,
    task: Option<JoinHandle<Result<A, Error>>>,
}
impl<A> SignIn<A> {
    /// Loopback URL to open; contains no token, identity hint or code. Keep it
    /// out of logs: until the attempt ends, it can be replayed and redirects to
    /// the authorization request, which carries the attempt's state and hint.
    pub fn url(&self) -> &url::Url {
        &self.url
    }
    /// A handle for signing in with a browser on another computer. Its URL
    /// omits retained identity hints; submit the complete callback URL there
    /// while this sign-in awaits completion.
    pub fn remote(&self) -> RemoteSignIn {
        self.remote.clone()
    }
    /// Wait for consent, verified identity and durable storage.
    pub async fn wait(mut self) -> Result<A, Error> {
        // Keeping the handle here ensures dropping wait also aborts the task.
        let task = self.task.as_mut().ok_or(Error::Cancelled)?;
        let result = task.await.map_err(|_| Error::Cancelled)?;
        self.task = None;
        result
    }
}
impl<A> Drop for SignIn<A> {
    fn drop(&mut self) {
        self.remote.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl<A> fmt::Debug for SignIn<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn").finish_non_exhaustive()
    }
}

pub(crate) async fn begin(auth: ChatGpt, account: Option<&str>) -> Result<SignIn, Error> {
    let (host, existing) = registration(&auth, account).await?;
    let discovery = auth.inner.http.discovery().await?;
    let browser = Browser::new("/auth/callback").await?;
    let exchange = Exchange {
        auth,
        existing,
        discovery,
        redirect: browser.redirect.to_string(),
        nonce: browser.nonce.clone(),
        verifier: browser.verifier.clone(),
    };
    let authorization = authorization(&exchange, &host, &browser.state)?;
    Ok(browser.start(authorization, move |callback| exchange.complete(callback)))
}

/// The listener and one-use challenges for a local application's browser sign-in.
pub(crate) struct Browser {
    listener: TcpListener,
    local: url::Url,
    pub redirect: url::Url,
    pub state: Secret,
    pub nonce: Secret,
    pub verifier: Secret,
}

impl Browser {
    pub async fn new(callback_path: &str) -> Result<Self, Error> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| Error::Network)?;
        let address = listener.local_addr().map_err(|_| Error::Network)?;
        let local = url::Url::parse(&format!("http://{address}/start/{}", random()?))
            .map_err(|_| Error::Configuration)?;
        let redirect = local
            .join(callback_path)
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            listener,
            local,
            redirect,
            state: Secret(random()?),
            nonce: Secret(random()?),
            verifier: Secret(random()?),
        })
    }

    pub fn start<A, F, Fut>(self, authorization: url::Url, finish: F) -> SignIn<A>
    where
        A: Send + 'static,
        F: FnOnce(crate::callback::Authorization) -> Fut + Send + 'static,
        Fut: Future<Output = Result<A, Error>> + Send + 'static,
    {
        let (remote, receiver) = RemoteSignIn::new(
            authorization.clone(),
            self.redirect.clone(),
            self.state.clone(),
        );
        let local = self.local.clone();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(600), async move {
                let callback = receive(
                    self.listener,
                    &local,
                    &self.redirect,
                    &authorization,
                    &self.state,
                    receiver,
                )
                .await?;
                finish(callback).await
            })
            .await
            .map_err(|_| Error::Timeout)?
        });
        SignIn {
            url: self.local,
            remote,
            task: Some(task),
        }
    }
}

fn authorization(exchange: &Exchange, host: &str, state: &Secret) -> Result<url::Url, Error> {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(exchange.verifier.expose_secret()));
    let client = exchange
        .existing
        .as_ref()
        .map_or("dynamic_agent_client", |r| r.client_id.as_str());
    let mut authorization =
        url::Url::parse(&exchange.discovery.authorization_endpoint).map_err(|_| Error::Protocol)?;
    {
        let mut query = authorization.query_pairs_mut();
        query.extend_pairs([
            ("client_id", client),
            ("ext_agent_host_id", host),
            ("response_type", "code"),
            ("redirect_uri", &exchange.redirect),
            (
                "scope",
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
            ),
            ("resource", &exchange.auth.inner.http.resource),
            ("state", state.expose_secret()),
            ("nonce", exchange.nonce.expose_secret()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
    }
    hints(&mut authorization, exchange);
    Ok(authorization)
}

fn hints(authorization: &mut url::Url, exchange: &Exchange) {
    let mut query = authorization.query_pairs_mut();
    if let Some(record) = &exchange.existing {
        if let Some(tokens) = &record.tokens {
            query.append_pair("id_token_hint", tokens.id.expose_secret());
            // A returning sign-in shows no consent screen, so a person who
            // declined plan usage could otherwise never grant it.
            if !tokens.plan_usage() {
                query.append_pair("prompt", "consent");
            }
        }
        if let Some(email) = &record.email {
            query.append_pair("login_hint", email);
        }
    } else {
        query.append_pair("agent_name_hint", &exchange.auth.inner.app_name);
    }
}

async fn registration(
    auth: &ChatGpt,
    account: Option<&str>,
) -> Result<(String, Option<Record>), Error> {
    let _lease = auth.inner.store.lock().await?;
    let data = auth.inner.store.read()?;
    let existing = account
        .map(|id| data.accounts.get(id).cloned().ok_or(Error::SignInRequired))
        .transpose()?;
    if existing.is_none() && data.accounts.len() >= MAX_ACCOUNTS {
        return Err(Error::AccountLimit);
    }
    auth.inner.store.write(&data)?;
    Ok((data.host, existing))
}

/// Taking either callback drops the other receiver before exchanging a code.
async fn receive(
    listener: TcpListener,
    local: &url::Url,
    redirect: &url::Url,
    authorization: &url::Url,
    state: &Secret,
    receiver: tokio::sync::oneshot::Receiver<crate::callback::Callback>,
) -> Result<crate::callback::Authorization, Error> {
    tokio::select! {
        result = loopback::receive(listener, local, redirect, authorization, state.expose_secret()) => result,
        result = receiver => result.map_err(|_| Error::Cancelled)?.authorization(),
    }
}

/// Store a verified sign-in. A reauthorization updates the entry it started
/// from, unless that entry changed meanwhile; a new sign-in takes the entry of
/// its registration if it has one, and never touches another registration's.
pub(crate) async fn save(
    store: &crate::store::Store,
    existing: Option<&Record>,
    record: Record,
) -> Result<Record, Error> {
    let _lease = store.lock().await?;
    let mut data = store.read()?;
    let record = match existing {
        Some(old) => {
            let current = data.accounts.get(&old.id);
            if current.is_none_or(|current| current.revision != old.revision) {
                return Err(Error::Cancelled);
            }
            record
        }
        None => data.place(record)?,
    };
    data.accounts.insert(record.id.clone(), record.clone());
    store.write(&data)?;
    Ok(record)
}

fn random() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Configuration)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
