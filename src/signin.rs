use crate::{
    Account, ChatGpt, Error, RemoteSignIn, Secret, loopback,
    store::{MAX_ACCOUNTS, Record},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};

mod exchange;
use exchange::Exchange;

/// Pending sign-in. Debug hides URLs. Drop cancels; expires after ten minutes.
pub struct SignIn {
    url: url::Url,
    remote: RemoteSignIn,
    task: Option<JoinHandle<Result<Account, Error>>>,
}
impl SignIn {
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
    pub async fn wait(mut self) -> Result<Account, Error> {
        // Keeping the handle here ensures dropping wait also aborts the task.
        let task = self.task.as_mut().ok_or(Error::Cancelled)?;
        let result = task.await.map_err(|_| Error::Cancelled)?;
        self.task = None;
        result
    }
}
impl Drop for SignIn {
    fn drop(&mut self) {
        self.remote.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn").finish_non_exhaustive()
    }
}

pub(crate) async fn begin(auth: ChatGpt, account: Option<&str>) -> Result<SignIn, Error> {
    let (host, existing) = registration(&auth, account).await?;
    let discovery = auth.inner.http.discovery().await?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| Error::Network)?;
    let address = listener.local_addr().map_err(|_| Error::Network)?;
    let redirect = format!("http://{address}/auth/callback");
    let start = url::Url::parse(&format!("http://{address}/start/{}", random()?))
        .map_err(|_| Error::Configuration)?;
    let state = Secret(random()?);
    let nonce = Secret(random()?);
    let verifier = Secret(random()?);
    let exchange = Exchange {
        auth,
        existing,
        discovery,
        redirect,
        nonce,
        verifier,
    };
    let authorization = authorization(&exchange, &host, &state)?;
    let local = start.clone();
    let redirect_url = url::Url::parse(&exchange.redirect).map_err(|_| Error::Configuration)?;
    let (remote, receiver) = RemoteSignIn::new(authorization.clone(), redirect_url, state.clone());
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(600), async {
            let callback = receive(listener, &local, &authorization, &state, receiver).await?;
            exchange.complete(callback).await
        })
        .await
        .map_err(|_| Error::Timeout)?
    });
    Ok(SignIn {
        url: start,
        remote,
        task: Some(task),
    })
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
    authorization: &url::Url,
    state: &Secret,
    receiver: tokio::sync::oneshot::Receiver<crate::callback::Callback>,
) -> Result<crate::callback::Authorization, Error> {
    tokio::select! {
        result = loopback::receive(listener, local, authorization, state.expose_secret()) => result,
        result = receiver => result.map_err(|_| Error::Cancelled)?.authorization(),
    }
}

/// Store a verified sign-in. A reauthorization updates the entry it started
/// from, unless that entry changed meanwhile; a new sign-in takes the entry of
/// its registration if it has one, and never touches another registration's.
async fn save(auth: &ChatGpt, existing: Option<&Record>, record: Record) -> Result<Account, Error> {
    let _lease = auth.inner.store.lock().await?;
    let mut data = auth.inner.store.read()?;
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
    let account = record.account();
    data.accounts.insert(record.id.clone(), record);
    auth.inner.store.write(&data)?;
    Ok(account)
}

fn random() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Configuration)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
