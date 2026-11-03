use crate::{
    Account, ChatGpt, Error, Secret, http, loopback, now, scopes,
    store::{MAX_ACCOUNTS, Record, Tokens},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};

/// Pending sign-in. Debug hides URLs. Drop cancels; expires after ten minutes.
pub struct SignIn {
    url: url::Url,
    task: Option<JoinHandle<Result<Account, Error>>>,
}
impl SignIn {
    /// Loopback URL to open; contains no token, identity hint or code.
    pub fn url(&self) -> &url::Url {
        &self.url
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
    let (host, existing) = {
        let _lease = auth.inner.store.lock().await?;
        let data = auth.inner.store.read()?;
        let existing = account
            .map(|id| data.accounts.get(id).cloned().ok_or(Error::SignInRequired))
            .transpose()?;
        if existing.is_none() && data.accounts.len() >= MAX_ACCOUNTS {
            return Err(Error::AccountLimit);
        }
        auth.inner.store.write(&data)?;
        (data.host, existing)
    };
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
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose_secret()));
    let client = existing
        .as_ref()
        .map_or("dynamic_agent_client", |r| r.client_id.as_str());
    let mut authorization =
        url::Url::parse(&discovery.authorization_endpoint).map_err(|_| Error::Protocol)?;
    {
        let mut query = authorization.query_pairs_mut();
        query.extend_pairs([
            ("client_id", client),
            ("ext_agent_host_id", &host),
            ("response_type", "code"),
            ("redirect_uri", &redirect),
            (
                "scope",
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
            ),
            ("resource", &auth.inner.http.resource),
            ("state", state.expose_secret()),
            ("nonce", nonce.expose_secret()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
        if let Some(record) = &existing {
            if let Some(tokens) = &record.tokens {
                query.append_pair("id_token_hint", tokens.id.expose_secret());
            }
            if let Some(email) = &record.email {
                query.append_pair("login_hint", email);
            }
        } else {
            query.append_pair("agent_name_hint", &auth.inner.app_name);
        }
    }
    let local = start.clone();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(600), async {
            let callback =
                loopback::receive(listener, &local, &authorization, state.expose_secret()).await?;
            let client_id = match (&existing, callback.client_id) {
                (Some(record), None) => record.client_id.clone(),
                (Some(record), Some(id)) if id == record.client_id => id,
                (None, Some(id)) if http::text(&id, 256) && id != "dynamic_agent_client" => id,
                _ => return Err(Error::Identity),
            };
            let keys = auth.inner.http.keys(&discovery).await?;
            let grant = auth
                .inner
                .http
                .grant(
                    &discovery,
                    &[
                        ("grant_type", "authorization_code"),
                        ("client_id", &client_id),
                        ("code", &callback.code),
                        ("code_verifier", verifier.expose_secret()),
                        ("redirect_uri", &redirect),
                        ("resource", &auth.inner.http.resource),
                    ],
                )
                .await?;
            let id_token = grant.id_token.ok_or(Error::Identity)?;
            let claims = auth.inner.http.identity(
                &keys,
                &id_token,
                &client_id,
                Some(nonce.expose_secret()),
            )?;
            if existing
                .as_ref()
                .is_some_and(|r| r.issuer != auth.inner.http.issuer || r.subject != claims.sub)
            {
                return Err(Error::Identity);
            }
            let record = Record {
                id: existing
                    .as_ref()
                    .map_or_else(|| uuid::Uuid::new_v4().to_string(), |r| r.id.clone()),
                client_id,
                issuer: auth.inner.http.issuer.clone(),
                subject: claims.sub,
                email: claims.email.filter(|email| http::text(email, 320)),
                revision: uuid::Uuid::new_v4().to_string(),
                tokens: Some(Tokens {
                    access: grant.access_token,
                    refresh: grant.refresh_token.ok_or(Error::Protocol)?,
                    id: id_token,
                    expires_at: now()?.saturating_add(grant.expires_in),
                    scopes: scopes(&grant.scope.ok_or(Error::Protocol)?),
                }),
            };
            save(&auth, existing.as_ref(), record, discovery).await
        })
        .await
        .map_err(|_| Error::Timeout)?
    });
    Ok(SignIn {
        url: start,
        task: Some(task),
    })
}

/// Store a verified sign-in. A reauthorization updates the entry it started
/// from, unless that entry changed meanwhile; a new sign-in takes the entry of
/// its account if it has one, so signing in twice never duplicates an account.
async fn save(
    auth: &ChatGpt,
    existing: Option<&Record>,
    record: Record,
    discovery: http::Discovery,
) -> Result<Account, Error> {
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
    let client_id = record.client_id.clone();
    let replaced = data.accounts.insert(record.id.clone(), record);
    auth.inner.store.write(&data)?;
    if let Some(replaced) = replaced.filter(|old| old.client_id != client_id) {
        end_replaced_grant(auth, discovery, replaced);
    }
    Ok(account)
}

/// Once its token is replaced, nothing here can use or revoke a replaced
/// registration's grant, so ask the service to end it. Best effort and in the
/// background: the sign-in has already succeeded.
fn end_replaced_grant(auth: &ChatGpt, discovery: http::Discovery, replaced: Record) {
    let Some(tokens) = replaced.tokens else {
        return;
    };
    let auth = auth.clone();
    tokio::spawn(async move {
        let _ = auth
            .inner
            .http
            .revoke(&discovery, &replaced.client_id, &tokens.refresh)
            .await;
    });
}

fn random() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Configuration)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
