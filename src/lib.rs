#![doc = include_str!("../README.md")]
mod error;
mod http;
mod loopback;
mod secret;
mod signin;
mod store;

pub use error::Error;
pub use secret::Secret;
pub use signin::SignIn;
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use store::{Record, Store, Tokens};

/// Trusted inference root. Never forward these tokens to a configurable URL.
pub const CHATGPT_API_ROOT: &str = http::RESOURCE;

/// Metadata safe to display, based on a verified ID token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// Stable opaque local ID.
    pub id: String,
    /// Optional email label; never used as a registration identity.
    pub email: Option<String>,
    /// Whether credentials remain locally.
    pub connected: bool,
    /// Whether the grant authorizes ChatGPT plan usage.
    pub plan_usage: bool,
}
/// An available model. Catalogue order is preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// Slug for inference.
    pub id: String,
    /// Display name.
    pub name: String,
}
/// Local credentials are removed in either case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOut {
    /// Remote revocation confirmed, or already disconnected.
    Revoked,
    /// Local sign-out succeeded; remote revocation could not be confirmed.
    LocalOnly,
}
/// Account manager. Processes sharing a directory serialize token rotation.
#[derive(Clone, Debug)]
pub struct ChatGpt {
    inner: Arc<Inner>,
}
#[derive(Debug)]
struct Inner {
    store: Store,
    http: http::Http,
    app_name: String,
}

impl ChatGpt {
    /// Open private storage without network access or implicit sign-in.
    pub fn new(directory: impl AsRef<Path>, app_name: impl Into<String>) -> Result<Self, Error> {
        let app_name = app_name.into();
        if !http::text(&app_name, 100) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                store: Store::new(directory.as_ref())?,
                http: http::Http::new()?,
                app_name,
            }),
        })
    }
    /// List registrations, including disconnected accounts; never returns tokens.
    pub fn accounts(&self) -> Result<Vec<Account>, Error> {
        Ok(self
            .inner
            .store
            .read()?
            .accounts
            .values()
            .map(|r| r.account())
            .collect())
    }
    /// Start browser sign-in, optionally reauthorizing a specific account.
    /// Open [`SignIn::url`] and await [`SignIn::wait`]. Drop cancels the listener.
    /// A new sign-in with an account already saved here updates its entry and
    /// keeps its ID, so hosts can offer "add an account" without duplicates.
    pub async fn sign_in(&self, account: Option<&str>) -> Result<SignIn, Error> {
        signin::begin(self.clone(), account).await
    }
    /// Resolve a bearer token before each generation, including tool rounds.
    /// Started refreshes persist rotation even if the caller is cancelled.
    pub async fn access_token(&self, account: &str) -> Result<Secret, Error> {
        let this = self.clone();
        let account = account.to_owned();
        tokio::spawn(async move { this.refresh(&account).await })
            .await
            .map_err(|_| Error::Cancelled)?
    }
    /// Discover listed models for this account, refreshing its token first.
    pub async fn models(&self, account: &str) -> Result<Vec<Model>, Error> {
        self.inner
            .http
            .models(&self.access_token(account).await?)
            .await
    }
    /// Revoke refresh credentials, then clear local tokens. Keeps identity and
    /// client ID for reauthorization; [`ChatGpt::remove_account`] deletes them
    /// too. Cleanup survives caller cancellation.
    pub async fn sign_out(&self, account: &str) -> Result<SignOut, Error> {
        let this = self.clone();
        let account = account.to_owned();
        tokio::spawn(async move { this.revoke(&account, false).await })
            .await
            .map_err(|_| Error::Cancelled)?
    }
    /// Revoke credentials like [`ChatGpt::sign_out`], then delete everything
    /// stored for this account: tokens, identity, email and client ID. A sign-in
    /// still pending for it ends in [`Error::Cancelled`]. Signing in again
    /// registers the account anew under a new ID.
    pub async fn remove_account(&self, account: &str) -> Result<SignOut, Error> {
        let this = self.clone();
        let account = account.to_owned();
        tokio::spawn(async move { this.revoke(&account, true).await })
            .await
            .map_err(|_| Error::Cancelled)?
    }
    async fn refresh(&self, account: &str) -> Result<Secret, Error> {
        let _lease = self.inner.store.lock().await?;
        let mut data = self.inner.store.read()?;
        let record = data
            .accounts
            .get_mut(account)
            .ok_or(Error::SignInRequired)?;
        let old = record.tokens.as_ref().ok_or(Error::SignInRequired)?;
        if !old.plan_usage() {
            return Err(Error::PlanUsageRequired);
        }
        if old.expires_at > now()?.saturating_add(60) {
            return Ok(old.access.clone());
        }
        let tokens = match self.rotate(record, old).await {
            Err(Error::SignInRequired) => {
                record.tokens = None;
                record.revision = uuid::Uuid::new_v4().to_string();
                self.inner.store.write(&data)?;
                return Err(Error::SignInRequired);
            }
            other => other?,
        };
        let result = if tokens.plan_usage() {
            Ok(tokens.access.clone())
        } else {
            Err(Error::PlanUsageRequired)
        };
        record.tokens = Some(tokens);
        record.revision = uuid::Uuid::new_v4().to_string();
        self.inner.store.write(&data)?;
        result
    }
    /// Spend the refresh token. The service rotates it on use, so everything
    /// that can fail on the network happens first: after the grant, only local
    /// verification stands between the new tokens and the store.
    async fn rotate(&self, record: &Record, old: &Tokens) -> Result<Tokens, Error> {
        let http = &self.inner.http;
        let discovery = http.discovery().await?;
        let keys = http.keys(&discovery).await?;
        let grant = http
            .grant(
                &discovery,
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", &record.client_id),
                    ("refresh_token", old.refresh.expose_secret()),
                    ("resource", &http.resource),
                ],
            )
            .await?;
        if let Some(id) = &grant.id_token {
            let claims = http.identity(&keys, id, &record.client_id, None)?;
            if claims.sub != record.subject {
                return Err(Error::Identity);
            }
        }
        Ok(Tokens {
            access: grant.access_token,
            refresh: grant.refresh_token.unwrap_or_else(|| old.refresh.clone()),
            id: grant.id_token.unwrap_or_else(|| old.id.clone()),
            expires_at: now()?.saturating_add(grant.expires_in),
            scopes: grant
                .scope
                .map(|s| scopes(&s))
                .unwrap_or_else(|| old.scopes.clone()),
        })
    }
    async fn revoke(&self, account: &str, forget: bool) -> Result<SignOut, Error> {
        let _lease = self.inner.store.lock().await?;
        let mut data = self.inner.store.read()?;
        let record = data
            .accounts
            .get_mut(account)
            .ok_or(Error::SignInRequired)?;
        let result = if let Some(tokens) = &record.tokens {
            match self.inner.http.discovery().await {
                Ok(discovery) => {
                    self.inner
                        .http
                        .revoke(&discovery, &record.client_id, &tokens.refresh)
                        .await
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        if forget {
            data.accounts.remove(account);
        } else {
            record.tokens = None;
            record.revision = uuid::Uuid::new_v4().to_string();
        }
        self.inner.store.write(&data)?;
        Ok(if result.is_ok() {
            SignOut::Revoked
        } else {
            SignOut::LocalOnly
        })
    }
}
fn scopes(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}
fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Configuration)
}
#[cfg(test)]
mod tests;
