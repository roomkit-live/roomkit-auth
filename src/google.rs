//! Offline Google user grants for the Gemini Developer API.
mod signin;

use crate::{
    Error, Secret, SignIn, SignOut,
    http::{Discovery, Http, text},
    now, scopes,
    store::{Record, Store, Tokens},
};
use std::{path::Path, sync::Arc};

pub(crate) const ISSUER: &str = "https://accounts.google.com";
const CLOUD: &str = "https://www.googleapis.com/auth/cloud-platform";

/// A verified Google account in local storage. The ID is stable across reauthorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleAccount {
    /// The opaque local account ID.
    pub id: String,
    /// A display label supplied by Google.
    pub email: Option<String>,
    /// Whether a reusable offline grant is saved.
    pub connected: bool,
}

impl From<&Record> for GoogleAccount {
    fn from(record: &Record) -> Self {
        Self {
            id: record.id.clone(),
            email: record.email.clone(),
            connected: record.tokens.is_some(),
        }
    }
}

/// Google account manager for an application's registered desktop OAuth client.
/// Model requests belong to the host. Send its access token only to the Google API.
#[derive(Clone, Debug)]
pub struct Google(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    store: Store,
    http: Http,
    endpoints: Discovery,
    client_id: String,
    client_secret: Secret,
}

impl Google {
    /// Open the private `google` subdirectory of the application's auth directory.
    /// Supply the credentials of the application's registered Google desktop client.
    /// Opening the manager makes no network requests.
    pub fn new(
        directory: impl AsRef<Path>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, Error> {
        let client_id = client_id.into();
        let client_secret = Secret(client_secret.into());
        if !text(&client_id, 256) || !text(client_secret.expose_secret(), 1024) {
            return Err(Error::Configuration);
        }
        let mut http = Http::new()?;
        http.issuer = ISSUER.into();
        Ok(Self(Arc::new(Inner {
            store: Store::new(&directory.as_ref().join("google"))?,
            http,
            client_id,
            client_secret,
            endpoints: Discovery {
                issuer: ISSUER.into(),
                authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
                token_endpoint: "https://oauth2.googleapis.com/token".into(),
                jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
                revocation_endpoint: "https://oauth2.googleapis.com/revoke".into(),
            },
        })))
    }

    fn owns(&self, record: &Record) -> bool {
        record.client_id == self.0.client_id && record.issuer == self.0.http.issuer
    }

    /// List the registrations for this Google OAuth client.
    pub fn accounts(&self) -> Result<Vec<GoogleAccount>, Error> {
        Ok(self
            .0
            .store
            .read()?
            .accounts
            .values()
            .filter(|r| self.owns(r))
            .map(GoogleAccount::from)
            .collect())
    }

    /// Open the returned URL in the user's browser, then wait for consent.
    /// Passing an account ID binds reauthorization to its verified Google subject.
    pub async fn sign_in(&self, account: Option<&str>) -> Result<SignIn<GoogleAccount>, Error> {
        signin::begin(self.clone(), account).await
    }

    /// Obtain the account's access token, refreshing it under a process-wide file
    /// lock when it has less than a minute left. Cancellation cannot lose rotation.
    pub async fn access_token(&self, account: &str) -> Result<Secret, Error> {
        let auth = self.clone();
        let id = account.to_owned();
        tokio::spawn(async move { auth.refresh(&id).await })
            .await
            .map_err(|_| Error::Cancelled)?
    }

    async fn refresh(&self, id: &str) -> Result<Secret, Error> {
        let _lease = self.0.store.lock().await?;
        let mut data = self.0.store.read()?;
        let record = data
            .accounts
            .get_mut(id)
            .filter(|r| self.owns(r))
            .ok_or(Error::SignInRequired)?;
        let old = record.tokens.as_ref().ok_or(Error::SignInRequired)?;
        if old.expires_at > now()?.saturating_add(60) {
            return Ok(old.access.clone());
        }
        let result = self.rotate(old, &record.subject).await;
        let access = match result {
            Ok(tokens) => {
                let access = tokens.access.clone();
                record.tokens = Some(tokens);
                Ok(access)
            }
            Err(e @ (Error::SignInRequired | Error::Identity | Error::GoogleScopeRequired)) => {
                record.tokens = None;
                Err(e)
            }
            Err(e) => return Err(e),
        };
        record.revision = uuid::Uuid::new_v4().to_string();
        self.0.store.write(&data)?;
        access
    }

    async fn rotate(&self, old: &Tokens, subject: &str) -> Result<Tokens, Error> {
        let inner = &self.0;
        let keys = inner.http.keys(&inner.endpoints).await?;
        let grant = inner
            .http
            .grant(
                &inner.endpoints,
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", &inner.client_id),
                    ("client_secret", inner.client_secret.expose_secret()),
                    ("refresh_token", old.refresh.expose_secret()),
                ],
            )
            .await?;
        if let Some(id) = &grant.id_token
            && inner.http.identity(&keys, id, &inner.client_id, None)?.sub != subject
        {
            return Err(Error::Identity);
        }
        let scopes = grant
            .scope
            .map(|s| scopes(&s))
            .unwrap_or_else(|| old.scopes.clone());
        check_scope(&scopes)?;
        Ok(Tokens {
            access: grant.access_token,
            refresh: grant.refresh_token.unwrap_or_else(|| old.refresh.clone()),
            id: grant.id_token.unwrap_or_else(|| old.id.clone()),
            expires_at: now()?.saturating_add(grant.expires_in),
            scopes,
        })
    }

    /// Revoke the grant at Google and clear local tokens even if revocation
    /// could not be confirmed. The account remains available for reauthorization.
    pub async fn sign_out(&self, account: &str) -> Result<SignOut, Error> {
        self.revoke(account, false).await
    }

    /// Revoke the grant and forget this registration, including its display
    /// label. A later sign-in for the same subject receives a new local ID.
    pub async fn remove_account(&self, account: &str) -> Result<SignOut, Error> {
        self.revoke(account, true).await
    }

    async fn revoke(&self, account: &str, remove: bool) -> Result<SignOut, Error> {
        let auth = self.clone();
        let id = account.to_owned();
        tokio::spawn(async move { auth.disconnect(&id, remove).await })
            .await
            .map_err(|_| Error::Cancelled)?
    }

    async fn disconnect(&self, id: &str, remove: bool) -> Result<SignOut, Error> {
        let inner = &self.0;
        let _lease = inner.store.lock().await?;
        let mut data = inner.store.read()?;
        let record = data
            .accounts
            .get_mut(id)
            .filter(|r| self.owns(r))
            .ok_or(Error::SignInRequired)?;
        let result = if let Some(tokens) = &record.tokens {
            inner
                .http
                .revoke_fields(
                    &inner.endpoints,
                    &[("token", tokens.refresh.expose_secret())],
                )
                .await
        } else {
            Ok(())
        };
        if remove {
            data.accounts.remove(id);
        } else {
            record.tokens = None;
            record.revision = uuid::Uuid::new_v4().to_string();
        }
        inner.store.write(&data)?;
        Ok(if result.is_ok() {
            SignOut::Revoked
        } else {
            SignOut::LocalOnly
        })
    }
}

fn check_scope(granted: &[String]) -> Result<(), Error> {
    if granted.iter().any(|s| s == CLOUD) {
        Ok(())
    } else {
        Err(Error::GoogleScopeRequired)
    }
}

#[cfg(test)]
impl Google {
    pub(crate) fn fixture(directory: &Path, issuer: &str) -> Result<Self, Error> {
        let mut google = Self::new(
            directory,
            "fixture-google-client",
            "fixture-installed-client",
        )?;
        let inner = Arc::get_mut(&mut google.0).ok_or(Error::Configuration)?;
        inner.http.issuer = issuer.into();
        inner.endpoints = Discovery {
            issuer: issuer.into(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/api/accounts/oauth/token"),
            jwks_uri: format!("{issuer}/jwks"),
            revocation_endpoint: format!("{issuer}/revoke"),
        };
        Ok(google)
    }
}
