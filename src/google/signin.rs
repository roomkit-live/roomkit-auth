//! The Google authorization code flow for an installed application.
use super::{CLOUD, Google, GoogleAccount, check_scope};
use crate::{
    Error, SignIn,
    callback::Authorization,
    http, now, scopes,
    signin::{Browser, save},
    store::{MAX_ACCOUNTS, Record, Tokens},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub(super) async fn begin(
    auth: Google,
    account: Option<&str>,
) -> Result<SignIn<GoogleAccount>, Error> {
    let data = auth.0.store.read()?;
    let existing = account
        .map(|id| {
            data.accounts
                .get(id)
                .filter(|r| auth.owns(r))
                .cloned()
                .ok_or(Error::SignInRequired)
        })
        .transpose()?;
    if existing.is_none() && data.accounts.len() >= MAX_ACCOUNTS {
        return Err(Error::AccountLimit);
    }
    let browser = Browser::new().await?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(browser.verifier.expose_secret()));
    let mut url = url::Url::parse(&auth.0.endpoints.authorization_endpoint)
        .map_err(|_| Error::Configuration)?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", auth.0.client_id.as_str()),
        ("redirect_uri", browser.redirect.as_str()),
        ("response_type", "code"),
        ("scope", &format!("openid email {CLOUD}")),
        ("access_type", "offline"),
        ("prompt", "consent select_account"),
        ("state", browser.state.expose_secret()),
        ("nonce", browser.nonce.expose_secret()),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let redirect = browser.redirect.clone();
    let nonce = browser.nonce.clone();
    let verifier = browser.verifier.clone();
    Ok(browser.start(url, move |callback| async move {
        let record = exchange(
            &auth,
            callback,
            redirect.as_str(),
            nonce.expose_secret(),
            verifier.expose_secret(),
            existing.as_ref(),
        )
        .await?;
        let saved = save(&auth.0.store, existing.as_ref(), record).await?;
        Ok(GoogleAccount::from(&saved))
    }))
}

async fn exchange(
    auth: &Google,
    callback: Authorization,
    redirect: &str,
    nonce: &str,
    verifier: &str,
    existing: Option<&Record>,
) -> Result<Record, Error> {
    let inner = &auth.0;
    let keys = inner.http.keys(&inner.endpoints).await?;
    let grant = inner
        .http
        .grant(
            &inner.endpoints,
            &[
                ("grant_type", "authorization_code"),
                ("code", &callback.code),
                ("redirect_uri", redirect),
                ("code_verifier", verifier),
                ("client_id", &inner.client_id),
                ("client_secret", inner.client_secret.expose_secret()),
            ],
        )
        .await?;
    let id_token = grant.id_token.ok_or(Error::Identity)?;
    let claims = inner
        .http
        .identity(&keys, &id_token, &inner.client_id, Some(nonce))?;
    if existing.is_some_and(|r| r.subject != claims.sub) {
        return Err(Error::Identity);
    }
    let scopes = scopes(&grant.scope.ok_or(Error::Protocol)?);
    check_scope(&scopes)?;
    let refresh = grant
        .refresh_token
        .or_else(|| existing?.tokens.as_ref().map(|t| t.refresh.clone()))
        .ok_or(Error::SignInRequired)?;
    Ok(Record {
        id: existing
            .map(|r| r.id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        client_id: inner.client_id.clone(),
        issuer: inner.http.issuer.clone(),
        subject: claims.sub,
        email: claims.email.filter(|s| http::text(s, 320)),
        revision: uuid::Uuid::new_v4().to_string(),
        tokens: Some(Tokens {
            access: grant.access_token,
            refresh,
            id: id_token,
            expires_at: now()?.saturating_add(grant.expires_in),
            scopes,
        }),
    })
}
