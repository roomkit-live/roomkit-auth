//! Exchange one validated callback and verify identity before changing storage.

use crate::store::{Record, Tokens};
use crate::{Account, ChatGpt, Error, Secret, callback::Authorization, http, now, scopes};

pub(super) struct Exchange {
    pub auth: ChatGpt,
    pub existing: Option<Record>,
    pub discovery: http::Discovery,
    pub redirect: String,
    pub nonce: Secret,
    pub verifier: Secret,
}

impl Exchange {
    pub async fn complete(self, callback: Authorization) -> Result<Account, Error> {
        let client_id = match (&self.existing, callback.client_id) {
            (Some(record), None) => record.client_id.clone(),
            (Some(record), Some(id)) if id == record.client_id => id,
            (None, Some(id)) if http::text(&id, 256) && id != "dynamic_agent_client" => id,
            _ => return Err(Error::Identity),
        };
        let keys = self.auth.inner.http.keys(&self.discovery).await?;
        let grant = self.grant(&client_id, &callback.code).await?;
        let record = self.verified_record(client_id, grant, &keys)?;
        super::save(&self.auth, self.existing.as_ref(), record).await
    }

    async fn grant(&self, client_id: &str, code: &str) -> Result<http::Grant, Error> {
        self.auth
            .inner
            .http
            .grant(
                &self.discovery,
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", client_id),
                    ("code", code),
                    ("code_verifier", self.verifier.expose_secret()),
                    ("redirect_uri", &self.redirect),
                    ("resource", &self.auth.inner.http.resource),
                ],
            )
            .await
    }

    fn verified_record(
        &self,
        client_id: String,
        grant: http::Grant,
        keys: &jsonwebtoken::jwk::JwkSet,
    ) -> Result<Record, Error> {
        let id_token = grant.id_token.ok_or(Error::Identity)?;
        let claims = self.auth.inner.http.identity(
            keys,
            &id_token,
            &client_id,
            Some(self.nonce.expose_secret()),
        )?;
        if self.existing.as_ref().is_some_and(|record| {
            record.issuer != self.auth.inner.http.issuer || record.subject != claims.sub
        }) {
            return Err(Error::Identity);
        }
        Ok(Record {
            id: self.existing.as_ref().map_or_else(
                || uuid::Uuid::new_v4().to_string(),
                |record| record.id.clone(),
            ),
            client_id,
            issuer: self.auth.inner.http.issuer.clone(),
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
        })
    }
}
