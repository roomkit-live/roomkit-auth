//! A user's credentials, as gcloud writes them for Application Default
//! Credentials (`authorized_user`): google-auth's
//! `google.oauth2.credentials.Credentials`, refreshed with its refresh token.

use serde::Deserialize;

use super::token::{Granted, Sender};
use crate::{Error, Secret, secret::plain};

/// Where a user's token is refreshed when the file names no endpoint.
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// A user's credentials, read.
pub(super) struct User {
    client_id: String,
    client_secret: Secret,
    refresh_token: Secret,
    token_uri: String,
    pub(super) quota_project: Option<String>,
}

#[derive(Deserialize)]
struct Written {
    client_id: Option<String>,
    #[serde(default, deserialize_with = "plain::optional")]
    client_secret: Option<Secret>,
    #[serde(default, deserialize_with = "plain::optional")]
    refresh_token: Option<Secret>,
    token_uri: Option<String>,
    quota_project_id: Option<String>,
}

impl User {
    /// The credentials a file's `contents` hold.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for contents that lack the client's id, its
    /// secret or the refresh token, as google-auth refuses them.
    pub(super) fn read(contents: &serde_json::Value) -> Result<Self, Error> {
        let written = Written::deserialize(contents).map_err(|_| Error::Configuration)?;
        let (Some(client_id), Some(client_secret), Some(refresh_token)) = (
            written.client_id,
            written.client_secret,
            written.refresh_token,
        ) else {
            return Err(Error::Configuration);
        };
        Ok(Self {
            client_id,
            client_secret,
            refresh_token,
            token_uri: written.token_uri.unwrap_or_else(|| TOKEN_URI.to_owned()),
            quota_project: written.quota_project_id,
        })
    }

    /// A token, its refresh token spent on it, at `now`.
    pub(super) async fn granted(&self, sender: &Sender, now: f64) -> Result<Granted, Error> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret()),
            ("refresh_token", self.refresh_token.expose_secret()),
        ];
        sender.granted(&self.token_uri, &form, now).await
    }
}

impl std::fmt::Debug for User {
    /// The client, never its secret nor the refresh token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}
