use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{Error, Secret};

pub(crate) const ISSUER: &str = "https://auth.openai.com";
pub(crate) const RESOURCE: &str = "https://api.openai.com/v1";

/// TLS with rustls's ring provider and the webpki roots: the same trust on
/// every host, and no system TLS library. HTTP/1.1 is offered by ALPN, as
/// reqwest's own rustls configuration does.
pub(crate) fn tls_config() -> Option<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Some(config)
}

#[derive(Clone, Debug)]
pub(crate) struct Http {
    client: reqwest::Client,
    pub issuer: String,
    pub resource: String,
}

#[derive(Deserialize)]
pub(crate) struct Discovery {
    issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
}

#[derive(Deserialize)]
pub(crate) struct Grant {
    pub access_token: Secret,
    pub refresh_token: Option<Secret>,
    pub id_token: Option<Secret>,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Claims {
    pub sub: String,
    pub email: Option<String>,
    nonce: Option<String>,
    aud: serde_json::Value,
    azp: Option<String>,
}

impl Http {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .tls_backend_preconfigured(tls_config().ok_or(Error::Configuration)?)
                // Answers come uncompressed whatever reqwest features the
                // host enables, as the service's limits expect.
                .no_gzip()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .map_err(|_| Error::Configuration)?,
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
        })
    }

    pub async fn discovery(&self) -> Result<Discovery, Error> {
        let mut discovery: Discovery = self
            .json(
                self.client
                    .get(format!("{}/.well-known/openid-configuration", self.issuer)),
            )
            .await?;
        if discovery.issuer != self.issuer {
            return Err(Error::Identity);
        }
        let origin = url::Url::parse(&self.issuer)
            .map_err(|_| Error::Configuration)?
            .origin();
        for endpoint in [
            &discovery.authorization_endpoint,
            &discovery.token_endpoint,
            &discovery.jwks_uri,
            &discovery.revocation_endpoint,
        ] {
            let url = url::Url::parse(endpoint).map_err(|_| Error::Protocol)?;
            if url.origin() != origin
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
            {
                return Err(Error::Protocol);
            }
        }
        // Native dynamic registration uses these documented account endpoints,
        // which can differ from the ordinary OIDC web-client endpoints.
        discovery.authorization_endpoint = format!("{}/api/accounts/authorize", self.issuer);
        discovery.token_endpoint = format!("{}/api/accounts/oauth/token", self.issuer);
        Ok(discovery)
    }

    pub async fn grant(
        &self,
        discovery: &Discovery,
        fields: &[(&str, &str)],
    ) -> Result<Grant, Error> {
        let response = self
            .client
            .post(&discovery.token_endpoint)
            .form(fields)
            .send()
            .await
            .map_err(|_| Error::Network)?;
        let status = response.status();
        if !status.is_success() {
            let body = body(response, 65_536).await?;
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            return Err(
                if error.get("error").and_then(|e| e.as_str()) == Some("invalid_grant") {
                    Error::SignInRequired
                } else {
                    Error::Http(status.as_u16())
                },
            );
        }
        let bytes = body(response, 65_536).await?;
        let grant: Grant = serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)?;
        if !grant.token_type.eq_ignore_ascii_case("Bearer")
            || !valid_secret(&grant.access_token)
            || grant.expires_in == 0
            || grant.expires_in > 365 * 86400
            || grant
                .refresh_token
                .as_ref()
                .is_some_and(|s| !valid_secret(s))
            || grant.id_token.as_ref().is_some_and(|s| !valid_secret(s))
        {
            return Err(Error::Protocol);
        }
        Ok(grant)
    }

    /// Fetch the signing keys. Callers do this before spending a code or a
    /// refresh token, so an outage here costs a retry, never a credential.
    pub async fn keys(&self, discovery: &Discovery) -> Result<JwkSet, Error> {
        self.json(self.client.get(&discovery.jwks_uri)).await
    }

    pub fn identity(
        &self,
        keys: &JwkSet,
        token: &Secret,
        client_id: &str,
        nonce: Option<&str>,
    ) -> Result<Claims, Error> {
        let header = decode_header(token.expose_secret()).map_err(|_| Error::Identity)?;
        if header.alg != Algorithm::RS256 {
            return Err(Error::Identity);
        }
        let kid = header.kid.ok_or(Error::Identity)?;
        let jwk = keys.find(&kid).ok_or(Error::Identity)?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| Error::Identity)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let claims = decode::<Claims>(token.expose_secret(), &key, &validation)
            .map_err(|_| Error::Identity)?
            .claims;
        if !text(&claims.sub, 1024)
            || nonce.is_some_and(|n| claims.nonce.as_deref() != Some(n))
            || claims.azp.as_deref().is_some_and(|id| id != client_id)
            || claims
                .aud
                .as_array()
                .is_some_and(|a| a.len() > 1 && claims.azp.as_deref() != Some(client_id))
        {
            return Err(Error::Identity);
        }
        Ok(claims)
    }

    pub async fn revoke(
        &self,
        discovery: &Discovery,
        client_id: &str,
        refresh: &Secret,
    ) -> Result<(), Error> {
        // Retain the credential for bounded retries; the caller clears it after
        // this operation and reports whether remote revocation was confirmed.
        for attempt in 0..3 {
            let result = self
                .client
                .post(&discovery.revocation_endpoint)
                .form(&[
                    ("client_id", client_id),
                    ("token", refresh.expose_secret()),
                    ("token_type_hint", "refresh_token"),
                ])
                .send()
                .await;
            match result {
                Ok(response) if response.status().as_u16() == 200 => return Ok(()),
                Ok(response) if !response.status().is_server_error() => {
                    return Err(Error::Http(response.status().as_u16()));
                }
                _ if attempt < 2 => {
                    tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt + 1))).await
                }
                _ => return Err(Error::Network),
            }
        }
        Err(Error::Network)
    }

    pub async fn models(&self, access: &Secret) -> Result<Vec<crate::Model>, Error> {
        let value: serde_json::Value = self
            .json(
                self.client
                    .get(format!("{}/models", self.resource))
                    .bearer_auth(access.expose_secret()),
            )
            .await?;
        let models = value
            .get("models")
            .and_then(|v| v.as_array())
            .ok_or(Error::Protocol)?;
        let mut result = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for model in models
            .iter()
            .filter(|m| m.get("visibility").and_then(|v| v.as_str()) == Some("list"))
        {
            let slug = model
                .get("slug")
                .and_then(|v| v.as_str())
                .filter(|s| text(s, 256))
                .ok_or(Error::Protocol)?;
            let label = model
                .get("display_name")
                .and_then(|v| v.as_str())
                .filter(|s| text(s, 256))
                .unwrap_or(slug);
            if seen.insert(slug) {
                result.push(crate::Model {
                    id: slug.into(),
                    name: label.into(),
                });
            }
            if result.len() == 500 {
                break;
            }
        }
        Ok(result)
    }

    async fn json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, Error> {
        let response = request.send().await.map_err(|_| Error::Network)?;
        if !response.status().is_success() {
            return Err(Error::Http(response.status().as_u16()));
        }
        serde_json::from_slice(&body(response, 1_048_576).await?).map_err(|_| Error::Protocol)
    }
}

async fn body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mut body = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Network)? {
        if body.len() + chunk.len() > limit {
            return Err(Error::Protocol);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn valid_secret(secret: &Secret) -> bool {
    text(secret.expose_secret(), 32_768)
}
