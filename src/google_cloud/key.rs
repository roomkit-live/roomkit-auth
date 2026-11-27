//! A service-account key and the assertion it signs: google-auth's
//! `service_account.Credentials`, as RoomKit's Python builds them from a key
//! file's contents.
//!
//! A key names its account (`client_email`), the token endpoint it is
//! exchanged at (`token_uri`) and its RSA private key, PKCS#8 or PKCS#1 in
//! PEM; `private_key_id`, when it has one, names the key in the assertion's
//! header. The assertion asks for the `cloud-platform` scope, for an hour,
//! of Google's token endpoint whatever the key's `token_uri`, as google-auth
//! writes it.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;

use super::json::{Member, dumps};
use crate::Error;

/// The scope every token is asked for: the only one Vertex AI takes.
pub(super) const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The audience of every assertion: Google's token endpoint.
const AUDIENCE: &str = "https://oauth2.googleapis.com/token";

/// How long an assertion asks a token for, in seconds.
const LIFETIME: i64 = 3600;

/// A service-account key, read.
pub(super) struct Key {
    email: String,
    key_id: Option<String>,
    pub(super) token_uri: String,
    signer: RsaKeyPair,
    /// The project a request is billed to, when the key file names one.
    pub(super) quota_project: Option<String>,
}

/// The members of a key file the identity reads.
#[derive(Deserialize)]
struct Written {
    client_email: Option<String>,
    token_uri: Option<String>,
    private_key: Option<String>,
    private_key_id: Option<String>,
    quota_project_id: Option<String>,
}

impl Key {
    /// The key a key file's `contents` hold.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for contents that are no JSON object, that
    /// lack the account, the token endpoint or the private key, or whose
    /// private key is no RSA key in PEM.
    pub(super) fn read(contents: &str) -> Result<Self, Error> {
        let written: Written = serde_json::from_str(contents).map_err(|_| Error::Configuration)?;
        let (Some(email), Some(token_uri), Some(private_key)) =
            (written.client_email, written.token_uri, written.private_key)
        else {
            return Err(Error::Configuration);
        };
        let der = PrivateKeyDer::from_pem_slice(private_key.as_bytes())
            .map_err(|_| Error::Configuration)?;
        let signer = match &der {
            PrivateKeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(der) => RsaKeyPair::from_der(der.secret_pkcs1_der()),
            _ => return Err(Error::Configuration),
        };
        Ok(Self {
            email,
            key_id: written.private_key_id,
            token_uri,
            signer: signer.map_err(|_| Error::Configuration)?,
            quota_project: written.quota_project_id,
        })
    }

    /// The assertion the key signs at `now`, in seconds since 1970.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] when the key cannot sign.
    pub(super) fn assertion(&self, now: f64) -> Result<String, Error> {
        let mut header = vec![("typ", Member::Text("JWT")), ("alg", Member::Text("RS256"))];
        if let Some(key_id) = &self.key_id {
            header.push(("kid", Member::Text(key_id)));
        }
        // Python counts whole seconds, its clock read down to one.
        #[expect(clippy::cast_possible_truncation, reason = "a date in seconds")]
        let issued = now.floor() as i64;
        let claims = [
            ("iat", Member::Number(issued)),
            ("exp", Member::Number(issued.saturating_add(LIFETIME))),
            ("iss", Member::Text(&self.email)),
            ("aud", Member::Text(AUDIENCE)),
            ("scope", Member::Text(SCOPE)),
        ];
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(dumps(&header)),
            URL_SAFE_NO_PAD.encode(dumps(&claims))
        );
        let mut signature = vec![0; self.signer.public().modulus_len()];
        self.signer
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::Configuration)?;
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

impl std::fmt::Debug for Key {
    /// The account, never the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}
