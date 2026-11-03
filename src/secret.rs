use std::fmt;

use zeroize::Zeroize;

/// A credential whose debug representation is redacted and storage is cleared
/// on drop. Callers must not log or persist its exposed value unprotected.
///
/// It implements no serde trait, so a host's own type cannot write it out by
/// accident:
///
/// ```compile_fail
/// fn serializable<T: serde::Serialize>() {}
/// serializable::<roomkit_auth::Secret>();
/// ```
#[derive(Clone)]
pub struct Secret(pub(crate) String);

impl Secret {
    /// Borrow the credential for an authenticated request.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

/// Serde for the two places a credential may cross as plain text: the token
/// response and the private store. Use with `#[serde(with = "...")]`.
pub(crate) mod plain {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::Secret;

    pub fn serialize<S: Serializer>(secret: &Secret, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&secret.0)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        String::deserialize(deserializer).map(Secret)
    }

    pub fn optional<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Secret>, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.map(Secret))
    }
}
