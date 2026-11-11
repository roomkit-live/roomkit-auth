//! One callback contract for browser redirects and manually pasted URLs.

use std::collections::BTreeMap;

use crate::{Error, http::text};

pub(crate) struct Authorization {
    pub code: String,
    pub client_id: Option<String>,
}

pub(crate) enum Callback {
    Authorized(Authorization),
    Rejected(Error),
}

impl Callback {
    pub fn authorization(self) -> Result<Authorization, Error> {
        match self {
            Self::Authorized(code) => Ok(code),
            Self::Rejected(error) => Err(error),
        }
    }
}

/// An invalid paste never consumes the pending attempt. A validated denial
/// does: its state and callback URI must match before its error is accepted.
pub(crate) fn parse(value: &str, redirect: &url::Url, state: &str) -> Result<Callback, Error> {
    let value = value.trim();
    if value.len() > 16_384 || value.chars().any(char::is_control) {
        return Err(Error::InvalidCallback);
    }
    let url = url::Url::parse(value).map_err(|_| Error::InvalidCallback)?;
    if url.origin() != redirect.origin()
        || url.path() != redirect.path()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::InvalidCallback);
    }
    let mut fields = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if fields
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(Error::InvalidCallback);
        }
    }
    if fields.get("state").map(String::as_str) != Some(state) {
        return Err(Error::InvalidCallback);
    }
    outcome(fields)
}

fn outcome(mut fields: BTreeMap<String, String>) -> Result<Callback, Error> {
    if let Some(error) = fields.get("error") {
        if fields.contains_key("code") {
            return Err(Error::InvalidCallback);
        }
        return Ok(Callback::Rejected(if error == "access_denied" {
            Error::Denied
        } else {
            Error::Protocol
        }));
    }
    let code = fields
        .remove("code")
        .filter(|code| text(code, 8192))
        .ok_or(Error::InvalidCallback)?;
    Ok(Callback::Authorized(Authorization {
        code,
        client_id: fields.remove("client_id"),
    }))
}
