//! A service account borrowed with another identity's token: google-auth's
//! `impersonated_credentials.Credentials`, asked of IAM Credentials
//! (`generateAccessToken`) for the `cloud-platform` scope, for an hour.
//!
//! The account is borrowed as the configuration names it, its delegates
//! none (written `null`), or as an Application Default Credentials file of
//! type `impersonated_service_account` names it, at its URL, with its
//! delegates. The request is sent once; a refusal says its status alone.

use serde::Deserialize;
use serde_json::{Value, json};

use super::key::SCOPE;
use super::token::{Granted, Sender, bounded};
use crate::{Error, Secret, secret::plain};

/// Where IAM Credentials lends the token of a service account.
const IAM_CREDENTIALS: &str = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts";

/// How long a borrowed token is asked for.
const LIFETIME: &str = "3600s";

/// What is borrowed, and how.
#[derive(Debug)]
pub(super) struct Borrowing {
    /// The URL the token is asked at.
    pub(super) url: String,
    /// The accounts the borrowing goes through, `None` written `null`.
    pub(super) delegates: Option<Vec<String>>,
}

impl Borrowing {
    /// The account `target`, as a configuration names it.
    pub(super) fn of(target: &str) -> Self {
        Self {
            url: format!("{IAM_CREDENTIALS}/{target}:generateAccessToken"),
            delegates: None,
        }
    }

    /// The borrowing an `impersonated_service_account` file states: its URL
    /// and its delegates.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] for a file that names no URL.
    pub(super) fn read(contents: &Value) -> Result<Self, Error> {
        let url = contents
            .get("service_account_impersonation_url")
            .and_then(Value::as_str)
            .ok_or(Error::Configuration)?;
        let delegates = match contents.get("delegates") {
            None | Some(Value::Null) => Some(Vec::new()),
            Some(Value::Array(delegates)) => {
                let named = delegates
                    .iter()
                    .map(|delegate| delegate.as_str().map(str::to_owned));
                Some(named.collect::<Option<_>>().ok_or(Error::Configuration)?)
            }
            Some(_) => return Err(Error::Configuration),
        };
        Ok(Self {
            url: url.to_owned(),
            delegates,
        })
    }

    /// The token IAM Credentials lends for `source`, the borrower's token.
    pub(super) async fn granted(&self, sender: &Sender, source: &Secret) -> Result<Granted, Error> {
        let body = json!({"delegates": self.delegates, "scope": [SCOPE], "lifetime": LIFETIME});
        let body = serde_json::to_vec(&body).map_err(|_| Error::Configuration)?;
        let request = sender
            .http
            .post(sender.target(&self.url)?)
            .bearer_auth(source.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let answer = request.send().await.map_err(|_| Error::Network)?;
        let status = answer.status().as_u16();
        let body = bounded(answer).await?;
        if status != 200 {
            return Err(Error::Http(status));
        }
        let lent: Lent = serde_json::from_slice(&body).map_err(|_| Error::Protocol)?;
        let expires_at = seconds_of(&lent.expire_time).ok_or(Error::Protocol)?;
        Ok(Granted {
            token: lent.access_token,
            expires_at: Some(expires_at),
        })
    }
}

/// IAM Credentials' answer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Lent {
    #[serde(with = "plain")]
    access_token: Secret,
    expire_time: String,
}

/// The seconds since 1970 of an RFC 3339 date in UTC
/// (`2026-01-01T01:00:00Z`, its fraction of a second kept), as IAM
/// Credentials writes `expireTime`.
fn seconds_of(date: &str) -> Option<f64> {
    let date = date.strip_suffix('Z')?;
    let (day, time) = date.split_once('T')?;
    let mut day = day.splitn(3, '-').map(str::parse::<i64>);
    let (year, month, of_month) = (day.next()?.ok()?, day.next()?.ok()?, day.next()?.ok()?);
    let mut time = time.splitn(3, ':');
    let hour = time.next()?.parse::<i64>().ok()?;
    let minute = time.next()?.parse::<i64>().ok()?;
    let second = time.next()?.parse::<f64>().ok()?;
    let in_range = (1..=12).contains(&month)
        && (1..=31).contains(&of_month)
        && (0..24).contains(&hour)
        && (0..60).contains(&minute)
        && (0.0..61.0).contains(&second);
    if !in_range {
        return None;
    }
    // Days since 1970-01-01 of a date of the proleptic Gregorian calendar.
    let (year, month) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * month + 2) / 5 + of_month - 1;
    let of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    let days = era * 146_097 + of_era_days - 719_468;
    #[expect(clippy::cast_precision_loss, reason = "a date in seconds")]
    let whole = (days * 86_400 + hour * 3600 + minute * 60) as f64;
    Some(whole + second)
}

#[cfg(test)]
mod tests {
    use super::seconds_of;

    // Python: datetime.datetime(2026, 1, 1, 1, tzinfo=datetime.UTC).timestamp()
    #[test]
    fn an_expiry_reads_as_seconds_since_1970() {
        assert_eq!(seconds_of("2026-01-01T01:00:00Z"), Some(1_767_229_200.0));
        assert_eq!(seconds_of("1970-01-01T00:00:00.5Z"), Some(0.5));
        assert_eq!(seconds_of("2024-02-29T12:00:00Z"), Some(1_709_208_000.0));
        assert_eq!(seconds_of("2026-01-01T01:00:00+01:00"), None);
        assert_eq!(seconds_of("2026-13-01T01:00:00Z"), None);
    }
}
