//! A token asked of an OAuth 2.0 token endpoint, as google-auth asks it
//! (`oauth2._client._token_endpoint_request`).
//!
//! The form is posted at most three times: again after one second, then two,
//! while the answer is refused with a status google-auth takes for a passing
//! one (408, 429, 500, 503, 504), or names a passing error
//! (`internal_failure`, `server_error`, `temporarily_unavailable`). A
//! request that gets no answer is not tried again. A failure says neither
//! the endpoint nor what it answered: its status, at most.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::Value;

use crate::{Error, Secret, secret::plain};

/// How many times a form is posted at most.
const TRIES: u32 = 3;

/// The statuses google-auth tries a token request again after.
const PASSING_STATUSES: [u16; 5] = [408, 429, 500, 503, 504];

/// The errors google-auth tries a token request again after.
const PASSING_ERRORS: [&str; 3] = [
    "internal_failure",
    "server_error",
    "temporarily_unavailable",
];

/// The most bytes of an answer read.
const ANSWER_LIMIT: usize = 64 * 1024;

/// The time, in seconds since 1970.
#[doc(hidden)]
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// A wait of the time it is given.
#[doc(hidden)]
pub type Wait = Arc<dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A clock and the waits between tries, which a replay sets.
#[derive(Clone)]
#[doc(hidden)]
pub struct Pace {
    /// The time.
    pub now: Clock,
    /// Waits for as long as it is given.
    pub wait: Wait,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            now: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |since| since.as_secs_f64())
            }),
            wait: Arc::new(|wait| Box::pin(tokio::time::sleep(wait))),
        }
    }
}

impl std::fmt::Debug for Pace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pace").finish_non_exhaustive()
    }
}

/// A token, and when it expires, if the endpoint said. Its `Debug` shows
/// the token redacted, as [`Secret`] does.
#[derive(Debug)]
pub(super) struct Granted {
    pub(super) token: Secret,
    pub(super) expires_at: Option<f64>,
}

/// The answer of a token endpoint, as google-auth reads it.
#[derive(Deserialize)]
struct Answer {
    #[serde(with = "plain")]
    access_token: Secret,
    #[serde(default)]
    expires_in: Option<Value>,
}

/// Where the token requests go and how.
#[derive(Debug)]
pub(super) struct Sender {
    pub(super) http: reqwest::Client,
    /// Where a replay sends every request instead, over plain HTTP, each to
    /// its path and its query.
    pub(super) origin: Option<reqwest::Url>,
    pub(super) pace: Pace,
}

impl Sender {
    /// The URL `url` is sent to: itself, or the replay's origin.
    fn target(&self, url: &str) -> Result<reqwest::Url, Error> {
        let mut target = reqwest::Url::parse(url).map_err(|_| Error::Configuration)?;
        if let Some(origin) = &self.origin {
            let path = target.path().to_owned();
            let query = target.query().map(str::to_owned);
            target = origin.clone();
            target.set_path(&path);
            target.set_query(query.as_deref());
        }
        Ok(target)
    }

    /// The token `url` grants for `form`, asked at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Network`] for a request that got no answer,
    /// [`Error::Http`] for one refused, [`Error::Protocol`] for an answer
    /// that holds no token.
    pub(super) async fn granted(
        &self,
        url: &str,
        form: &[(&str, &str)],
        now: f64,
    ) -> Result<Granted, Error> {
        let target = self.target(url)?;
        let mut wait = 1.0;
        for tried in 1..=TRIES {
            if tried > 1 {
                (self.pace.wait)(jittered(wait)).await;
                wait *= 2.0;
            }
            let answer = self.http.post(target.clone()).form(form).send().await;
            let answer = answer.map_err(|_| Error::Network)?;
            let status = answer.status().as_u16();
            let body = bounded(answer).await?;
            if status == 200 {
                return read(&body, now);
            }
            if tried == TRIES || !passing(status, &body) {
                return Err(Error::Http(status));
            }
        }
        Err(Error::Network)
    }
}

/// The wait google-auth takes before a try: `wait`, less up to a tenth of
/// it, drawn at random (google-auth draws within a tenth either side).
fn jittered(wait: f64) -> Duration {
    let mut drawn = [0; 1];
    let less = SystemRandom::new()
        .fill(&mut drawn)
        .map_or(0.0, |()| f64::from(drawn[0]) / 255.0 * 0.1);
    Duration::from_secs_f64(wait * (1.0 - less))
}

/// Whether google-auth tries a request again after this refusal.
fn passing(status: u16, body: &[u8]) -> bool {
    if PASSING_STATUSES.contains(&status) {
        return true;
    }
    let Ok(Value::Object(said)) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    ["error", "error_description"].iter().any(|name| {
        let named = said.get(*name).and_then(Value::as_str);
        named.is_some_and(|named| PASSING_ERRORS.contains(&named))
    })
}

/// The token the answer `body` grants at `now`.
fn read(body: &[u8], now: f64) -> Result<Granted, Error> {
    let answer: Answer = serde_json::from_slice(body).map_err(|_| Error::Protocol)?;
    let lifetime = match answer.expires_in {
        None | Some(Value::Null) => None,
        Some(Value::Number(seconds)) => Some(seconds.as_f64().ok_or(Error::Protocol)?),
        // Some endpoints write it as text, which google-auth reads as a whole
        // number.
        Some(Value::String(seconds)) => {
            let seconds = seconds.trim().parse::<i64>().map_err(|_| Error::Protocol)?;
            #[expect(clippy::cast_precision_loss, reason = "a lifetime in seconds")]
            Some(seconds as f64)
        }
        Some(_) => return Err(Error::Protocol),
    };
    Ok(Granted {
        token: answer.access_token,
        expires_at: lifetime.map(|lifetime| now + lifetime),
    })
}

/// The body of `answer`, at most [`ANSWER_LIMIT`] bytes of it.
async fn bounded(mut answer: reqwest::Response) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = answer.chunk().await.map_err(|_| Error::Network)? {
        if body.len() + chunk.len() > ANSWER_LIMIT {
            return Err(Error::Protocol);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
