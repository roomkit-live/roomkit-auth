//! The identity of the machine, from its metadata server (Compute Engine,
//! GKE, Cloud Run): google-auth's `compute_engine.Credentials`, found as
//! `_get_gce_credentials` finds it.
//!
//! The machine is one when its metadata server answers a ping as Google's
//! (tried three times, after one second then two, while it gets no answer),
//! or, on Linux, when its product name says Google. Its token is then asked
//! as google-auth asks it the first time: the project, the account, then
//! the token; later, the token alone. Each request waits three seconds at
//! most. `GCE_METADATA_HOST` (or `GCE_METADATA_ROOT`) names the server,
//! `GCE_METADATA_IP` the address pinged, `GCE_METADATA_TIMEOUT` and
//! `GCE_METADATA_DETECT_RETRIES` the wait and the tries, `NO_GCE_CHECK`
//! (`true`) says the machine is none.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::environment::Environment;
use super::token::{Granted, Sender, bounded, jittered, read};
use crate::Error;

/// The server google-auth asks when no variable names one.
const HOST: &str = "metadata.google.internal";

/// The address it pings when no variable names one.
const ADDRESS: &str = "169.254.169.254";

/// The file a Linux machine names its product in.
const PRODUCT_NAME: &str = "/sys/class/dmi/id/product_name";

/// The header a request to the server carries, and its answer too.
const FLAVOR: &str = "metadata-flavor";

/// The metadata server, as the environment names it.
#[derive(Debug)]
pub(super) struct Machine {
    host: String,
    address: String,
    timeout: Duration,
    tries: u32,
    /// Whether `NO_GCE_CHECK` says the machine is none.
    unchecked: bool,
    /// Whether the product name says Google.
    google_product: bool,
    /// Whether the machine was found one, and its account read.
    found: AtomicBool,
}

impl Machine {
    /// The server `environment` names.
    pub(super) fn of(environment: &Environment) -> Self {
        let whole = |name: &str, default: u32| {
            let set = environment.set(name);
            set.and_then(|value| value.trim().parse::<u32>().ok())
                .unwrap_or(default)
        };
        let host = environment.set("GCE_METADATA_HOST");
        let host = host.or_else(|| environment.set("GCE_METADATA_ROOT"));
        let product = (environment.file)(Path::new(PRODUCT_NAME));
        let product = product.filter(|_| !environment.windows);
        Self {
            host: host.unwrap_or_else(|| HOST.to_owned()),
            address: environment
                .set("GCE_METADATA_IP")
                .unwrap_or_else(|| ADDRESS.to_owned()),
            timeout: Duration::from_secs(u64::from(whole("GCE_METADATA_TIMEOUT", 3))),
            tries: whole("GCE_METADATA_DETECT_RETRIES", 3),
            unchecked: environment.set("NO_GCE_CHECK").as_deref() == Some("true"),
            google_product: product.is_some_and(|name| name.trim().starts_with("Google")),
            found: AtomicBool::new(false),
        }
    }

    /// A token of the machine's account for `scope`, at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::NoCredentials`] where the machine is none; what a request
    /// to its server fails with.
    pub(super) async fn granted(
        &self,
        sender: &Sender,
        now: f64,
        scope: &str,
    ) -> Result<Granted, Error> {
        if !self.found.load(Ordering::Acquire) {
            if self.unchecked || !(self.pinged(sender).await || self.google_product) {
                return Err(Error::NoCredentials);
            }
            // What google-auth reads first, the project and the account; it
            // keeps neither here, the configuration naming the project.
            let _project = self.asked(sender, "project/project-id", None).await;
            let account = "instance/service-accounts/default/";
            self.asked(sender, account, Some(("recursive", "true")))
                .await?;
            self.found.store(true, Ordering::Release);
        }
        let token = "instance/service-accounts/default/token";
        let body = self.asked(sender, token, Some(("scopes", scope))).await?;
        read(&body, now)
    }

    /// Whether the server answers a ping as Google's: tried while it gets
    /// no answer, as many times as said.
    async fn pinged(&self, sender: &Sender) -> bool {
        let Ok(url) = sender.target(&format!("http://{}", self.address)) else {
            return false;
        };
        let mut wait = 1.0;
        for tried in 1..=self.tries {
            if tried > 1 {
                (sender.pace.wait)(jittered(wait)).await;
                wait *= 2.0;
            }
            let ping = sender.http.get(url.clone()).header(FLAVOR, "Google");
            if let Ok(answer) = ping.timeout(self.timeout).send().await {
                let flavor = answer.headers().get(FLAVOR).and_then(|v| v.to_str().ok());
                return answer.status().as_u16() == 200 && flavor == Some("Google");
            }
        }
        false
    }

    /// The body the server answers `path` with, its query `query`.
    async fn asked(
        &self,
        sender: &Sender,
        path: &str,
        query: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, Error> {
        let url = format!("http://{}/computeMetadata/v1/{path}", self.host);
        let mut url = sender.target(&url)?;
        if let Some((name, value)) = query {
            url.query_pairs_mut().append_pair(name, value);
        }
        let request = sender.http.get(url).header(FLAVOR, "Google");
        let answer = request.timeout(self.timeout).send().await;
        let answer = answer.map_err(|_| Error::Network)?;
        let status = answer.status().as_u16();
        let body = bounded(answer).await?;
        if status == 200 {
            Ok(body)
        } else {
            Err(Error::Http(status))
        }
    }
}
