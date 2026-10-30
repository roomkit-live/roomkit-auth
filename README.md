# RoomKit Auth

Reusable Rust authentication for applications built with RoomKit. Independent
of the engine, agent behavior, tools and terminal interface. Linux and macOS;
Rust 1.92 or newer. This early API may change before the first stable release.

The initial provider implements [Sign in with ChatGPT for local applications](https://developers.openai.com/siwc/token-sharing-open-source/sign-in):

- Dynamic registration under the host application's actual name, with a stable
  installation ID, PKCE, state, nonce and a loopback callback.
- Signed ID-token verification (RS256/JWKS, issuer, audience, expiry, nonce and
  verified subject). Reauthorization cannot replace another account's identity.
- Separate registrations and grants, including identity-only authorization.
- Refresh before expiry, rotation persisted atomically under a cross-process
  lock, and revocation with explicit reporting when only local sign-out succeeds.
- Account-specific model discovery from the public API, preserving server order.

There is no browser launcher, UI, agent loop, model inference or Python binding
in this crate. Applications open the returned local URL in a browser and choose
which account each provider uses. No existing application's credentials are read.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let auth = roomkit_auth::ChatGpt::new("/path/to/private/app-state/auth", "Example App")?;
let sign_in = auth.sign_in(None).await?;
// Open sign_in.url() using your application's browser integration.
let account = sign_in.wait().await?;
let models = auth.models(&account.id).await?;
// Before EACH inference request, including tool rounds:
let credential = auth.access_token(&account.id).await?;
// Send credential.expose_secret() only to roomkit_auth::CHATGPT_API_ROOT.
# Ok(()) }
```

Run the browser-flow example with `cargo run --example sign_in -- /private/state/auth`.
It starts a real interactive sign-in only when explicitly run. Automated tests
use a loopback OAuth issuer and a clearly marked, public test signing key.

Credentials are stored **unencrypted** in owner-only files (`0600`, directory
`0700`). Writes are atomic; unsafe permissions and symlinks are refused. Keep
this directory out of projects, backups shared with others, logs and source
control. Secret values redact `Debug` and zero their owned strings on drop.
HTTP errors never include remote response bodies or credential-bearing URLs.
A pending sign-in cancels when dropped and expires after ten minutes. Started
refresh/revocation operations finish storage cleanup despite caller cancellation.

ChatGPT access depends on the account's granted scopes and available models.
Use the [public Responses API](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
with `store: false`, `stream: true` and the route's supported tool format. The
library does not promise account eligibility or a fixed model catalogue.

Run `make check`, `make msrv` and `make audit` before delivery.
