# RoomKit Auth

Reusable Rust authentication for applications built with RoomKit. Independent
of the engine, agent behavior, tools and terminal interface. Linux and macOS;
Rust 1.92 or newer, in a Tokio runtime. This early API may change before the
first stable release.

The initial provider implements [Sign in with ChatGPT for local applications](https://developers.openai.com/siwc/token-sharing-open-source/sign-in):

- Dynamic registration under the host application's actual name, with a stable
  installation ID, PKCE, state, nonce and a loopback callback.
- Signed ID-token verification (RS256/JWKS, issuer, audience, expiry, nonce and
  verified subject). Reauthorization cannot replace another account's identity.
- One entry per registration, with separate grants, including identity-only
  authorization. A registration is the verified subject with the issued client
  ID: signing in again under it updates the entry and keeps its ID, and another
  registration of one login, such as another workspace, keeps its own entry.
- Refresh before expiry, rotation persisted atomically under a cross-process
  lock, and revocation with explicit reporting when only local sign-out succeeds.
- Account-specific model discovery from the public API, preserving server order.

There is no browser launcher, UI, agent loop, model inference or Python binding
in this crate. Applications open the returned local URL in a browser and choose
which account each provider uses. No existing application's credentials are read.

```rust,no_run
async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let auth = roomkit_auth::ChatGpt::new("/path/to/private/app-state/auth", "Example App")?;
    let sign_in = auth.sign_in(None).await?;
    // Open sign_in.url() using your application's browser integration.
    let account = sign_in.wait().await?;
    let models = auth.models(&account.id).await?;
    // Before EACH inference request, including tool rounds:
    let credential = auth.access_token(&account.id).await?;
    // Send credential.expose_secret() only to roomkit_auth::CHATGPT_API_ROOT.
    Ok(())
}
```

Run the browser-flow example with `cargo run --example sign_in -- /private/state/auth`.
It starts a real interactive sign-in only when explicitly run. Automated tests
use a loopback OAuth issuer and a clearly marked, public test signing key.

## Accounts and credentials

`sign_out` revokes the grant and clears the tokens, and keeps the account's
identity and client ID so it can reauthorize. `remove_account` revokes the grant
and deletes all of it. One directory holds up to 64 accounts; beyond that,
`sign_in` returns `Error::AccountLimit` until one is removed.

Credentials are stored **unencrypted** in owner-only files (`0600`, directory
`0700`). Writes are atomic; unsafe permissions and symlinks are refused. Keep
this directory out of projects, backups shared with others, logs and source
control. Secret values redact `Debug`, implement no serde trait and zero their
owned strings on drop. HTTP errors never include remote response bodies or
credential-bearing URLs. A pending sign-in cancels when dropped and expires after
ten minutes. Started refresh/revocation operations finish storage cleanup despite
caller cancellation.

## OpenAI's conditions

This crate's license covers its code, not access to OpenAI's service. RoomKit
Auth is an independent project, not affiliated with or endorsed by OpenAI. Your
application is responsible for following OpenAI's terms:

- OpenAI documents this flow as ChatGPT plan usage [for open-source and locally
  hosted apps](https://developers.openai.com/siwc/token-sharing-open-source). To
  offer it in a paid or remotely hosted app, it asks you to complete its
  [interest form](https://openai.com/form/sign-in-with-chatgpt-interest/).
- The flow has [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
  on the fields, tools and inputs it accepts.
- Label the action **Continue with ChatGPT**, as the [UI/UX guidelines](https://developers.openai.com/siwc/ui-ux-guidelines)
  say.

ChatGPT access depends on the account's granted scopes and available models.
Use the [public Responses API](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
with `store: false`, `stream: true` and the route's supported tool format. The
library does not promise account eligibility or a fixed model catalogue.

## Security

Report vulnerabilities privately, as described in
[SECURITY.md](https://github.com/roomkit-live/roomkit-auth/blob/main/SECURITY.md).
