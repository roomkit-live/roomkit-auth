# RoomKit Auth

**Let your local Rust application use a person's ChatGPT plan, without an API key.**

[![CI](https://github.com/roomkit-live/roomkit-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/roomkit-live/roomkit-auth/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/roomkit-auth)](https://crates.io/crates/roomkit-auth)
[![docs.rs](https://img.shields.io/docsrs/roomkit-auth)](https://docs.rs/roomkit-auth)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/roomkit-live/roomkit-auth/blob/main/LICENSE)
[![MSRV: 1.92](https://img.shields.io/badge/MSRV-1.92-orange.svg)](https://github.com/roomkit-live/roomkit-auth/blob/main/Cargo.toml)

RoomKit Auth implements [Sign in with ChatGPT](https://developers.openai.com/siwc/token-sharing-open-source)
for applications that run on the user's own machine. The person approves your
application in their browser, and your application gets an access token for
OpenAI's Responses API that draws on their ChatGPT plan. You need no OpenAI API
key or client secret, and your application gets no access to their ChatGPT
conversations.

The crate handles the parts that are easy to get wrong: registering your
application, verifying who signed in, storing credentials safely, renewing
tokens and revoking them. Your application keeps the rest: opening the browser,
its interface and the model requests.

ChatGPT is the only provider today. The crate was written for
[RoomKit](https://github.com/roomkit-live/roomkit) applications but does not
depend on RoomKit: it works in any Rust application that uses Tokio.

> **Early development.** The API may change before 1.0. OpenAI's flow also has
> [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
> and [conditions](#openais-conditions) your application must follow.

## When it fits

It fits an open-source or locally hosted application, such as a command-line tool
or a desktop application. The browser may run on the same machine or on another
computer when using the manual callback described below.

It does not fit:

- **a paid or remotely hosted application:** OpenAI asks you to complete its
  [interest form](https://openai.com/form/sign-in-with-chatgpt-interest/) first;
- **Windows:** `ChatGpt::new` returns `Error::Storage`. Linux and macOS are the
  supported platforms.

## Install

```sh
cargo add roomkit-auth
cargo add tokio --features macros,rt
```

This needs Rust 1.92 or newer and a C compiler for the cryptography libraries.

## Quick start

This complete program signs in once, then reuses the saved account on later runs.
Your application opens the browser itself: the crate only gives it the URL.

```rust,no_run
use roomkit_auth::ChatGpt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A private directory of your application, and its actual name, which people
    // see when they approve it.
    let auth = ChatGpt::new("/path/to/app-state/auth", "Example App")?;

    // Use the saved account if it is ready. Otherwise sign in, passing a saved
    // account's ID so that it keeps its registration.
    let account = match auth.accounts()?.into_iter().next() {
        Some(account) if account.connected && account.plan_usage => account,
        saved => {
            let sign_in = auth.sign_in(saved.as_ref().map(|a| a.id.as_str())).await?;
            // A local URL. Open it in the user's browser, or show it to them.
            println!("Continue with ChatGPT: {}", sign_in.url());
            sign_in.wait().await?
        }
    };

    for model in auth.models(&account.id).await? {
        println!("{} ({})", model.name, model.id);
    }

    // Call this before each model request, including tool rounds: it renews the
    // token when needed.
    let token = auth.access_token(&account.id).await?;
    let (bearer, root) = (token.expose_secret(), roomkit_auth::CHATGPT_API_ROOT);
    println!("Token ready, {} bytes. Send it to {root} and nowhere else.", bearer.len());
    Ok(())
}
```

Three things to know when you adapt it:

- **The directory must be private.** `ChatGpt::new` creates it with mode `0700` if
  it is missing, and refuses an existing one that group or others can access. So
  use a dedicated directory inside your application's state directory, not a
  shared one such as `~/.config`.
- **Credentials can stop working.** `access_token` then returns
  `Error::SignInRequired` or `Error::Identity`: call `sign_in(Some(id))`.
- **People can refuse plan usage.** Plan usage is the permission to make requests
  on their ChatGPT plan, and they can sign in without granting it. `wait()` still
  succeeds, with `account.plan_usage` set to `false`, and `models` and
  `access_token` return `Error::PlanUsageRequired`. Use `sign_in(Some(id))` to ask
  again: `sign_in(None)` would create another registration.

### Sign in from another computer

For an SSH session, obtain `let remote = sign_in.remote()` and show `remote.url()`
instead of the loopback start URL. Open it in the laptop's browser. After consent,
the browser redirects to `127.0.0.1` and may show a connection error. Copy the
complete URL from its address bar into a private input in the host application,
then call `remote.submit_callback(&callback_url)` and await `sign_in.wait()`.

The callback contains a one-use authorization code, not an access or refresh
token. It must match the attempt's callback address and state. The original PKCE,
nonce, client ID and identity checks still apply. Invalid pasted URLs leave the
attempt open; a valid callback can be submitted once. Dropping the sign-in or its
wait future cancels the attempt, which otherwise expires after ten minutes.
The copied authorization link omits saved identity tokens and email hints, so
returning users select the account in the browser. Hosts must keep both URLs out
of logs and callback submissions out of conversation history.

To try the flow from a clone of this repository, run
`cargo run --example sign_in -- ~/.local/state/roomkit-auth-example`, with a path
that does not exist yet. It signs in for real and lists your models. The automated
tests never contact OpenAI: they use a local fake issuer and a clearly marked,
public test signing key.

## How it works

1. `sign_in` starts a listener on `127.0.0.1` and returns a local URL, which your
   application opens in the browser or shows to the person.
2. That URL redirects to OpenAI. The person signs in and approves your application
   under the name you gave, which they can edit. On a first sign-in, OpenAI issues
   a client ID for your application: this is a *registration*.
3. OpenAI sends the browser back to the listener. The crate exchanges the code for
   tokens, verifies the identity in the signed ID token and saves the account, and
   `wait()` returns it.
4. Before each model request, `access_token` returns a valid access token. When it
   renews one, OpenAI also replaces the refresh token, and the crate saves the new
   one under a lock that processes sharing the directory respect.

## Make a model request

The crate stops at the token. Send model requests to the
[Responses API](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
yourself, with `store: false` and `stream: true`, as this flow requires. The root
is `roomkit_auth::CHATGPT_API_ROOT`, and `$ACCESS_TOKEN` stands for
`token.expose_secret()`:

```sh
curl --no-buffer https://api.openai.com/v1/responses \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "<id from auth.models()>",
    "input": [{"role": "user", "content": "Hello"}],
    "store": false,
    "stream": true
  }'
```

Which models exist depends on the signed-in account, so list them with
`models()` instead of hard-coding one. OpenAI documents the [errors these requests
can return](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery),
such as a 403 when plan usage is unavailable for the user and a 429 at the usage
limit, and what to do about each.

## API overview

| Call | What it does |
| --- | --- |
| `ChatGpt::new(directory, app_name)` | Opens the private directory, creating it if needed. No network access. |
| `accounts()` | Lists saved accounts, including signed-out ones. Never returns tokens. |
| `sign_in(None)` | Adds an account through the browser, or updates it if that registration is already saved. |
| `sign_in(Some(id))` | Signs in again to a saved account. If it lacks plan usage, OpenAI asks the person to approve again. |
| `access_token(id)` | Returns a valid bearer token, renewing it when it is about to expire. |
| `models(id)` | Lists the models the service shows for this account, in its order. |
| `sign_out(id)` | Tries to revoke the application's access, then clears the tokens in any case. Keeps the account for a later sign-in. |
| `remove_account(id)` | Tries to revoke the application's access, then deletes everything stored for the account. |

`sign_in` returns a `SignIn`. Open `url()`, then await `wait()`, which returns the
`Account` once it is verified and stored. Dropping a `SignIn` cancels it, and it
expires after ten minutes.

`sign_out` and `remove_account` return `SignOut::Revoked`, or `SignOut::LocalOnly`
if OpenAI did not confirm the revocation. In that case, tell the person they can
disconnect the application in their ChatGPT settings.

An `Account` is one registration: a verified ChatGPT login together with the
client ID OpenAI issued for it. Signing in again under the same registration
updates it and keeps its ID. One login can have several, for example one per
ChatGPT workspace, and they can share an email address. So save `Account::id` in
your configuration to refer to an account, and use `email` only as a label. One
directory holds up to 64 accounts.

The [API documentation](https://docs.rs/roomkit-auth) has the details.

## Handle errors

Show errors with `{error}`: returning one from `main`, as the quick start does,
prints only its name. Every message is safe to show to the user: none contains a
token, a URL or a response from the service. The enum may grow, so keep a catch-all
arm.

| Error | What it means | What to do |
| --- | --- | --- |
| `SignInRequired` | The account is signed out, its token can no longer be used, or it does not exist. | Check `accounts()`, then `sign_in(Some(id))` or `sign_in(None)`. |
| `PlanUsageRequired` | The person did not grant plan usage, or a renewal no longer includes it. | `sign_in(Some(id))` if they choose to enable it. |
| `Identity` | The signed-in identity could not be verified. | Sign in again. |
| `Denied` | The person declined in the browser. | Offer a new attempt. |
| `Timeout` | The sign-in was not finished within ten minutes. | Offer a new attempt. |
| `Cancelled` | The account changed during the sign-in: it was removed or signed out, or its token was renewed. | Offer a new attempt. |
| `AccountLimit` | The directory holds 64 accounts, so `sign_in(None)` is refused. | `sign_in(Some(id))` for a saved account, or `remove_account` to free a place. Signing out does not free one. |
| `Storage` | The directory or a file in it is open to group or others, is a symlink, is corrupt or cannot be written, or the platform is not supported. | Check the modes (`0700` directory, `0600` files) and that `accounts.json` comes from this crate. |
| `Busy` | Another task or process held the credential lock for 30 seconds. | Try again. |
| `Network` | The service could not be reached, or the local listener could not start. | Try again later. |
| `Http(status)` | The service refused the request. | Try again later after a 5xx or a 429. After another 4xx, do not repeat the same request. |
| `Protocol` | The service answered in an unexpected way. | Try again later. |
| `Configuration` | The application name is empty, over 100 bytes or contains control characters, or the system setup is invalid. | Fix the configuration. |

## Credentials and security

Credentials are stored **unencrypted** in `accounts.json`, in the directory you
choose, next to the lock file `accounts.lock`. The crate creates the directory with
mode `0700` and its files with mode `0600`. It refuses symlinks, and any directory
or file whose mode gives group or others access; it checks the mode, not the owner.
Writes are atomic, and processes sharing a directory take turns through the lock.

- Keep the directory out of projects, source control, logs and shared backups.
- Keep the `SignIn::url` address out of logs. It holds no token, but anyone who
  reads it while the attempt is pending can interfere with that attempt.
- Send tokens only to `CHATGPT_API_ROOT`.

`Secret`, the token type, hides its value in `Debug`, implements no serialization
trait and clears its memory on drop. A refresh or a revocation that has started
finishes its storage work even if the caller is cancelled.

Report vulnerabilities privately, as described in
[SECURITY.md](https://github.com/roomkit-live/roomkit-auth/blob/main/SECURITY.md).

## OpenAI's conditions

This crate's license covers its code, not access to OpenAI's service. RoomKit
Auth is an independent project, not affiliated with or endorsed by OpenAI. Your
application is responsible for following OpenAI's terms:

- OpenAI documents this flow as ChatGPT plan usage [for open-source and locally
  hosted apps](https://developers.openai.com/siwc/token-sharing-open-source).
- The flow has [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
  on the fields, tools and inputs it accepts.
- Label the sign-in action **Continue with ChatGPT**, as the
  [UI/UX guidelines](https://developers.openai.com/siwc/ui-ux-guidelines) say.

What an account can do depends on its plan, its granted scopes and the models
available to it. The crate does not promise eligibility or a fixed model list.

## Contributing

Bug reports, documentation and fixes are welcome: see
[CONTRIBUTING.md](https://github.com/roomkit-live/roomkit-auth/blob/main/CONTRIBUTING.md),
the [Code of Conduct](https://github.com/roomkit-live/roomkit-auth/blob/main/CODE_OF_CONDUCT.md)
and the [changelog](https://github.com/roomkit-live/roomkit-auth/blob/main/CHANGELOG.md).

## License

[MIT](https://github.com/roomkit-live/roomkit-auth/blob/main/LICENSE)
