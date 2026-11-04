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
or a desktop application, where the browser runs on the same machine.

It does not fit:

- **a paid or remotely hosted application:** OpenAI asks you to complete its
  [interest form](https://openai.com/form/sign-in-with-chatgpt-interest/) first;
- **a machine without a local browser:** the sign-in returns to a listener on
  `127.0.0.1`, and there is no device-code flow;
- **Windows:** only Linux and macOS are supported. Elsewhere, `ChatGpt::new`
  returns `Error::Storage`.

## Install

```sh
cargo add roomkit-auth
cargo add tokio --features macros,rt
```

This needs Rust 1.92 or newer and a C compiler for the cryptography libraries.

## Quick start

This complete program signs in once, then reuses the saved account on later runs:

```rust,no_run
use roomkit_auth::ChatGpt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A private directory of your application, and its actual name, which people
    // see when they approve it.
    let auth = ChatGpt::new("/path/to/app-state/auth", "Example App")?;

    let saved = auth.accounts()?.into_iter().find(|a| a.connected && a.plan_usage);
    let account = match saved {
        Some(account) => account,
        None => {
            let sign_in = auth.sign_in(None).await?;
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

To try the flow from a clone of this repository, run
`cargo run --example sign_in -- /private/state/auth`. It signs in for real and
lists your models. The automated tests never contact OpenAI: they use a local fake
issuer and a clearly marked, public test signing key.

## Make a model request

The crate stops at the token. Send model requests to the
[Responses API](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
yourself, with `store: false` and `stream: true`, as this flow requires:

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
`models()` instead of hard-coding one.

## API overview

| Call | What it does |
| --- | --- |
| `ChatGpt::new(directory, app_name)` | Opens the private directory, creating it if needed. No network access. |
| `accounts()` | Lists saved accounts, including signed-out ones. Never returns tokens. |
| `sign_in(None)` | Adds an account through the browser. |
| `sign_in(Some(id))` | Signs in again to a saved account, without asking the user to choose one. |
| `access_token(id)` | Returns a valid bearer token, renewing it when it is about to expire. |
| `models(id)` | Lists the models this account can use, in the service's order. |
| `sign_out(id)` | Revokes the grant and clears the tokens. Keeps the account for a later sign-in. |
| `remove_account(id)` | Revokes the grant and deletes everything stored for the account. |

`sign_in` returns a `SignIn`. Open `url()`, then await `wait()`, which returns the
`Account` once it is verified and stored. Dropping a `SignIn` cancels it, and it
expires after ten minutes.

An `Account` is one registration: a verified ChatGPT login together with the
client ID OpenAI issued for it. Signing in again under the same registration
updates it and keeps its ID. One login can have several, for example one per
workspace, and they can share an email address. So save `Account::id` in your
configuration to refer to an account, and use `email` only as a label. One
directory holds up to 64 accounts.

The [API documentation](https://docs.rs/roomkit-auth) has the details.

## Handle errors

Every `Error` message is safe to show to the user: none contains a token, a URL
or a response from the service. The enum may grow, so keep a catch-all arm.

| Error | What it means | What to do |
| --- | --- | --- |
| `SignInRequired` | The account is signed out, its token can no longer be used, or it does not exist. | Check `accounts()`, then `sign_in(Some(id))` or `sign_in(None)`. |
| `PlanUsageRequired` | The user signed in but did not grant ChatGPT plan usage. | `sign_in(Some(id))`, and ask them to approve it. |
| `Identity` | The signed-in identity could not be verified. | Sign in again. |
| `Denied`, `Timeout`, `Cancelled` | The user declined, did not finish in time, or the attempt was replaced. | Offer a new attempt. |
| `AccountLimit` | The directory already holds 64 accounts. | `remove_account`. Signing out does not free a place. |
| `Storage` | The directory is not safe to use, or the platform is not supported. | Check its owner and permissions. |
| `Busy` | Another process held the credential lock for 30 seconds. | Try again. |
| `Network`, `Http(_)`, `Protocol` | The service could not be reached, refused, or answered unexpectedly. | Try again later. |
| `Configuration` | The application name is empty, over 100 bytes or contains control characters, or the system setup is invalid. | Fix the configuration. |

## Credentials and security

Credentials are stored **unencrypted** in `accounts.json`, in the directory you
choose. The directory must be private: the crate creates it with mode `0700`,
writes files with mode `0600`, and refuses an existing directory or file that
other users can reach, and symlinks. Writes are atomic, and processes sharing a
directory take turns through a lock file.

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
