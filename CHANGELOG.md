# Changelog

## Unreleased

- Sign in from another computer with `SignIn::remote()`: open the authorization
  link there and submit its complete callback URL. The same PKCE and identity
  checks apply, and copied links omit retained identity tokens and email hints.

## 0.1.0

- Sign in with ChatGPT for local applications: browser consent on a loopback
  callback, verified identity and one entry per registration.
- Token refresh with rotation under a cross-process lock, revocation, and
  account-specific model discovery.
- `sign_out` keeps an account for reauthorization; `remove_account` deletes it.
- `sign_in(Some(id))` asks for consent again when an account lacks plan usage.
