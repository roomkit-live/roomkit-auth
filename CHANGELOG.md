# Changelog

## 0.1.0

- Sign in with ChatGPT for local applications: browser consent on a loopback
  callback, verified identity and one entry per registration.
- Token refresh with rotation under a cross-process lock, revocation, and
  account-specific model discovery.
- `sign_out` keeps an account for reauthorization; `remove_account` deletes it.
