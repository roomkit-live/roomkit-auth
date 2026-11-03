# Contributing

Keep authentication independent of RoomKit engines, tools and user interfaces.
Use Rust 1.92 or later. Run `make check`, `make msrv` and `make audit` before
shipping. Tests use local HTTP peers and synthetic credentials; real account
validation is opt-in. Public documentation and fixtures use English and generic
data. Local planning lives under ignored `docs/`; never force-add it.

Record user-visible changes in `CHANGELOG.md`, and use conventional commit
subjects. Never log or include access tokens, refresh tokens, identity tokens,
codes or PKCE verifiers in errors.

## Releasing

1. On `main`, set `version` in `Cargo.toml` and add a matching `## X.Y.Z` heading
   to `CHANGELOG.md`.
2. Push a `vX.Y.Z` tag. `.github/workflows/release.yml` runs CI, checks that the
   tag, the manifest and the changelog agree, and publishes through crates.io
   Trusted Publishing once the `crates-io` environment approves.

Trusted Publishing cannot create a crate, so 0.1.0 goes by hand: tag the commit,
run `cargo publish --locked` from it, then push the tag. The workflow finds that
version on crates.io and skips publishing. Afterwards, add the trusted publisher
on crates.io: repository `roomkit-live/roomkit-auth`, workflow `release.yml`,
environment `crates-io`.
