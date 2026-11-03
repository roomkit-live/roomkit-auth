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

Before the first release, on the public repository:

- give the `crates-io` environment required reviewers and limit its deployments
  to `v*.*.*` tags;
- restrict who can create those tags with a tag ruleset;
- enable private vulnerability reporting, which `SECURITY.md` relies on.

These settings are what control publication. A missing environment is created
unprotected on first use, and a tag runs the workflow of its own commit, so the
workflow's check that a tag is on `main` only catches mistakes.

For each release:

1. On `main`, set `version` in `Cargo.toml`, add a matching `## X.Y.Z` heading to
   `CHANGELOG.md`, and wait for CI to pass on that commit.
2. Push a `vX.Y.Z` tag on it. `.github/workflows/release.yml` runs CI, checks that
   the tag is on `main` and agrees with the manifest and the changelog, and
   publishes through crates.io Trusted Publishing once the `crates-io`
   environment approves.

Trusted Publishing cannot create a crate, so 0.1.0 goes by hand: after step 1, tag
the commit, run `cargo publish --locked` from it, then push the tag. The workflow
finds that version on crates.io and skips publishing. Afterwards, add the trusted
publisher on crates.io: repository `roomkit-live/roomkit-auth`, workflow
`release.yml`, environment `crates-io`.
