# Contributing

Thank you for helping improve RoomKit Auth. Bug reports, documentation, fixes and
features are all welcome. For a large change, open an issue first so we can agree
on the approach before you invest time in it.

Report security issues privately: see [SECURITY.md](SECURITY.md). This project
follows a [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

You need Rust through [rustup](https://rustup.rs); the repository pins its
toolchain, and rustup installs it on first use. You also need a C compiler. The
other checks need the minimum supported toolchain
(`rustup toolchain install 1.92.0`) and `cargo-deny`
(`cargo install cargo-deny --locked`).

```sh
git clone https://github.com/roomkit-live/roomkit-auth
cd roomkit-auth
make check
```

## Design rules

Keep authentication independent of RoomKit engines, tools and user interfaces. The
host application owns the browser launcher, its menus and its model requests. This
crate depends on no RoomKit crate and must stay usable without one.

The protocol follows [OpenAI's documentation](https://developers.openai.com/siwc/token-sharing-open-source).
When a change relies on one of its rules, name the page in the commit.

## Checks

Run `make check` before submitting a change. Run `make msrv` when adding a
dependency or using a new standard-library API, and `make audit` when changing
dependencies.

Test observable behaviour through the public API. A fix comes with a test that
fails without it. Tests use the local fake issuer and synthetic credentials: they
never contact OpenAI and never need an account. Checking with a real account is
opt-in, with `cargo run --example sign_in -- <private-directory>`.

## Public interfaces

Document every public item, and return failures rather than panicking on caller
input. Never log or include access tokens, refresh tokens, identity tokens, codes
or PKCE verifiers in errors. Record user-visible changes in `CHANGELOG.md`, and use
conventional commit subjects.

## Documentation and distribution

Write code, comments, public documentation and fixtures in English. Use generic,
fictional records. Do not commit local planning, private integration data, machine
paths, credentials or session logs. The manifest lists what the package includes;
`cargo package --list` shows the result.

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
