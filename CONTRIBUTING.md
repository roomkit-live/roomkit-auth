# Contributing

Keep authentication independent of RoomKit engines, tools and user interfaces.
Use Rust 1.92 or later. Run `make check`, `make msrv` and `make audit` before
shipping. Tests use local HTTP peers and synthetic credentials; real account
validation is opt-in. Public documentation and fixtures use English and generic
data. Local planning lives under ignored `docs/`; never force-add it.

Use immutable git dependency revisions until release. Record user-visible changes
in `CHANGELOG.md`, and use conventional commit subjects. Never log or include
access tokens, refresh tokens, identity tokens, codes or PKCE verifiers in errors.
