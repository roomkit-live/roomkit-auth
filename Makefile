.PHONY: check fmt fmt-check clippy test doc msrv audit
check: fmt-check clippy test doc
fmt:
	cargo fmt --all
fmt-check:
	cargo fmt --all --check
# Every feature, then the server identities alone, as a provider takes them.
clippy:
	cargo clippy --locked --all-targets --all-features -- -D warnings
	cargo clippy --locked --all-targets --no-default-features --features google-cloud -- -D warnings
test:
	cargo test --locked --all-features
	cargo test --locked --no-default-features --features google-cloud --lib
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
msrv:
	cargo +1.92.0 test --locked --all-features
audit:
	cargo deny check
