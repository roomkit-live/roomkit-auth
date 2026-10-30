.PHONY: check fmt fmt-check clippy test doc msrv audit
check: fmt-check clippy test doc
fmt:
	cargo fmt --all
fmt-check:
	cargo fmt --all --check
clippy:
	cargo clippy --locked --all-targets -- -D warnings
test:
	cargo test --locked
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
msrv:
	cargo +1.92.0 test --locked
audit:
	cargo deny check
