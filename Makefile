.PHONY: check test build install uninstall

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace --all-features

test:
	cargo test --workspace --all-features

build:
	cargo build --release --workspace

install:
	sudo ./scripts/install.sh

uninstall:
	sudo ./scripts/uninstall.sh

