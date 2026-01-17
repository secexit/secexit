build-ebpf:
	cargo xtask build-ebpf --release
build-daemon:
	cargo build --package secexit-daemon --release
build-shim:
	cargo build --package secexit-shim --release
build: build-ebpf build-daemon build-shim

setup-env:
	rustup toolchain install nightly
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker
	cargo install cargo-xtask

test:
	cargo test --release
test-all:
	cargo test --release --no-fail-fast
check:
	cargo check --release
format:
	cargo fmt --check
clean:
	cargo clean
clippy:
	cargo clippy --release --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used

run:
	sudo RUST_LOG=info cargo run --release --bin secexit-daemon

run2:
	sudo RUST_LOG=info ./target/release/secexit-daemon

publish-package:

publish-crates:
	cargo publish -p secexit-shim
	cargo publish -p secexit-daemon

