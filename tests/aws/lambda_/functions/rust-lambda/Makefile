build:
	cargo build --release --target x86_64-unknown-linux-musl
	cp ./target/x86_64-unknown-linux-musl/release/bootstrap .
	zip function.zip bootstrap
	rm bootstrap
