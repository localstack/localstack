build:
	mkdir -p build && \
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out rust:1.64.0 bash -c "rustup target add x86_64-unknown-linux-musl && mkdir -p /app2 && cp -r /app/* /app2 && cd /app2 && cargo build --release --target x86_64-unknown-linux-musl && cp ./target/x86_64-unknown-linux-musl/release/bootstrap /out" && \
	find ./build -exec touch -t 200001010100.00 {} \;

.PHONY: build
