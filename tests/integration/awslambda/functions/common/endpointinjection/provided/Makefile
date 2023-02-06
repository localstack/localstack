build:
	mkdir -p build && \
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out rust:1.64.0@sha256:922d814994d77f8e3ab8a7db45a277e9cebe41a557046eeef91a2e34b28b4962 bash -c "rustup target add x86_64-unknown-linux-musl && mkdir -p /app2 && cp -r /app/* /app2 && cd /app2 && cargo build --release --target x86_64-unknown-linux-musl && cp ./target/x86_64-unknown-linux-musl/release/bootstrap /out && chown $$(id -u):$$(id -g) /out/bootstrap"
	find ./build -exec touch -t 200001010100.00 {} \;
	cd ./build && zip -r handler.zip .
	mv ./build/handler.zip .

.PHONY: build
