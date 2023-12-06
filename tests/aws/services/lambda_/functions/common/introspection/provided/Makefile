DOCKER_PLATFORM ?= linux/amd64
# Using a sha256 hash breaks on multi-platform hosts (e.g., ARM Macs): https://github.com/moby/moby/issues/43188
# https://hub.docker.com/_/rust/tags
DOCKER_RUST_IMAGE ?= rust:1.74.0

# x86 cross-build on ARM hosts are killed due to memory issues: https://github.com/rust-lang/cargo/issues/10781#issuecomment-1351670409
# Slow workaround takes ~5min to build on an M1 MacBook Pro: --config net.git-fetch-with-cli=true
ARM_CROSS_BUILD_WORKAROUND ?= --config net.git-fetch-with-cli=true

# Overview: https://doc.rust-lang.org/nightly/rustc/platform-support.html
# Targets: x86_64-unknown-linux-musl or x86_64-unknown-linux-gnu or add aarch64-unknown-linux-gnu
# ARM cross-compile requires some more config and dependencies because cargo does not find cross-build tools itself:
# https://stackoverflow.com/questions/69360099/apple-m1-to-linux-x86-64-unrecognized-command-line-option-m64
# --env RUSTFLAGS='-C linker=x86_64-linux-gnu-gcc' yields: error: linker `x86_64-linux-gnu-gcc` not found
# Alternative cross compilation tool: https://github.com/cross-rs/cross
# cargo install cross --git https://github.com/cross-rs/cross
# --env CROSS_CONTAINER_IN_CONTAINER=true -v /var/run/docker.sock:/var/run/docker.sock
# cross build --target x86_64-unknown-linux-musl
# "no container engine found" => requires installing Docker
# ARM support for aarch64-unknown-linux-gnu pending: https://github.com/rust-lang/rust/issues/77071
RUST_TARGET ?= x86_64-unknown-linux-musl

build:
	mkdir -p build && \
	docker run --rm --platform=$(DOCKER_PLATFORM) -v $$(pwd)/src:/app -v $$(pwd)/build:/out:cached $(DOCKER_RUST_IMAGE) bash -c "rustup target add $(RUST_TARGET) && mkdir -p /app2 && cp -r /app/* /app2 && cd /app2 && cargo build $(ARM_CROSS_BUILD_WORKAROUND) --release --target $(RUST_TARGET) && cp ./target/$(RUST_TARGET)/release/bootstrap /out && chown $$(id -u):$$(id -g) /out/bootstrap" && \
	cd ./build && zip -r handler.zip . && \
	mv handler.zip ..

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
