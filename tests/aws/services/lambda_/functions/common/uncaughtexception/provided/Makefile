UNAME := $(shell uname -m)
ifeq ($(UNAME),x86_64)
	ARCHITECTURE ?= x86_64
else
	ARCHITECTURE ?= arm64
endif
DOCKER_PLATFORM ?= linux/$(ARCHITECTURE)
# Manual implementation of the --arm64 logic from `cargo lambda lambda build`:
# https://docs.aws.amazon.com/lambda/latest/dg/rust-package.html
# https://github.com/cargo-lambda/cargo-lambda/blob/7b0977e6fd9a6b03d8f6ddf71eff5a5b9999e0c0/crates/cargo-lambda-build/src/target_arch.rs#L10
ifeq ($(ARCHITECTURE),arm64)
  # ARM builds are finally fixed (2024-03): https://github.com/rust-lang/rust/issues/77071
  RUST_TARGET ?= aarch64-unknown-linux-gnu
else
  RUST_TARGET ?= x86_64-unknown-linux-musl
endif

# https://hub.docker.com/_/rust/tags
DOCKER_RUST_IMAGE ?= rust:1.76.0

build:
	mkdir -p build && \
	docker run --rm --platform=$(DOCKER_PLATFORM) -v $$(pwd)/src:/app -v $$(pwd)/build:/out:cached $(DOCKER_RUST_IMAGE) \
		bash -c "rustup target add $(RUST_TARGET) && mkdir -p /app2 && cp -r /app/* /app2 && cd /app2 && cargo build --release --target $(RUST_TARGET) && cp ./target/$(RUST_TARGET)/release/bootstrap /out && chown $$(id -u):$$(id -g) /out/bootstrap"

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
