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
  # ARM builds are finally fixed since 1.76.0: https://github.com/rust-lang/rust/issues/77071
  # TODO: Migrate to -gnu once we can avoid the following issue for the runtime provided.al2.
  #  It might require using the official build image (https://gallery.ecr.aws/sam/emulation-provided.al2), but
  #  that seems not worth fixing before provided.al2 deprecation 2026-06.
  # The suffix -musl instead of -gnu is required for the runtime `provided.al2` to fix a GLIBC version not found error:
  # /var/task/bootstrap: /lib64/libc.so.6: version `GLIBC_2.28' not found (required by /var/task/bootstrap)
  # https://github.com/awslabs/aws-lambda-rust-runtime/issues/17#issuecomment-645064821
  RUST_TARGET ?= aarch64-unknown-linux-musl
else
  RUST_TARGET ?= x86_64-unknown-linux-musl
endif

# https://github.com/cargo-lambda/cargo-lambda/pkgs/container/cargo-lambda
DOCKER_RUST_IMAGE ?= ghcr.io/cargo-lambda/cargo-lambda:1.8.6

# TODO: consider migrating to AWS SAM-based build (easier and better parity):
#  https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/building-rust.html
build:
	mkdir -p build && \
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out:cached $(DOCKER_RUST_IMAGE) \
		bash -c "rustup target add $(RUST_TARGET) && mkdir -p /app2 && cp -r /app/* /app2 && cd /app2 && cargo lambda build --target $(RUST_TARGET) && cp ./target/lambda/bootstrap/bootstrap /out && chown $$(id -u):$$(id -g) /out/bootstrap"

clean:
	$(RM) -rf build handler.zip

.PHONY: build clean
