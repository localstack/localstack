# Lambda Multiruntime Builds

This directory contains the source code and build instructions for Lambda multiruntime tests.
Example tests are available under `tests.aws.lambda_.functions.common`

Each scenario (e.g., "echo") has the following folder structure: `./<scenario>/runtime/`
A runtime can be an aggregated runtime defined in `runtimes.py` (e.g., "python") or
a specific runtime (e.g., "python3.12") if customizations are required.

Each runtime directory defines a `Makefile` that
* MUST define a `build` target that:
  * a) creates a `build` directory containing all Lambda sources ready for packaging
  * b) creates a `handler.zip` file with a Lambda deployment package
* SHOULD define an `ARCHITECTURE` parameter to overwrite the target architecture (i.e., `x86_64` or `arm64`)
  if architecture-specific builds are required (e.g., Dotnet, Golang, Rust).
  * By default, the Makefile should build a deployment package with the same architecture as the host.
  * However, for testing on multi-architecture platforms, we should be able to overwrite the `ARCHITECTURE` parameter.
  * We need to standardize `uname -m` into `ARCHITECTURE` because the output differs depending on the platform.
    Ubuntu yields `aarch64` and macOS yields `arm64`.
  * If we want to support dev systems without the `uname` utility, we could add `|| echo x86_64` to the uname detection.
* SHOULD define a `clean` target that deletes any build artefacts, including the `handler.zip`.
  This helps a lot during development to tidy up and invalidate caching.

Checkout the [AWS guides](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html) on
"Building with <language>" (e.g., "Building with Java") for instructions how to
build Lambda deployment packages correctly.

The top-level and intermediary directories provided a meta-Makefile that automatically invokes sub-Makefiles such that
we can run `make clean` at the top-level recursively.

## Dotnet

The `dotnet` directory contains the original source code and a parametrizable Makefile to build multiple Dotnet versions.
We create individual subdirectories for supported Dotnet versions (e.g., `dotnet6` and `dotnet8`) with a Makefile that
invokes the original Makefile in the `dotnet` directory.

Using the shared `dotnet` directory has a couple of limitations:
* In CI, we currently waste one extra build cycle for the top-level dotnet directory
* Concurrent builds of Dotnet runtimes are unsafe
* We need to use a concrete sub-directory (i.e., `dotnet6` and `dotnet8`) for pre-building
* We need to clean before building to avoid picking up leftover from another Dotnet version build
* We need to parametrize the build directory to mitigate a Docker race condition when executing two builds in succession

## Rust

ARM builds had some issues but were finally fixed. Here are the relevant sources:

* List of Rust build targets in the docs: https://doc.rust-lang.org/nightly/rustc/platform-support.html
* This issue mentioned that "Aarch64 stack probes are tested in CI" and everything should work: https://github.com/rust-lang/rust/issues/77071
* The fix was done in this PR and released with Rust `1.76.0`: https://github.com/rust-lang/rust/pull/118491
* The `-musl` suffix was required to fix a GLIBC not found error with the Lambda runtime `provided.al2`
