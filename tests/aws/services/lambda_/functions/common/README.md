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
  By default, the Makefile should build a deployment package with the same architecture as the host.
  However, for testing on multi-architecture platforms, we should be able to overwrite the `ARCHITECTURE` parameter.
* SHOULD define a `clean` target that deletes any build artefacts, including the `handler.zip`.
  This helps a lot during development to tidy up and invalidate caching.

Checkout the [AWS guides](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html) on
"Building with <language>" (e.g., "Building with Java") for instructions how to
build Lambda deployment packages correctly.

The top-level and intermediary directories provided a meta-Makefile that automatically invokes sub-Makefiles such that
we can run `make clean` at the top-level recursively.
