# Testing in LocalStack

- [Integration Tests](integration-tests/README.md)
- [Parity Testing](parity-testing/README.md)
- [Multi-account and Multi-region Testing](multi-account-region-testing/README.md)
- [Terraform Tests](terraform-tests/README.md)

## Rules for stable tests

Through experience, we encountered some guiding principles and rules when it comes to testing LocalStack.
These aim to ensure a stable pipeline, keeping flakes minimal and reducing maintenance effort.
Any newly added test and feature should keep these in mind!

| **ID** | **Rule** |
|-------|-----------|
| R01 | Inform code owners and/or test authors about flaky tests by creating a PR skipping them (reason: flaky), so that they can be fixed ASAP. |
| R02 | Do not assume external dependencies (AWS resources, files, packages, images, licenses) are indefinitely available on the same URL. |
| R03 | Where possible, tests should be in control of the resources they use and re-create them if removed (e.g., S3 buckets, roles). |
| R04 | If on-demand creation is not possible, opt for a fail-fast approach and make retrieval failures clearly visible for further investigation. |
| R05 | Add mechanisms to avoid access failures caused by rate limiting. |
| R06 | Do not wait a set amount of time but instead opt for a reactive approach using notification systems or polling for asynchronous (long-lasting) operations |
| R07 | For tests with multiple steps, handle waits separately and start each wait in the correct state. |
| R08 | Ensure features interacting with account numbers work with arbitrary account numbers and multiple accounts simultaneously. (see [here](multi-account-region-testing/README.md) for further documentation) |
| R09 | Ensure deterministic responses for anything that reaches an assertion or a snapshot match (e.g., by using proper transformations). (see [here](parity-testing/README.md) for further documentation) |
| R10 | When a feature or its tests require a Python dependency, track updates to the dependency for potential stability impacts. |
| R11 | Ensure all dependencies are available and functional on both AMD64 and ARM64 architectures. If a dependency is exclusive to one architecture, mark the corresponding test accordingly. |

Where appropriate, we provide comparisons of good practice and anti-pattern:

### R02

TODO

### R03

TODO

### R04

TODO

### R05

TODO

### R06

TODO

### R07

TODO

### R08

TODO

### R09

TODO

### R09

TODO

### R10

TODO

## Test markers

TODO
