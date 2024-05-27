# Testing in LocalStack

- [Integration Tests](integration-tests/README.md)
- [Parity Testing](parity-testing/README.md)
- [Multi-account and Multi-region Testing](multi-account-region-testing/README.md)
- [Terraform Tests](terraform-tests/README.md)

## Rules for stable tests

Through experience, we encountered some guiding principles and rules when it comes to testing LocalStack.
These aim to ensure a stable pipeline and keep flakes minimal. Any newly added test and feature should keep these in mind!

| **ID** | **Rule** |
|-------|-----------|
| R01   | Inform code owners and/or test authors when a test is marked as flaky so that it can be fixed ASAP. |
| R02   | Do not assume external dependencies (AWS resources, files, packages, images, licenses) are indefinitely available. |
| R02a  | Where possible, add automatic creation of dependencies if they no longer exist (e.g., S3 buckets, roles). |
| R02b  | If on-demand creation is not possible, make access failures clearly visible for further investigation. |
| R02c  | Add mechanisms to avoid access failures caused by rate limiting. |
| R03   | Instead of waiting for a set amount of time, wait only as long as needed (with a reasonable cap). |
| R04   | For tests with multiple steps, handle waits separately and start each wait in the correct state. |
| R05   | Ensure features interacting with account numbers work with arbitrary account numbers and multiple accounts simultaneously. (see [here](multi-account-region-testing/README.md) for further documentation) |
| R06   | Ensure deterministic responses for anything that reaches an assertion or a snapshot match (e.g., by using proper transformations). (see [here](parity-testing/README.md) for further documentation) |
| R07   | When a feature or its tests require a Python dependency, track updates to the dependency for potential stability impacts. |
| R08   | Ensure all dependencies are available and functional on both AMD64 and ARM64 architectures. If a dependency is exclusive to one architecture, mark the corresponding test accordingly. |

