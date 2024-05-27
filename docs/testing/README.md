# Testing in LocalStack

- [Integration Tests](integration-tests/README.md)
- [Parity Testing](parity-testing/README.md)
- [Multi-account and Multi-region Testing](multi-account-region-testing/README.md)
- [Terraform Tests](terraform-tests/README.md)

## Rules for stable tests

Through experience, we encountered some guiding principles and rules when it comes to testing LocalStack.
These aim to ensure a stable pipeline and keep flakes minimal. Any newly added test and feature should keep these in mind!

R01: After a test is marked as flaky, make sure to inform code owners and/or test authors so that the flake can be fixed ASAP.
R02: External dependencies (AWS resources, files, packages, images, licenses) should not be assumed as indefinitely available. 
R02a: Where possible, add automatic creation of dependencies if they do not exist anymore (e.g, S3 buckets, roles)
R02b: If on demand creation is not possible, make access failures clearly visible, so that they can be further investigated
R02c: Add mechanisms to avoid access failures caused by rate limiting.
R03: Instead of waiting for a set amount of time, only wait as long as is needed (with a reasonable cap)
R04: If a test has multiple steps to conclude, make sure that the waits are handled separately and that each wait starts in the correct state.
R05: When adding features which interact with account numbers, make sure that these work with arbitrary account numbers and multiple accounts at the same time. (see [here](multi-account-region-testing/README.md) for further documentation)
R06: Ensure deterministic responses on anything that reaches an assertion or a snapshot match (e.g., by using proper transformations) (see [here](parity-testing/README.md) for further documentation)
R07: When a feature and/or the tests corresponding to that feature need a python dependency, keep track of updates to that dependency on possible impacts to stability.
R08: Ensure that all dependencies are available and working in both AMD64 as well as ARM64 architectures. If the dependency is exclusive for one architecture, mark the corresponding test as such

