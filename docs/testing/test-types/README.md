# Test Types

In the LocalStack codebase we differentiate between the following test types:

- Unit tests
- Acceptance Tests
- Integration Tests

Depending on the workflow and its trigger not all of those tests are executed at once.
For ordinary pushes to `master` we only want to execute the Unit and Acceptance tests.
On a regular schedule, however, we want to execute all tests to have as big of a coverage of our logic as possible.
This differentiation also educates what we expect from the different types of tests.

## Unit tests

As the name suggests, these tests are performed on smaller units of logic to check if they're sound and perform the operations they claim to.
This small unit can most often be a kind of helper function inside of a larger procedure.
These tests should be able to complete their execution very quickly, so they never contain any interaction with some kind of infrastructure.
If you need some kind of waiting mechanism in your unit test, it is most likely that you are not writing a unit test.


## Acceptance tests

We use acceptance tests to gain a quick understanding of whether the recently pushed commit to `master` fulfils minimally viable quality criteria.
This means that these tests do not aim at maximum coverage but instead should test that the most important functionality works.
This in general is the entire serving infrastructure and the main features of the most used services.

As these tests are executed very often we need them to be as stable, fast and relevant as possible.
We ensure this by the following criteria:

- Should perfectly conform to all the testing rules laid out [here](../README.md)
- Does not contain wait times (e.g., for resources to spin up) averaging longer than 20 seconds
- Should be able to run in parallel. If tests need to run together (e.g., in a scenario), they need to be added to the same test class.
- Displays some kind of real-world usage. This can be a scenario with multiple services. 
    - When composing these scenarios, the services should not overlap too much with already existing acceptance tests. We want to avoid redundancy
    - Existing samples (from [our samples organization](https://github.com/localstack-samples)) can serve as a good starting point for constructing such a scenario
- The test should have a proven track record of being stable over a month of being in the regular integration test suite.
    - Should an acceptance test turn flaky, it will be skipped until it is fixed ([as the rules already state](../README.md))

## Integration tests

These tests are quite similar to the acceptance tests, but are less restrictive.
Any acceptance test can be demoted to an integration test should it not satisfy the needs of the acceptance test suite anymore.
However, this does not mean that integration tests do not have any quality requirements in their own right.
Flaky integration tests can (and will) still be skipped until their flake is resolved.
Also, they still should all conform to the testing rules.
