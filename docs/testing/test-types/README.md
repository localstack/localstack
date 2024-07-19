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

A good example for a unit test is `tests.unit.testing.testselection.test_matching.test_service_dependency_resolving_with_dependencies`.
It tests whether an algorithm implemented inside of a bigger implementation performs as it is expected of it. 

## Acceptance tests

We use acceptance tests to gain a quick understanding of whether the recently pushed commit to `master` fulfils minimally viable quality criteria.
This means that these tests do not aim at maximum coverage but instead should test that the most important functionality works.
This in general is the entire serving infrastructure and the main features of the most used services.

As these tests are executed very often we need them to be as stable, fast and relevant as possible.
We ensure this by the following criteria:

- It shows some kind of real-world usage. This is usually a scenario or architectural pattern with multiple services. 
    - When composing these scenarios, the services should not overlap too much with already existing acceptance tests. We want to avoid redundancy where possible. At the same time we want to have our primary services and typical use-cases being covered.
    - Existing samples (from [our samples organization](https://github.com/localstack-samples)) might serve as a starting point for constructing such a scenario.
    However, keep in mind that we want to use many interacting resources in these tests, so the samples might need further expansion.
- It perfectly conforms to all the testing rules laid out [here](../README.md)
- It does not contain long wait times (e.g., for resources to spin up).
  The acceptance tests need to be fast.
  Whether they are fast enough is evaluated on a case-by-case basis (e.g., depending on the amount of confidence they provide)
- It is fully parallelizable.
  If certain acceptance tests need to run together (e.g., in a scenario), they need to be added to the same test class.
- The test needs to be perfectly stable and only fail because of real issues with the implementation under test.
    - Should an acceptance test turn flaky, it will be skipped until it is fixed ([as we already state in our testing rules](../README.md)).
- It needs to be validated against the targeted cloud provider if it is purely testing parity with that cloud provider.
    - See [the documentation on parity tests for further information](../parity-testing/README.md)
    - This effectively means that the test should not carry the markers `aws.unknown` or `needs_fixing`.

Note, that some criteria is still not concrete and will evolve over time.
For cases where it is unclear if a test fulfils a criterium, reviewers will need to decide whether it fits the general goals laid out here.
With growing maturity, however, criteria will become more concrete (and strict).

The first acceptance test that we added to our suite, and which serves as an example is `tests.aws.scenario.bookstore.test_bookstore.TestBookstoreApplication`.
It implements an entire application involving multiple services and tests their interaction with each other.

## Integration tests

These tests are quite similar to the acceptance tests, but are less restrictive.
Any acceptance test can be demoted to an integration test should it not satisfy the needs of the acceptance test suite anymore.
However, this does not mean that integration tests do not have any quality requirements in their own right.
Flaky integration tests can (and will) still be skipped until their flake is resolved.
Also, they still should all conform to the testing rules.

An example for a good integration test, that could not be an acceptance test is `tests.aws.services.s3.test_s3.TestS3.test_object_with_slashes_in_key`.
It tests a concrete feature of the S3 implementation while not being part of a scenario with other services.
