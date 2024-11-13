# Integration tests

LocalStack has an extensive set of [integration tests](https://github.com/localstack/localstack/tree/master/tests/integration). This document describes how to run and write integration tests.

## Writing integration tests

The following guiding principles apply to writing integration tests in addition to the [general rules](../README.md):

-   Tests should pass when running against AWS:
    -   Don't make assumptions about the time it takes to create resources. If you do asserts after creating resources, use `poll_condition`, `retry` or one of the waiters included in the boto3 library to wait for the resource to be created.
    -   Make sure your tests always clean up AWS resources, even if your test fails! Prefer existing factory fixtures (like `sqs_create_queue`). Introduce try/finally blocks if necessary.
-   Tests should be runnable concurrently:
    -   Protect your tests against side effects. Example: never assert on global state that could be modified by a concurrently running test (like `assert len(sqs.list_queues()) == 1`; may not hold!).
    -   Make sure your tests are side-effect free. Avoid creating top-level resources with constant names. Prefer using generated unique names (like `short_uid`).
-   Tests should not be clever. It should be plain to see what they are doing by looking at the test. This means avoiding creating functions, loops, or abstractions, even for repeated behavior (like groups of asserts) and instead preferring a bit of code duplication:
-   Group tests logically using classes.
-   Avoid injecting more than 2-3 fixtures in a test (unless you are testing complex integrations where your tests requires several different clients).
-   Create factory fixtures only for top-level resources (like Queues, Topics, Lambdas, Tables).
-   Avoid sleeps! Use `poll_condition`, `retry`, or `threading.Event` internally to control concurrent flows.

We use [pytest](https://docs.pytest.org) for our testing framework.
Older tests were written using the unittest framework, but its use is discouraged.

If your test matches the pattern `tests/integration/**/test_*.py` or `tests/aws/**/test_*.py` it will be picked up by the integration test suite.
Any test targeting one or more AWS services should go into `tests/aws/**` in the corresponding service package.
Every test in `tests/aws/**/test_*.py` must be marked by exactly one pytest marker, e.g. `@markers.aws.validated`.

### Functional-style tests

You can write functional style tests by defining a function with the prefix `test_` with basic asserts:

```python
def test_something():
  assert True is not False
```

### Class-style tests

Or you can write class-style tests by grouping tests that logically belong together in a class:

```python
class TestMyThing:
  def test_something(self):
    assert True is not False
```

### Fixtures

We use the pytest fixture concept, and provide several fixtures you can use when writing AWS tests. For example, to inject a boto client factory for all services, you can specify the `aws_client` fixture in your test method and access a client from it:

```python
class TestMyThing:
  def test_something(self, aws_client):
    assert len(aws_client.sqs.list_queues()["QueueUrls"]) == 0
```

We also provide fixtures for certain disposable resources, like buckets:

```bash
def test_something_on_a_bucket(s3_bucket):
  s3_bucket
  # s3_bucket is a boto s3 bucket object that is created before
  # the test runs, and removed after it returns.
```

Another pattern we use is the [factory as fixture](https://docs.pytest.org/en/6.2.x/fixture.html#factories-as-fixtures) pattern.

```bash
def test_something_on_multiple_buckets(s3_create_bucket):
  bucket1 = s3_create_bucket()
  bucket2 = s3_create_bucket()
  # both buckets will be deleted after the test returns
```

You can find the list of available fixtures in the [fixtures.py](https://github.com/localstack/localstack/blob/master/localstack-core/localstack/testing/pytest/fixtures.py) file.


## Running the test suite

To run the tests you can use the make target and set the `TEST_PATH` variable.

```bash
TEST_PATH="tests/integration" make test
```

or run it manually within the virtual environment:

```bash
python -m pytest --log-cli-level=INFO tests/integration
```

### Running individual tests

You can further specify the file and test class you want to run in the test path:

```bash
TEST_PATH="tests/integration/docker/test_docker.py::TestDockerClient" make test
```

### Test against a running LocalStack instance

When you run the integration tests, LocalStack is automatically started (via the pytest conftest mechanism in [tests/integration/conftest.py](https://github.com/localstack/localstack/blob/master/tests/integration/conftest.py)).
You can disable this behavior by setting the environment variable `TEST_SKIP_LOCALSTACK_START=1`.

### Test against Amazon Web Services

Ideally every integration is tested against real AWS. To run the integration tests, we prefer you to use an AWS sandbox account, so that you don't accidentally run tests against your production account.

#### Creating an AWS sandbox account

1.  Login with your credentials into your AWS Sandbox Account with `AWSAdministratorAccess`.
2.  Type in **IAM** in the top bar and navigate to the **IAM** service
3.  Navigate to `Users` and create a new user (**Add Users**)
    1.  Add the username as `localstack-testing`.
    2.  Keep the **Provide user access to the AWS Management Console - optional** box unchecked.
4.  Attach existing policies directly.
5.  Check **AdministratorAccess** and click **Next** before **Next/Create User** until done.
6.  Go to the newly created user under `IAM/Users`, go to the `Security Credentials` tab, and click on **Create access key** within the `Access Keys` section.
7.  Pick the **Local code** option and check the **I understand the above recommendation and want to proceed to create an access key** box.
8.  Click on **Create access key** and copy the Access Key ID and the Secret access key immediately.
9.  Run `aws configure —-profile ls-sandbox` and enter the Access Key ID, and the Secret access key when prompted.
10.  Verify that the profile is set up correctly by running: `aws sts get-caller-identity --profile ls-sandbox`.

Here is how `~/.aws/credentials` should look like:

```bash
[ls-sandbox]
aws_access_key_id = <your-key-id>
aws_secret_access_key = <your-secret-key>
```

The `~/.aws/config` file should look like:

```bash
[ls-sandbox]
region=eu-central-1
# .... you can add additional configuration options for AWS clients here
```

#### Running integration tests against AWS

-   Set the environment variable: `TEST_TARGET=AWS_CLOUD`.
-   Use the client `fixtures` and other fixtures for resource creation instead of methods from `aws_stack.py`
    -   While using the environment variable `TEST_TARGET=AWS_CLOUD`, the boto client will be automatically configured to target AWS instead of LocalStack.
-   Configure your AWS profile/credentials:
    -   When running the test, set the environment variable `AWS_PROFILE` to the profile name you chose in the previous step. Example: `AWS_PROFILE=ls-sandbox`
-   Ensure that all resources are cleaned up even when the test fails and even when other fixture cleanup operations fail!
-   Testing against AWS might require additional roles and policies.

Here is how a useful environment configuration for testing against AWS could look like:

```bash
DEBUG=1;  # enables debug logging
TEST_DISABLE_RETRIES_AND_TIMEOUTS=1;
TEST_TARGET=AWS_CLOUD;
AWS_DEFAULT_REGION=us-east-1;
AWS_PROFILE=ls-sandbox
```

Once you're confident your test is reliably working against AWS you can add the pytest marker `@markers.aws.validated`.

#### Create a snapshot test

Once you verified that your test is running against AWS, you can record snapshots for the test run. A snapshot records the response from AWS and can be later on used to compare the response of LocalStack.

Snapshot tests helps to increase the parity with AWS and to raise the confidence in the service implementations. Therefore, snapshot tests are preferred over normal integrations tests.

Please check our subsequent guide on [Parity Testing](../parity-testing/README.md) for a detailed explanation on how to write AWS validated snapshot tests.
