# Testing in LocalStack

- [Test Types](test-types/README.md)
- [Integration Tests](integration-tests/README.md)
- [Parity Testing](parity-testing/README.md)
- [Multi-account and Multi-region Testing](multi-account-region-testing/README.md)
- [Terraform Tests](terraform-tests/README.md)

## Rules for stable tests

Through experience, we encountered some guiding principles and rules when it comes to testing LocalStack.
These aim to ensure a stable pipeline, keeping flakes minimal and reducing maintenance effort.
Any newly added test and feature should keep these in mind!

| **ID**      | **Rule**                                                                                                                                                                               |
|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [R01](#r01) | Inform code owners and/or test authors about flaky tests by creating a PR skipping them (reason: flaky), so that they can be fixed ASAP.                                               |
| [R02](#r02) | Do not assume external dependencies are indefinitely available on the same location. They can move and we need to adapt in the future for it.                                          |
| [R03](#r03) | Where possible, tests should be in control of the resources they use and re-create them if removed.                                                                                    |
| [R04](#r04) | If on-demand creation is not possible, opt for a fail-fast approach and make retrieval failures clearly visible for further investigation.                                             |
| [R05](#r05) | Add mechanisms to avoid access failures caused by rate limiting.                                                                                                                       |
| [R06](#r06) | Do not wait a set amount of time but instead opt for a reactive approach using notification systems or polling for asynchronous (long-lasting) operations                              |
| [R07](#r07) | For tests with multiple steps, handle waits separately and start each wait in the correct state.                                                                                       |
| [R08](#r08) | Ensure features interacting with account numbers work with arbitrary account numbers and multiple accounts simultaneously.                                                             |
| [R09](#r09) | Make sure that your tests are idempotent and could theoretically run in parallel, by using randomized IDs and not re-using IDs across tests.                                           |
| [R10](#r10) | Ensure deterministic responses for anything that reaches an assertion or a snapshot match.                                                                                             |
| [R11](#r11) | Be vigilant about changes happening to dependencies that can affect stability of your added features and tests.                                                                        |
| [R12](#r12) | Ensure all dependencies are available and functional on both AMD64 and ARM64 architectures. If a dependency is exclusive to one architecture, mark the corresponding test accordingly. |
| [R13](#r13) | After the test run, make sure that the created resources are cleaned up properly.                                                                                                      |
| [R14](#r14) | Utilize fixture scopes for ensuring created resources exist as long as they should.                                                                                                    |


### R01

Inform code owners and/or test authors about flaky tests by creating a PR skipping them (reason: flaky), so that they can be fixed ASAP.
This way, the flaky tests are not blocking the pipeline and can be fixed in a separate PR.
We also set the test author and/or service owner as reviewer to ensure that the test is fixed in a timely manner.

#### Anti-pattern

1. Noticing a flake
2. Ignoring it

#### Best practice

1. Noticing a flake
2. Creating a new PR skipping the test and marking it as flaky

```python

@pytest.mark.skip(reason="flaky")
def test_xyz():
    pass
```

3. Setting test author and/or service owner as reviewer

### R02

Do not assume external dependencies (AWS resources, files, packages, images, licenses) are indefinitely available on the same location.
They can move, and we need to adapt in the future for it.
This can be done by checking the status code of the response and reacting accordingly.
Ideally, the test should be able to guide anyone to how to find the new location.

#### Anti-pattern

```python
response = requests.get("http://resource.com/my-resource.tar.gz")
use_resource(response.content)
```

#### Best practice

```python
response = requests.get("http://resource.com/my-resource.tar.gz")
if response.status_code == 404:
    further_steps()  # e.g. clear error message, potential documentation on where to find a new location, etc.
use_resource(response.content)
```

### R03

Where possible, tests should be in control of the resources they use and re-create them if removed (e.g., S3 buckets, roles).

#### Anti-pattern

```python
bucket = s3_client.get_bucket("test-bucket")
use_bucket(bucket)
```

#### Best practice

```python
buckets = s3_client.list_buckets()
if "test-bucket" not in buckets:
    s3_client.create_bucket("on-demand-bucket")

bucket = s3_client.get_bucket("on-demand-bucket")
use_bucket(bucket)
```

### R04

If on-demand creation is not possible, opt for a fail-fast approach and make retrieval failures clearly visible for further investigation.
We should not proceed with the test if the resource is not available.
This could lead to long-lasting loops with long log files and unclear error messages.

#### Anti-pattern

```python
bucket = s3_client.get_bucket("test-bucket")
use_bucket(bucket)
```

#### Best practice

```python
buckets = s3_client.list_buckets()
if "test-bucket" not in buckets:
    pytest.fail("Expected test-bucket to exist - it doesn't")
```

### R05

Add mechanisms to avoid access failures caused by rate limiting.
This can be done by adding exponential backoff or caching mechanisms.
In some cases, rate limits can be avoided by using an authenticated request.

#### Anti-pattern

```python
while True:
    response = requests.get("http://resource.com")
    if response.status_code == 429:  # Too many requests
        pass  # immediately try again
    else:
        use(response)
```

#### Best practice

```python
cache = TTLCache(ttl=60)


@cached(cache)
def get_resource(url, token, retries=10):
    retry = 0
    while retry < retries:
        response = authenticated_request(url, token)
        if response.status_code == 429:
            time.sleep(2 ** retry)  # Exponential backoff
        else:
            return response


resource = get_resource("http://resource.com", "abdfabdf")
use(resource)
```

### R06

Do not wait a set amount of time but instead opt for a reactive approach using notification systems or polling for asynchronous (long-lasting) operations.
Waiting a set amount of time can lead to long test runs and flaky tests, as the time needed for the operation can vary.

#### Anti-pattern

```python
create_resource()
time.sleep(300)
use_resource()
```

#### Best practice

```python
create_resource()
poll_condition(resource_exists, timeout=60)
use_resource()
```

### R07

For tests with multiple steps, handle waits separately and start each wait in the correct state.
This way, the test can be more reactive and not wait for a set amount of time.

#### Anti-pattern

```python
create_resource()
deploy_resource()
use_resource()
```

or

```python
create_resource()
deploy_resource()
poll_condition(resource_deployed, timeout=60)
use_resource()
```

#### Best practice

```python
create_resource()
poll_condition(resource_exists, timeout=20)
deploy_resource()
poll_condition(resource_deployed, timeout=60)
use_resource()
```

### R08

Ensure features interacting with account numbers work with arbitrary account numbers and multiple accounts simultaneously. 
See [here](multi-account-region-testing/README.md) for further documentation for multi account/region testing.

#### Anti-pattern

1. Add new feature
2. Use it with fixed account number
3. Works -> done

#### Best practice

1. Add new feature
2. Use it with fixed account number
3. Works
4. Try with randomized account numbers (as in [documentation](multi-account-region-testing/README.md)
5. Works -> done

### R09

Make sure that your tests are idempotent and could theoretically run in parallel, by using randomized IDs and not re-using IDs across tests.
This also means that tests should not depend on each other and should be able to run in any order.

#### Anti-pattern

```python
def test_something():
    key = "test-bucket"
    create_bucket(key)

def test_something_else():
    key = "test-bucket"
    create_bucket(key)
```

#### Best practice

```python
def test_something():
    key = f"test-bucket-{short_uid()}"
    create_bucket(key)
    
def test_something_else():
    key = f"test-bucket-{short_uid()}"
    create_bucket(key)
```

### R10

Ensure deterministic responses for anything that reaches an assertion or a snapshot match.
This is especially important when you have randomized IDs in your tests as per [R09](#r09).
You can achieve this by using proper transformations. 
See [here](parity-testing/README.md) for further documentation on parity testing and how to use transformers.

#### Anti-pattern

```python
snapshot = {"key": "key-asdfasdf"}  # representing snapshot as a dict for presentation purposes


def test_something(snapshot):
    key = f"key-{short_uid()}"
    snapshot.match(snapshot, {"key": key})
```

#### Best practice

```python
snapshot = {"key": "<key:1>"}  # representing snapshot as a dict for presentation purposes


def test_something(snapshot):
    snapshot.add_transformer(...)  # add appropriate transformers
    key = f"key-{short_uid()}"
    snapshot.match(snapshot, {"key": key})
```

### R11

Be vigilant about changes happening to dependencies (Python dependencies and other) that can affect stability of your added features and tests.

#### Anti-pattern

1. Add dependency
2. Forget about it
3. Dependency adds instability
4. Disregard

#### Best practice

1. Add dependency
2. Check weekly python upgrade PR for upgrades to the dependency
3. Keep track of relevant changes from the changelog

### R12

Ensure all dependencies are available and functional on both AMD64 and ARM64 architectures.
If a dependency is exclusive to one architecture, mark the corresponding test accordingly.
However, if possible, try to use multi-platform resources.

#### Anti-pattern

```python
def test_docker():
    docker.run(image="amd64-only-image")
```

#### Best practice

```python
def test_docker():
    docker.run(image="multi-platform-image")
```

if above not possible, then:

```python
@markers.only_on_amd64
def test_docker():
    docker.run(image="amd64-only-image")
```

### R13

After the test run, make sure that the created resources are cleaned up properly.
This can easily be achieved by using fixtures with a yield statement.
This way, the resources are cleaned up after the test run, even if the test fails.
Furthermore, you could use factory fixtures to create resources on demand and then clean them up together.

#### Anti-pattern

```python
def test_something():
    key = f"test-{short_uid()}"
    s3_client.create_bucket(key)
    use_bucket(key)
    # bucket still exists after test run
```

#### Best practice

```python
@pytest.fixture
def bucket():
    key = f"test-{short_uid()}"
    s3_client.create_bucket(key)
    yield key
    s3_client.delete_bucket(key)

def test_something(bucket):
    use_bucket(bucket)
    # bucket is deleted after test run
```

### R14

Utilize fixture scopes for ensuring created resources exist as long as they should.
For example, if a resource should exist for the duration of the test run, use the `session` scope.
If a resource should exist for the duration of the test, use the `function` scope.

#### Anti-pattern

```python
@pytest.fixture(scope="function") # function scope is default
def database_server():
    server = start_database_server()
    yield server
    stop_database_server()

@pytest.fixture(scope="function") # function scope is default
def database_connection(database_server):
    conn = connect_to_database(database_server)
    yield conn
    conn.close()

def test_insert_data(database_connection):
    insert_data(database_connection)
    # The database server is started and stopped for each test function,
    # leading to increased overhead and potential performance issues.

def test_query_data(database_connection):
    query_data(database_connection)
    # Similar issue here, the server is started and stopped for each test.
```

#### Best practice

```python
@pytest.fixture(scope="session")
def database_server():
    server = start_database_server()
    yield server
    stop_database_server()

@pytest.fixture(scope="function") # function scope is default
def database_connection(database_server):
    conn = connect_to_database(database_server)
    yield conn
    conn.close()

def test_insert_data(database_connection):
    insert_data(database_connection)

def test_query_data(database_connection):
    query_data(database_connection)
```

## Test markers

For tests, we offer additional markers which can be found
in: [localstack/testing/pytest/marking.py](../../localstack-core/localstack/testing/pytest/marking.py)

