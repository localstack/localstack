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
| R02 | Do not assume external dependencies (AWS resources, files, packages, images, licenses) are indefinitely available on the same location. They can move and we need to adapt in the future for it. |
| R03 | Where possible, tests should be in control of the resources they use and re-create them if removed (e.g., S3 buckets, roles). |
| R04 | If on-demand creation is not possible, opt for a fail-fast approach and make retrieval failures clearly visible for further investigation. |
| R05 | Add mechanisms to avoid access failures caused by rate limiting. |
| R06 | Do not wait a set amount of time but instead opt for a reactive approach using notification systems or polling for asynchronous (long-lasting) operations |
| R07 | For tests with multiple steps, handle waits separately and start each wait in the correct state. |
| R08 | Ensure features interacting with account numbers work with arbitrary account numbers and multiple accounts simultaneously. (see [here](multi-account-region-testing/README.md) for further documentation) |
| R09 | Ensure deterministic responses for anything that reaches an assertion or a snapshot match (e.g., by using proper transformations). (see [here](parity-testing/README.md) for further documentation) |
| R10 | Be vigilant about changes happening to dependencies (Python dependencies and other) that can affect stability of your added features and tests. |
| R11 | Ensure all dependencies are available and functional on both AMD64 and ARM64 architectures. If a dependency is exclusive to one architecture, mark the corresponding test accordingly. |


### R01

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

#### Anti-pattern

```python
response = requests.get("http://resource.com/my-resource.tar.gz")
use_resource(response.content)
```

#### Best practice

```python
response = requests.get("http://resource.com/my-resource.tar.gz")
if response.status_code == 404:
    further_steps() # e.g. clear error message, potential documentation on where to find a new location, etc.
use_resource(response.content)
```

### R03

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

#### Anti-pattern

```python
while True:
    response = requests.get("http://resource.com")
    if response.status_code == 429: # Too many requests
        pass # immediately try again
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
            time.sleep(2 ** retry) # Exponential backoff
        else:
            return response

resource = get_resource("http://resource.com", "abdfabdf")
use(resource)
```

### R06

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

#### Anti-pattern

```python
snapshot = {"key": "key-asdfasdf"} # representing snapshot as a dict for presentation purposes

def test_something(snapshot):
    key = f"key-{short_uid()}"
    snapshot.match(snapshot, {"key": key})
```

#### Best practice

```python
snapshot = {"key": "<key:1>"} # representing snapshot as a dict for presentation purposes

def test_something(snapshot):
    snapshot.add_transformer(...) # add appropriate transformers
    key = f"key-{short_uid()}"
    snapshot.match(snapshot, {"key": key})
```

[documentation](parity-testing/README.md)

### R10

#### Anti-pattern

1. Add dependency
2. Forget about it
3. Dependency adds instability
4. Disregard

#### Best practice

1. Add dependency
2. Check weekly python upgrade PR for upgrades to the dependency
3. Keep track of relevant changes from the changelog

### R11

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

## Test markers

For tests, we offer the following markers additionally to the regular pytest markers:

| Marker                                  | Description                                                                                               |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `markers.acceptance_test_beta`          | Tests to be included in the acceptance tests                                                              |
| `markers.skip_offline`                  | Tests that require an online connection                                                                   |
| `markers.only_on_amd64`                 | Tests that only run on AMD64 architecture                                                                 |
| `markers.only_on_arm64`                 | Tests that only run on ARM64 architecture                                                                 |
| `markers.resource_heavy`                | Tests that are resource intensive                                                                         |
| `markers.only_in_docker`                | Tests that only run within a Docker environment                                                           |
| `markers.lambda_runtime_update`         | Tests to execute when updating snapshots for a new Lambda runtime                                         |
| `markers.snapshot.skip_snapshot_verify` | Define the paths which should not be checked by the snapshot matching                                     |
| `markers.aws.validated`                 | Test has been successfully run against AWS, ideally multiple times                                        |
| `markers.aws.manual_setup_required`     | Implies aws_validated. Test needs additional setup, configuration, or some other steps not included in the test setup itself |
| `markers.aws.needs_fixing`              | Fails against AWS but should be made runnable against AWS in the future (TODO)                            |
| `markers.aws.only_localstack`           | Only runnable against LocalStack by design                                                                |
| `markers.aws.unknown`                   | It's unknown if the test works (reliably) against AWS or not                                              |

