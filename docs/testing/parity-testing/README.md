from conftest import aws_client

# Parity Testing

Parity tests (also called snapshot tests) are a special form of integration tests that should verify and improve the correctness of LocalStack compared to AWS.

Initially, the integration test is executed against AWS and collects responses of interest. Those responses are called "snapshots" and will be used later on to compare the results from AWS with the ones from LocalStack.
Those responses aka "snapshots" are stored in a **snapshot.json** file.

Once the snapshot is recorded, the test can be executed against LocalStack. During this “normal” test execution, the test runs against LocalStack and compares the LocalStack responses with the recorded content.

In theory, every integration test can be converted to a parity conform snapshot test.

This guide assumes you are already familiar with writing [integration tests](../integration-tests/README.md) for LocalStack in general.

## How to write Parity tests

In a nutshell, the necessary steps include:

1.  Make sure that the test works against AWS.
    * Check out our [Integration Test Guide](../integration-tests/README.md#running-integration-tests-against-aws) for tips on how run integration tests against AWS.
2.  Add the `snapshot` fixture to your test and identify which responses you want to collect and compare against LocalStack.
    * Use `snapshot.match(”identifier”, result)` to mark the result of interest. It will be recorded and stored in a file with the name `<testfile-name>.snapshot.json`
    *  The **identifier** can be freely selected, but ideally it gives a hint on what is recorded - so typically the name of the function. The **result** is expected to be a `dict`.
    * Run the test against AWS: use the parameter `--snapshot-update` (or the environment variable `SNAPSHOT_UPDATE=1`) and set the environment variable as `TEST_TARGET=AWS_CLOUD`.
    * Check the recorded result in `<testfile-name>.snapshot.json` and consider [using transformers](#using-transformers) to make the result comparable.
3.  Run the test against LocalStack.
    * Hint: Ensure that the `AWS_CLOUD` is not set as a test target and that the parameter `--snapshot-update` is removed.
    * If you used the environment variable make sure to delete it or reset the value, e.g. `SNAPSHOT_UPDATE=0`

Here is an example of a parity test:

```python
def test_invocation(self, aws_client, snapshot):
    # add transformers to make the results comparable
    snapshot.add_transformer(snapshot.transform.lambda_api())

    result = aws_client.lambda_.invoke(
            ....
    )
    # records the 'result' using the identifier 'invoke'
    snapshot.match("invoke", result)
```


## The Snapshot

When an integration test is executed against AWS with the `snapshot-update` flag, the response will automatically be updated in the snapshot-file.

**The file is automatically created if it doesn't exist yet.** The naming pattern is `<filename>.snapshot.json` where `<filename>` is the name of the file where the test is located.
One file can contain several snapshot recordings, e.g. the result from several tests.

The snapshot file is a json-file, and each json-object on the root-level represents one test.
E.g., imagine the test file name is `test_lambda_api.py` (example is outlined in ['Reference Replacement'](#reference-replacement)), with the class `TestLambda`.

When running the test `test_basic_invoke` it will create a json-object `test_lambda_api.py::TestLambda::test_basic_invoke`.

Each recorded snapshot contains:
 * `recorded-date` the timestamp when this test was last updated
 * `recorded-content` contains all `identifiers` as keys, with the `response` as values, from the tests `snapshot.match(identifier, response)` definitions

Note that all json-strings of a response will automatically be parsed to json. This makes the comparison, transformation, and exclusion of certain keys easier (string vs json-object).

**Snapshot files should never be modified manually.** If one or more snapshots need to be updated, simply execute the test against AWS, and [use transformers](#using-transformers) to make the recorded responses comparable.

## Using Transformers

In order to make results comparable, some parts response might need to be adapted before storing the record as a snapshot.
For example, AWS responses could contain special IDs, usernames, timestamps, etc.

Transformers should bring AWS response in a comparable form by replacing any request-specific parameters. Replacements require thoughtful handling so that important information is not lost in translation.

The `snapshot` fixture uses some basic transformations by default, including:

-   Trimming MetaData (we only keep the `HTTPStatusCode` and `content-type` if set).
-   Replacing all UUIDs (that match a regex) with [reference-replacement](#reference-replacement).
-   Replacing everything that matches the ISO8601 pattern with “date”.
-   Replacing any value with datatype `datetime` with “datetime”.
-   Replace all values where the key contains “timestamp” with “timestamp”.
-   Regex replacement of the `account-id`.
-   Regex replacement of the location.

## API Transformer

APIs for one service often require similar transformations. Therefore, we introduced some utilities that collect common transformations grouped by service.

Ideally, the service-transformation already includes every transformation that is required.
The [TransformerUtility](https://github.com/localstack/localstack/blob/master/localstack-core/localstack/testing/snapshots/transformer_utility.py) already provides some collections of transformers for specific service APIs.

For example, to add common transformers for lambda, you can use: `snapshot.add_transformer(snapshot.transform.lambda_api()`.

## Transformer Types

The Parity testing framework currently includes some basic transformer types:

-   `KeyValueBasedTransformer` replaces a value directly, or by reference; based on key-value evaluation.
-   `JsonPathTransformer` replaces the JSON path value directly, or by reference. [jsonpath-ng](https://pypi.org/project/jsonpath-ng/) is used for the JSON path evaluation.
-   `RegexTransformer` replaces the regex pattern globally. Please be aware that this will be applied on the json-string. The JSON will be transformed into a string, and the replacement happens globally - use it with care.

Hint: There are also some simplified transformers in [TransformerUtility](https://github.com/localstack/localstack/blob/master/localstack-core/localstack/testing/snapshots/transformer_utility.py).

### Examples

A transformer, that replaces the key `logGroupName` only if the value matches the value `log_group_name`:

```python
snapshot.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: v if k == "logGroupName" and v == log_group_name else None,
                replacement="log-group",
            )
        )
```

If you only want to check for the key name, a simplified transformer could look like this:

```python
snapshot.add_transformer(snapshot.transform.key_value("logGroupName"))
```

## Reference Replacement

Parameters can be replaced by reference. In contrast to the “direct” replacement, the value to be replaced will be **registered, and replaced later on as regex pattern**. It has the advantage of keeping information, when the same reference is used in several recordings in one test.

Consider the following example:

```python
def test_basic_invoke(
        self, aws_client, create_lambda, snapshot
    ):

    # custom transformers
    snapshot.add_transformer(snapshot.transform.lambda_api())

    # predefined names for functions
    fn_name = f"ls-fn-{short_uid()}"
    fn_name_2 = f"ls-fn-{short_uid()}"

    # create function 1
    response = create_lambda(FunctionName=fn_name, ...  )
    snapshot.match("lambda_create_fn", response)

    # create function 2
    response = create_lambda(FunctionName=fn_name_2, ...  )
    snapshot.match("lambda_create_fn_2", response)

    # get function 1
    get_fn_result = aws_client.lambda_.get_function(FunctionName=fn_name)
    snapshot.match("lambda_get_fn", get_fn_result)

    # get function 2
    get_fn_result_2 = aws_client.lambda_.get_function(FunctionName=fn_name_2)
    snapshot.match("lambda_get_fn_2", get_fn_result_2)
```

The information that the function-name of the first recording (`lambda_create_fn`) is the same as in the record for `lambda_get_fn` is important.

Using reference replacement, this information is preserved in the `snapshot.json`. The reference replacement automatically adds an ascending number, to ensure that different values can be differentiated.

```json
{
  "test_lambda_api.py::TestLambda::test_basic_invoke": {
    "recorded-date": ...,
    "recorded-content": {
      "lambda_create_fn": {
       ...
        "FunctionName": "<function-name:1>",
        "FunctionArn": "arn:aws:lambda:<region>:111111111111:function:<function-name:1>",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::111111111111:role/<resource:1>",
        ...
      },
      "lambda_create_fn_2": {
        ...
        "FunctionName": "<function-name:2>",
        "FunctionArn": "arn:aws:lambda:<region>:111111111111:function:<function-name:2>",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::111111111111:role/<resource:1>",
        ...
      },
      "lambda_get_fn": {
        ...
        "Configuration": {
          "FunctionName": "<function-name:1>",
          "FunctionArn": "arn:aws:lambda:<region>:111111111111:function:<function-name:1>",
          "Runtime": "python3.9",
          "Role": "arn:aws:iam::111111111111:role/<resource:1>",
         ...
      },
      "lambda_get_fn_2": {
        ...
        "Configuration": {
          "FunctionName": "<function-name:2>",
          "FunctionArn": "arn:aws:lambda:<region>:111111111111:function:<function-name:2>",
          "Role": "arn:aws:iam::111111111111:role/<resource:1>",
          ....
        },
      },

    }
  }
}
```

## Tips and Tricks for Transformers

Getting the transformations right can be a tricky task and we appreciate the time you spend on writing parity snapshot tests for LocalStack! We are aware that it might be challenging to implement transformers that work for AWS and LocalStack responses.

In general, we are interested in transformers that work for AWS. Therefore, we recommend also running the tests and testing the transformers against AWS itself.

Meaning, after you have executed the test with the `snapshot-update` flag and recorded the snapshot, you can run the test without the update flag against the `AWS_CLOUD` test target. If the test passes, we can be quite certain that the transformers work in general. Any deviations with LocalStack might be due to missing parity.

You do not have to fix any deviations right away, even though we would appreciate this very much! It is also possible to exclude the snapshot verification of single test cases, or specific json-pathes of the snapshot.

### Skipping verification of snapshot test

Snapshot verification is enabled by default. If for some reason you want to skip any snapshot verification, you can set the parameter `--snapshot-skip-all`.

If you want to skip verification for or a single test case, you can set the pytest marker `skip_snapshot_verify`. If you set the marker without a parameter, the verification will be skipped entirely for this test case.

Additionally, you can exclude certain paths from the verification only.
Simply include a list of json-paths. Those paths will then be excluded from the comparison:

```python
@pytest.mark.skip_snapshot_verify(
        paths=["$..LogResult", "$..Payload.context.memory_limit_in_mb"]
    )
    def test_something_that_does_not_work_completly_yet(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        result = aws_client.lambda_....
        snapshot.match("invoke-result", result)
```

> [!NOTE]
> Generally, [transformers](#using-transformers) should be used wherever possible to make responses comparable.
> If specific paths are skipped from the verification, it means LocalStack does not have parity yet.

### Debugging the Transformers

Sometimes different transformers might interfere, especially regex transformers and reference transformations can be tricky We added debug logs so that each replacement step should be visible in the output to help locate any unexpected behavior. You can enable the debug logs by setting the env `DEBUG_SNAPSHOT=1`.

```bash
localstack.testing.snapshots.transformer: Registering regex pattern '000000000000' in snapshot with '111111111111'
localstack.testing.snapshots.transformer: Registering regex pattern 'us-east-1' in snapshot with '<region>'localstack.testing.snapshots.transformer: Replacing JsonPath '$.json_encoded_delivery..Body.Signature' in snapshot with '<signature>'
localstack.testing.snapshots.transformer: Registering reference replacement for value: '1ad533b5-ac54-4354-a273-3ea885f0d59d' -> '<uuid:1>'
localstack.testing.snapshots.transformer: Replacing JsonPath '$.json_encoded_delivery..MD5OfBody' in snapshot with '<md5-hash>'
localstack.testing.snapshots.transformer: Replacing regex '000000000000' with '111111111111'
localstack.testing.snapshots.transformer: Replacing regex 'us-east-1' with '<region>'
localstack.testing.snapshots.transformer: Replacing '1ad533b5-ac54-4354-a273-3ea885f0d59d' in snapshot with '<uuid:1>'
```
