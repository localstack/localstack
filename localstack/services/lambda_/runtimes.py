"""This Lambda Runtimes reference defines everything around Lambda runtimes to facilitate adding new runtimes."""
from localstack.aws.api.lambda_ import Runtime

# HOWTO add a new Lambda runtime:
# 1. Update botocore and generate the Lambda API stubs using `python3 -m localstack.aws.scaffold upgrade`
# => This usually happens automatically through the Github Action "Update ASF APIs"
# 2. Add the new runtime to these variables below:
# a) `IMAGE_MAPPING`
# b) `RUNTIMES_AGGREGATED`
# c) `SNAP_START_SUPPORTED_RUNTIMES` if supported (currently only new Java runtimes)
# 3. Re-create snapshots for Lambda tests with the marker @markers.lambda_runtime_update
# => Filter the tests using pytest -m lambda_runtime_update (i.e., additional arguments in PyCharm)
# 4. Add the new runtime to these variables below:
# a) `VALID_RUNTIMES` matching the order of the snapshots
# b) `VALID_LAYER_RUNTIMES` matching the order of the snapshots
# 5. Run the unit test to check the runtime setup:
# tests.unit.services.lambda_.test_api_utils.TestApiUtils.test_check_runtime
# 6. Review special tests including:
# a) [ext] tests.aws.services.lambda_.test_lambda_endpoint_injection
# 7. Before merging, run the ext integration tests to cover transparent endpoint injection testing.
# 8. Add the new runtime to the K8 image build: https://github.com/localstack/lambda-cve-mitigation
# 9. Inform the web team to update the resource browser (consider offering an endpoint in the future)

# Mapping from a) AWS Lambda runtime identifier => b) official AWS image on Amazon ECR Public
# a) AWS Lambda runtimes: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
# b) Amazon ECR Lambda images: https://gallery.ecr.aws/lambda
# => Synchronize the order with the "Supported runtimes" under "AWS Lambda runtimes" (a)
# => Add comments for deprecated runtimes using <Phase 1> => <Phase 2>
IMAGE_MAPPING: dict[Runtime, str] = {
    # "nodejs22.x": "nodejs:22", expected November 2024
    Runtime.nodejs20_x: "nodejs:20",
    Runtime.nodejs18_x: "nodejs:18",
    Runtime.nodejs16_x: "nodejs:16",
    Runtime.nodejs14_x: "nodejs:14",
    Runtime.nodejs12_x: "nodejs:12",  # deprecated Mar 31, 2023 => Apr 30, 2023
    # "python3.13": "python:3.13", expected November 2024
    Runtime.python3_12: "python:3.12",
    Runtime.python3_11: "python:3.11",
    Runtime.python3_10: "python:3.10",
    Runtime.python3_9: "python:3.9",
    Runtime.python3_8: "python:3.8",
    Runtime.python3_7: "python:3.7",
    Runtime.java21: "java:21",
    Runtime.java17: "java:17",
    Runtime.java11: "java:11",
    Runtime.java8_al2: "java:8.al2",
    Runtime.java8: "java:8",
    # "dotnet8": "dotnet:8", expected January 2024
    # dotnet7 (container only)
    Runtime.dotnet6: "dotnet:6",
    Runtime.dotnetcore3_1: "dotnet:core3.1",  # deprecated Apr 3, 2023 => May 3, 2023
    Runtime.go1_x: "go:1",
    # "ruby3.3": "ruby:3.3", expected March 2024
    Runtime.ruby3_2: "ruby:3.2",
    Runtime.ruby2_7: "ruby:2.7",
    Runtime.provided_al2023: "provided:al2023",
    Runtime.provided_al2: "provided:al2",
    Runtime.provided: "provided:alami",
}

# An unordered list of all deprecated Lambda runtimes that are still supported in LocalStack.
DEPRECATED_RUNTIMES: list[Runtime] = [
    Runtime.nodejs12_x,  # deprecated Mar 31, 2023 => Apr 30, 2023
    Runtime.dotnetcore3_1,  # deprecated Apr 3, 2023 => May 3, 2023
    # deprecate once snapshot tests show that it really happened
    # Runtime.python3_7,  # deprecated Nov 27, 2023 => ???
    # Runtime.nodejs14_x,  # deprecated Nov 27, 2023 => ???
]
# An unordered list of all AWS-supported runtimes.
SUPPORTED_RUNTIMES: list[Runtime] = list(set(IMAGE_MAPPING.keys()) - set(DEPRECATED_RUNTIMES))

# An unordered list of all Lambda runtimes supported by LocalStack.
ALL_RUNTIMES: list[Runtime] = list(IMAGE_MAPPING.keys())

# Grouped supported runtimes by language for testing. Moved here from `lambda_utils` for easier runtime updates.
# => Remove deprecated runtimes from this testing list
RUNTIMES_AGGREGATED = {
    "nodejs": [
        Runtime.nodejs20_x,
        Runtime.nodejs18_x,
        Runtime.nodejs16_x,
        Runtime.nodejs14_x,
    ],
    "python": [
        Runtime.python3_12,
        Runtime.python3_11,
        Runtime.python3_10,
        Runtime.python3_9,
        Runtime.python3_8,
        Runtime.python3_7,
    ],
    "java": [
        Runtime.java21,
        Runtime.java17,
        Runtime.java11,
        Runtime.java8_al2,
        Runtime.java8,
    ],
    "ruby": [
        Runtime.ruby3_2,
        Runtime.ruby2_7,
    ],
    "dotnet": [Runtime.dotnet6],
    "go": [Runtime.go1_x],
    "custom": [
        Runtime.provided_al2023,
        Runtime.provided_al2,
        Runtime.provided,
    ],
}

# An unordered list of all tested runtimes listed in `RUNTIMES_AGGREGATED`
TESTED_RUNTIMES: list[Runtime] = [
    runtime for runtime_group in RUNTIMES_AGGREGATED.values() for runtime in runtime_group
]

# An unordered list of snapstart-enabled runtimes. Related to snapshots in test_snapstart_exceptions
# https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html
SNAP_START_SUPPORTED_RUNTIMES = [Runtime.java11, Runtime.java17, Runtime.java21]

# An ordered list of all Lambda runtimes considered valid by AWS. Matching snapshots in test_create_lambda_exceptions
VALID_RUNTIMES: str = "[nodejs20.x, provided.al2023, python3.12, java17, provided, nodejs16.x, nodejs14.x, ruby2.7, python3.10, java11, python3.11, dotnet6, go1.x, java21, nodejs18.x, provided.al2, java8, java8.al2, ruby3.2, python3.7, python3.8, python3.9]"
# An ordered list of all Lambda runtimes for layers considered valid by AWS. Matching snapshots in test_layer_exceptions
VALID_LAYER_RUNTIMES: str = "[ruby2.6, dotnetcore1.0, python3.7, nodejs8.10, nasa, ruby2.7, python2.7-greengrass, dotnetcore2.0, python3.8, java21, dotnet6, dotnetcore2.1, python3.9, java11, nodejs6.10, provided, dotnetcore3.1, dotnet8, java17, nodejs, nodejs4.3, java8.al2, go1.x, nodejs20.x, go1.9, byol, nodejs10.x, provided.al2023, python3.10, java8, nodejs12.x, python3.11, nodejs8.x, python3.12, nodejs14.x, nodejs8.9, python3.13, nodejs16.x, provided.al2, nodejs4.3-edge, nodejs18.x, ruby3.2, python3.4, ruby2.5, python3.6, python2.7]"
