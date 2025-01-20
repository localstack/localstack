"""This Lambda Runtimes reference defines everything around Lambda runtimes to facilitate adding new runtimes."""

from typing import Optional

from localstack.aws.api.lambda_ import Runtime

# LocalStack Lambda runtimes support policy
# We support all Lambda runtimes currently actively supported at AWS.
# Further, we aim to provide best-effort support for deprecated runtimes at least until function updates are blocked,
# ideally a bit longer to help users migrate their Lambda runtimes. However, we do not actively test them anymore.

# HOWTO add a new Lambda runtime:
# 1. Update botocore and generate the Lambda API stubs using `python3 -m localstack.aws.scaffold upgrade`
# => This usually happens automatically through the Github Action "Update ASF APIs"
# 2. Add the new runtime to these variables below:
# a) `IMAGE_MAPPING`
# b) `RUNTIMES_AGGREGATED`
# c) `SNAP_START_SUPPORTED_RUNTIMES` if supported (currently only new Java runtimes)
# 3. Re-create snapshots for Lambda tests with the marker @markers.lambda_runtime_update
# => Filter the tests using pytest -m lambda_runtime_update (i.e., additional arguments in PyCharm)
# Depending on the runtime, `test_lambda_runtimes.py` might require further snapshot updates.
# 4. Add the new runtime to these variables below:
# a) `VALID_RUNTIMES` matching the order of the snapshots
# b) `VALID_LAYER_RUNTIMES` matching the order of the snapshots
# 5. Run the unit test to check the runtime setup:
# tests.unit.services.lambda_.test_api_utils.TestApiUtils.test_check_runtime
# 6. Review special tests including:
# a) [ext] tests.aws.services.lambda_.test_lambda_endpoint_injection
# 7. Before merging, run the ext integration tests to cover transparent endpoint injection testing.
# 8. Add the new runtime to the K8 image build: https://github.com/localstack/lambda-images
# 9. Inform the web team to update the resource browser (consider offering an endpoint in the future)

# Mapping from a) AWS Lambda runtime identifier => b) official AWS image on Amazon ECR Public
# a) AWS Lambda runtimes: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
# b) Amazon ECR Lambda images: https://gallery.ecr.aws/lambda
# => Synchronize the order with the "Supported runtimes" under "AWS Lambda runtimes" (a)
# => Add comments for deprecated runtimes using <Deprecation date> => <Block function create> => <Block function update>
IMAGE_MAPPING: dict[Runtime, str] = {
    Runtime.nodejs22_x: "nodejs:22",
    Runtime.nodejs20_x: "nodejs:20",
    Runtime.nodejs18_x: "nodejs:18",
    Runtime.nodejs16_x: "nodejs:16",
    Runtime.nodejs14_x: "nodejs:14",  # deprecated Dec 4, 2023  => Jan 9, 2024  => Feb 8, 2024
    Runtime.nodejs12_x: "nodejs:12",  # deprecated Mar 31, 2023 => Mar 31, 2023 => Apr 30, 2023
    Runtime.python3_13: "python:3.13",
    Runtime.python3_12: "python:3.12",
    Runtime.python3_11: "python:3.11",
    Runtime.python3_10: "python:3.10",
    Runtime.python3_9: "python:3.9",
    Runtime.python3_8: "python:3.8",
    Runtime.python3_7: "python:3.7",  # deprecated Dec 4, 2023 => Jan 9, 2024 => Feb 8, 2024
    Runtime.java21: "java:21",
    Runtime.java17: "java:17",
    Runtime.java11: "java:11",
    Runtime.java8_al2: "java:8.al2",
    Runtime.java8: "java:8",  # deprecated Jan 8, 2024 => Feb 8, 2024 => Mar 12, 2024
    Runtime.dotnet8: "dotnet:8",
    # dotnet7 (container only)
    Runtime.dotnet6: "dotnet:6",
    Runtime.dotnetcore3_1: "dotnet:core3.1",  # deprecated Apr 3, 2023 => Apr 3, 2023 => May 3, 2023
    Runtime.go1_x: "go:1",  # deprecated Jan 8, 2024 => Feb 8, 2024 => Mar 12, 2024
    Runtime.ruby3_3: "ruby:3.3",
    Runtime.ruby3_2: "ruby:3.2",
    Runtime.ruby2_7: "ruby:2.7",  # deprecated Dec 7, 2023 => Jan 9, 2024 => Feb 8, 2024
    Runtime.provided_al2023: "provided:al2023",
    Runtime.provided_al2: "provided:al2",
    Runtime.provided: "provided:alami",  # deprecated Jan 8, 2024 => Feb 8, 2024 => Mar 12, 2024
}


# A list of all deprecated Lambda runtimes, with upgrade recommendations
# ideally ordered by deprecation date (following the AWS docs).
# LocalStack can still provide best-effort support.

# TODO: Consider removing these as AWS is not using them anymore and they likely get outdated.
#  We currently use them in LocalStack logs as bonus recommendation (DevX).
# When updating the recommendation,
# please regenerate all tests with @markers.lambda_runtime_update
DEPRECATED_RUNTIMES_UPGRADES: dict[Runtime, Optional[Runtime]] = {
    # deprecated Jan 8, 2024 => Feb 8, 2024 => Mar 12, 2024
    Runtime.java8: Runtime.java21,
    # deprecated Jan 8, 2024 => Feb 8, 2024 => Mar 12, 2024
    Runtime.go1_x: Runtime.provided_al2023,
    # deprecated Jan 8, 2024 => Feb 8, 2024 => Mar 12, 2024
    Runtime.provided: Runtime.provided_al2023,
    # deprecated Dec 7, 2023 => Jan 9, 2024 => Feb 8, 2024
    Runtime.ruby2_7: Runtime.ruby3_2,
    # deprecated Dec 4, 2023  => Jan 9, 2024  => Feb 8, 2024
    Runtime.nodejs14_x: Runtime.nodejs20_x,
    # deprecated Dec 4, 2023 => Jan 9, 2024 => Feb 8, 2024
    Runtime.python3_7: Runtime.python3_12,
    # deprecated Apr 3, 2023 => Apr 3, 2023 => May 3, 2023
    Runtime.dotnetcore3_1: Runtime.dotnet6,
    # deprecated Mar 31, 2023 => Mar 31, 2023 => Apr 30, 2023
    Runtime.nodejs12_x: Runtime.nodejs18_x,
}


DEPRECATED_RUNTIMES: list[Runtime] = list(DEPRECATED_RUNTIMES_UPGRADES.keys())

# An unordered list of all AWS-supported runtimes.
SUPPORTED_RUNTIMES: list[Runtime] = list(set(IMAGE_MAPPING.keys()) - set(DEPRECATED_RUNTIMES))

# A temporary list of missing runtimes not yet supported in LocalStack. Used for modular updates.
MISSING_RUNTIMES = []

# An unordered list of all Lambda runtimes supported by LocalStack.
ALL_RUNTIMES: list[Runtime] = list(IMAGE_MAPPING.keys())

# Grouped supported runtimes by language for testing. Moved here from `lambda_utils` for easier runtime updates.
# => Remove deprecated runtimes from this testing list
RUNTIMES_AGGREGATED = {
    "nodejs": [
        Runtime.nodejs22_x,
        Runtime.nodejs20_x,
        Runtime.nodejs18_x,
        Runtime.nodejs16_x,
    ],
    "python": [
        Runtime.python3_13,
        Runtime.python3_12,
        Runtime.python3_11,
        Runtime.python3_10,
        Runtime.python3_9,
        Runtime.python3_8,
    ],
    "java": [
        Runtime.java21,
        Runtime.java17,
        Runtime.java11,
        Runtime.java8_al2,
    ],
    "ruby": [
        Runtime.ruby3_2,
        Runtime.ruby3_3,
    ],
    "dotnet": [
        Runtime.dotnet6,
        Runtime.dotnet8,
    ],
    "provided": [
        Runtime.provided_al2023,
        Runtime.provided_al2,
    ],
}

# An unordered list of all tested runtimes listed in `RUNTIMES_AGGREGATED`
TESTED_RUNTIMES: list[Runtime] = [
    runtime for runtime_group in RUNTIMES_AGGREGATED.values() for runtime in runtime_group
]

# An ordered list of all Lambda runtimes considered valid by AWS. Matching snapshots in test_create_lambda_exceptions
VALID_RUNTIMES: str = "[nodejs20.x, provided.al2023, python3.12, python3.13, nodejs22.x, java17, nodejs16.x, dotnet8, python3.10, java11, python3.11, dotnet6, java21, nodejs18.x, provided.al2, ruby3.3, java8.al2, ruby3.2, python3.8, python3.9]"
# An ordered list of all Lambda runtimes for layers considered valid by AWS. Matching snapshots in test_layer_exceptions
VALID_LAYER_RUNTIMES: str = "[ruby2.6, dotnetcore1.0, python3.7, nodejs8.10, nasa, ruby2.7, python2.7-greengrass, dotnetcore2.0, python3.8, java21, dotnet6, dotnetcore2.1, python3.9, java11, nodejs6.10, provided, dotnetcore3.1, dotnet8, java17, nodejs, nodejs4.3, java8.al2, go1.x, nodejs20.x, go1.9, byol, nodejs10.x, provided.al2023, nodejs22.x, python3.10, java8, nodejs12.x, python3.11, nodejs8.x, python3.12, nodejs14.x, nodejs8.9, python3.13, nodejs16.x, provided.al2, nodejs4.3-edge, nodejs18.x, ruby3.2, python3.4, ruby3.3, ruby2.5, python3.6, python2.7]"
