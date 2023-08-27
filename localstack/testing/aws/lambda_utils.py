import itertools
import json
import logging
import os
import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Mapping, Optional, Sequence, overload

from localstack.aws.api.lambda_ import Runtime
from localstack.services.lambda_.lambda_api import use_docker
from localstack.utils.common import to_str
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import ShortCircuitWaitException, retry
from localstack.utils.testutil import get_lambda_log_events

if TYPE_CHECKING:
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_lambda.literals import ArchitectureType, PackageTypeType, RuntimeType
    from mypy_boto3_lambda.type_defs import (
        DeadLetterConfigTypeDef,
        EnvironmentTypeDef,
        EphemeralStorageTypeDef,
        FileSystemConfigTypeDef,
        FunctionCodeTypeDef,
        FunctionConfigurationResponseMetadataTypeDef,
        ImageConfigTypeDef,
        TracingConfigTypeDef,
        VpcConfigTypeDef,
    )

LOG = logging.getLogger(__name__)

# Supported Runtimes: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
# NOTE: missing support for `dotnet7` (container only)
RUNTIMES_AGGREGATED = {
    "python": [
        Runtime.python3_7,
        Runtime.python3_8,
        Runtime.python3_9,
        Runtime.python3_10,
        Runtime.python3_11,
    ],
    "nodejs": [Runtime.nodejs14_x, Runtime.nodejs16_x, Runtime.nodejs18_x],
    "ruby": [Runtime.ruby2_7, Runtime.ruby3_2],
    "java": [Runtime.java8, Runtime.java8_al2, Runtime.java11, Runtime.java17],
    "dotnet": [Runtime.dotnet6],
    "go": [Runtime.go1_x],
    "custom": [Runtime.provided, Runtime.provided_al2],
}

HANDLERS = {
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("python"), "handler.handler"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("nodejs"), "index.handler"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("ruby"), "function.handler"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("java"), "echo.Handler"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("custom"), "function.handler"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("go"), "main"),
    "dotnetcore3.1": "dotnetcore31::dotnetcore31.Function::FunctionHandler",  # TODO lets see if we can accumulate those
    "dotnet6": "dotnet6::dotnet6.Function::FunctionHandler",
}

PACKAGE_FOR_RUNTIME = {
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("python"), "python"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("nodejs"), "nodejs"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("ruby"), "ruby"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("java"), "java"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("custom"), "provided"),
    **dict.fromkeys(RUNTIMES_AGGREGATED.get("go"), "go"),
    "dotnet6": "dotnet6",
    "dotnetcore3.1": "dotnetcore3.1",
}


def generate_tests(metafunc):
    i = next(metafunc.definition.iter_markers("multiruntime"), None)
    if not i:
        return
    if i.args:
        raise ValueError("doofus")

    scenario = i.kwargs["scenario"]
    runtimes = i.kwargs.get("runtimes")
    if not runtimes:
        runtimes = list(RUNTIMES_AGGREGATED.keys())
    ids = list(
        itertools.chain.from_iterable(
            RUNTIMES_AGGREGATED.get(runtime) or [runtime] for runtime in runtimes
        )
    )
    arg_values = [(scenario, runtime, HANDLERS[runtime]) for runtime in ids]

    metafunc.parametrize(
        argvalues=arg_values,
        argnames="multiruntime_lambda",
        indirect=True,
        ids=ids,
    )


def package_for_lang(scenario: str, runtime: str, root_folder: Path) -> str:
    """
    :param scenario: which scenario to run
    :param runtime: which runtime to build
    :param root_folder: The root folder for the scenarios
    :return: path to built zip file
    """
    runtime_folder = PACKAGE_FOR_RUNTIME[runtime]

    common_dir = root_folder / "functions" / "common"
    scenario_dir = common_dir / scenario
    runtime_dir_candidate = scenario_dir / runtime
    generic_runtime_dir_candidate = scenario_dir / runtime_folder

    # if a more specific folder exists, use that one
    # otherwise: try to fall back to generic runtime (e.g. python for python3.9)
    if runtime_dir_candidate.exists() and runtime_dir_candidate.is_dir():
        runtime_dir = runtime_dir_candidate
    else:
        runtime_dir = generic_runtime_dir_candidate

    build_dir = runtime_dir / "build"
    package_path = runtime_dir / "handler.zip"

    # caching step
    # TODO: add invalidation (e.g. via storing a hash besides this of all files in src)
    if os.path.exists(package_path) and os.path.isfile(package_path):
        return package_path

    # packaging
    result = subprocess.run(["make", "build"], cwd=runtime_dir)
    if result.returncode != 0:
        raise Exception(
            f"Failed to build multiruntime {scenario=} for {runtime=} with error code: {result.returncode}"
        )

    # check again if the zip file is now present
    if os.path.exists(package_path) and os.path.isfile(package_path):
        return package_path

    # check something is in build now
    target_empty = len(os.listdir(build_dir)) <= 0
    if target_empty:
        raise Exception(f"Failed to build multiruntime {scenario=} for {runtime=} ")

    with zipfile.ZipFile(package_path, "w", strict_timestamps=True) as zf:
        for root, dirs, files in os.walk(build_dir):
            rel_dir = os.path.relpath(root, build_dir)
            for f in files:
                zf.write(os.path.join(root, f), arcname=os.path.join(rel_dir, f))

    # make sure package file has been generated
    assert package_path.exists() and package_path.is_file()
    return package_path


class ParametrizedLambda:
    lambda_client: "LambdaClient"
    function_names: list[str]
    scenario: str
    runtime: str
    handler: str
    zip_file_path: str
    role: str

    def __init__(
        self,
        lambda_client: "LambdaClient",
        scenario: str,
        runtime: str,
        handler: str,
        zip_file_path: str,
        role: str,
    ):
        self.function_names = []
        self.lambda_client = lambda_client
        self.scenario = scenario
        self.runtime = runtime
        self.handler = handler
        self.zip_file_path = zip_file_path
        self.role = role

    @overload
    def create_function(
        self,
        *,
        FunctionName: Optional[str] = None,
        Role: Optional[str] = None,
        Code: Optional["FunctionCodeTypeDef"] = None,
        Runtime: Optional["RuntimeType"] = None,
        Handler: Optional[str] = None,
        Description: Optional[str] = None,
        Timeout: Optional[int] = None,
        MemorySize: Optional[int] = None,
        Publish: Optional[bool] = None,
        VpcConfig: Optional["VpcConfigTypeDef"] = None,
        PackageType: Optional["PackageTypeType"] = None,
        DeadLetterConfig: Optional["DeadLetterConfigTypeDef"] = None,
        Environment: Optional["EnvironmentTypeDef"] = None,
        KMSKeyArn: Optional[str] = None,
        TracingConfig: Optional["TracingConfigTypeDef"] = None,
        Tags: Optional[Mapping[str, str]] = None,
        Layers: Optional[Sequence[str]] = None,
        FileSystemConfigs: Optional[Sequence["FileSystemConfigTypeDef"]] = None,
        ImageConfig: Optional["ImageConfigTypeDef"] = None,
        CodeSigningConfigArn: Optional[str] = None,
        Architectures: Optional[Sequence["ArchitectureType"]] = None,
        EphemeralStorage: Optional["EphemeralStorageTypeDef"] = None,
    ) -> "FunctionConfigurationResponseMetadataTypeDef":
        ...

    def create_function(self, **kwargs):
        kwargs.setdefault("FunctionName", f"{self.scenario}-{short_uid()}")
        kwargs.setdefault("Runtime", self.runtime)
        kwargs.setdefault("Handler", self.handler)
        kwargs.setdefault("Role", self.role)
        kwargs.setdefault("Code", {"ZipFile": load_file(self.zip_file_path, mode="rb")})

        def _create_function():
            return self.lambda_client.create_function(**kwargs)

        # @AWS, takes about 10s until the role/policy is "active", until then it will fail
        # localstack should normally not require the retries and will just continue here
        result = retry(_create_function, retries=3, sleep=4)
        self.function_names.append(result["FunctionArn"])
        self.lambda_client.get_waiter("function_active_v2").wait(
            FunctionName=kwargs.get("FunctionName")
        )

        return result

    def destroy(self):
        for function_name in self.function_names:
            try:
                self.lambda_client.delete_function(FunctionName=function_name)
            except Exception as e:
                LOG.debug("Error deleting function %s: %s", function_name, e)


def update_done(client, function_name):
    """wait fn for checking 'LastUpdateStatus' of lambda"""

    def _update_done():
        last_update_status = client.get_function_configuration(FunctionName=function_name)[
            "LastUpdateStatus"
        ]
        if last_update_status == "Failed":
            raise ShortCircuitWaitException(f"Lambda Config update failed: {last_update_status=}")
        else:
            return last_update_status == "Successful"

    return _update_done


def concurrency_update_done(client, function_name, qualifier):
    """wait fn for ProvisionedConcurrencyConfig 'Status'"""

    def _concurrency_update_done():
        status = client.get_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=qualifier
        )["Status"]
        if status == "FAILED":
            raise ShortCircuitWaitException(f"Concurrency update failed: {status=}")
        else:
            return status == "READY"

    return _concurrency_update_done


def get_invoke_init_type(
    client, function_name, qualifier
) -> Literal["on-demand", "provisioned-concurrency"]:
    """check the environment in the lambda for AWS_LAMBDA_INITIALIZATION_TYPE indicating ondemand/provisioned"""
    invoke_result = client.invoke(FunctionName=function_name, Qualifier=qualifier)
    return json.loads(to_str(invoke_result["Payload"].read()))


lambda_role = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
s3_lambda_permission = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:*",
                "dynamodb:DescribeStream",
                "dynamodb:GetRecords",
                "dynamodb:GetShardIterator",
                "dynamodb:ListStreams",
                "kinesis:DescribeStream",
                "kinesis:DescribeStreamSummary",
                "kinesis:GetRecords",
                "kinesis:GetShardIterator",
                "kinesis:ListShards",
                "kinesis:ListStreams",
                "kinesis:SubscribeToShard",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": ["*"],
        }
    ],
}


def _await_event_source_mapping_state(lambda_client, uuid, state, retries=30):
    def assert_mapping_disabled():
        assert lambda_client.get_event_source_mapping(UUID=uuid)["State"] == state

    retry(assert_mapping_disabled, sleep_before=2, retries=retries)


def _await_event_source_mapping_enabled(lambda_client, uuid, retries=30):
    return _await_event_source_mapping_state(
        lambda_client=lambda_client, uuid=uuid, retries=retries, state="Enabled"
    )


def _await_dynamodb_table_active(dynamodb_client, table_name, retries=6):
    def assert_table_active():
        assert (
            dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE"
        )

    retry(assert_table_active, retries=retries, sleep_before=2)


def _get_lambda_invocation_events(logs_client, function_name, expected_num_events, retries=30):
    def get_events():
        events = get_lambda_log_events(function_name, logs_client=logs_client)
        assert len(events) == expected_num_events
        return events

    return retry(get_events, retries=retries, sleep_before=2)


def is_old_local_executor() -> bool:
    """Returns True if running in local executor mode and False otherwise.
    The new provider ignores the LAMBDA_EXECUTOR flag and `not use_docker()` covers the fallback case if
    the Docker socket is not available.
    """
    return is_old_provider() and not use_docker()


def is_old_provider():
    return os.environ.get("TEST_TARGET") != "AWS_CLOUD" and os.environ.get(
        "PROVIDER_OVERRIDE_LAMBDA"
    ) in ["legacy", "v1"]


def is_new_provider():
    return os.environ.get("TEST_TARGET") != "AWS_CLOUD" and os.environ.get(
        "PROVIDER_OVERRIDE_LAMBDA"
    ) not in ["legacy", "v1"]
