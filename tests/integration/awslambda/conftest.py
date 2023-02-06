import itertools
import logging
import os
import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Optional, Sequence, overload

import pytest
from _pytest.python import Metafunc

from localstack.aws.api.lambda_ import Runtime
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

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


RUNTIMES_AGGREGATED = {
    "python": [Runtime.python3_7, Runtime.python3_8, Runtime.python3_9],
    "nodejs": [Runtime.nodejs12_x, Runtime.nodejs14_x, Runtime.nodejs16_x, Runtime.nodejs18_x],
    "ruby": [Runtime.ruby2_7],
    "java": [Runtime.java8, Runtime.java8_al2, Runtime.java11],
    "dotnet": [
        Runtime.dotnetcore3_1,
        Runtime.dotnet6,
    ],
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


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "multiruntime: Multi runtime",
    )


def pytest_generate_tests(metafunc: Metafunc) -> Optional[object]:

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


def package_for_lang(scenario: str, runtime: str) -> str:
    """
    :param lang: which language
    :param path: directory to build
    :return: path to built zip file
    """
    runtime_folder = PACKAGE_FOR_RUNTIME[runtime]

    common_dir = (
        Path(os.path.dirname(__file__)) / "functions" / "common"
    )  # TODO: remove implicit relative location to this file
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


@pytest.fixture
def multiruntime_lambda(lambda_client, request, lambda_su_role) -> ParametrizedLambda:
    scenario, runtime, handler = request.param

    zip_file_path = package_for_lang(scenario=scenario, runtime=runtime)
    param_lambda = ParametrizedLambda(
        lambda_client=lambda_client,
        scenario=scenario,
        runtime=runtime,
        handler=handler,
        zip_file_path=zip_file_path,
        role=lambda_su_role,
    )

    yield param_lambda

    param_lambda.destroy()


@pytest.fixture
def dummylayer():
    with open(os.path.join(os.path.dirname(__file__), "./layers/testlayer.zip"), "rb") as fd:
        yield fd.read()
