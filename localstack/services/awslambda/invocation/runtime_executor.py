import logging
import re
import shutil
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Literal, Optional, Tuple

from localstack import config
from localstack.services.awslambda.invocation.executor_endpoint import (
    ExecutorEndpoint,
    ServiceEndpoint,
)
from localstack.services.awslambda.invocation.lambda_models import FunctionVersion
from localstack.services.awslambda.lambda_utils import (
    get_container_network_for_lambda,
    get_main_endpoint_from_container,
)
from localstack.services.install import LAMBDA_RUNTIME_INIT_PATH
from localstack.utils.archives import unzip
from localstack.utils.container_utils.container_client import ContainerConfiguration
from localstack.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT
from localstack.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)

RUNTIME_REGEX = r"(?P<runtime>[a-z]+)(?P<version>\d+(\.\d+)?(\.al2)?)(?:.*)"

# IMAGE_PREFIX = "gallery.ecr.aws/lambda/"
IMAGE_PREFIX = "amazon/aws-lambda-"

RAPID_ENTRYPOINT = "/var/rapid/init"

InitializationType = Literal["on-demand", "provisioned-concurrency"]

LAMBDA_DOCKERFILE = """FROM {base_img}
COPY aws-lambda-rie {rapid_entrypoint}
COPY code/ /var/task
"""


# TODO provided runtimes
# TODO a tad hacky, might cause problems in the future.. just use mapping?
def get_runtime_split(runtime: str) -> Tuple[str, str]:
    match = re.match(RUNTIME_REGEX, runtime)
    if match:
        runtime, version = match.group("runtime"), match.group("version")
        # sad exception for .net
        if runtime == "dotnetcore":
            runtime = "dotnet"
            version = f"core{version}"
        return runtime, version
    raise ValueError(f"Unknown/unsupported runtime '{runtime}'")


def get_path_for_function(function_version: FunctionVersion) -> Path:
    return Path(
        f"{config.dirs.tmp}/lambda/{function_version.id.qualified_arn().replace(':', '_').replace('$', '_')}/"
    )


def get_code_path_for_function(function_version: FunctionVersion) -> Path:
    return get_path_for_function(function_version) / "code"


def get_image_name_for_function(function_version: FunctionVersion) -> str:
    return f"localstack/lambda-{function_version.id.qualified_arn().replace(':', '_').replace('$', '_').lower()}"


def get_image_for_runtime(runtime: str) -> str:
    runtime, version = get_runtime_split(runtime)
    return f"{IMAGE_PREFIX}{runtime}:{version}"


def get_runtime_client_path() -> Path:
    return Path(LAMBDA_RUNTIME_INIT_PATH)


def prepare_image(target_path: Path, function_version: FunctionVersion) -> None:
    if not function_version.config.runtime:
        raise NotImplementedError("Custom images are currently not supported")
    src_init = get_runtime_client_path()
    # copy init file
    target_init = target_path / "aws-lambda-rie"
    shutil.copy(src_init, target_init)
    target_init.chmod(0o755)
    # copy code
    # create dockerfile
    docker_file_path = target_path / "Dockerfile"
    docker_file = LAMBDA_DOCKERFILE.format(
        base_img=get_image_for_runtime(function_version.config.runtime),
        rapid_entrypoint=RAPID_ENTRYPOINT,
    )
    with docker_file_path.open(mode="w") as f:
        f.write(docker_file)
    try:
        CONTAINER_CLIENT.build_image(
            dockerfile_path=str(docker_file_path),
            image_name=get_image_name_for_function(function_version),
        )
    except Exception as e:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.exception(
                "Error while building prebuilt lambda image for '%s'",
                function_version.qualified_arn,
            )
        else:
            LOG.error(
                "Error while building prebuilt lambda image for '%s', Error: %s",
                function_version.qualified_arn,
                e,
            )


def prepare_version(function_version: FunctionVersion) -> None:
    if not function_version.code.zip_file:
        raise NotImplementedError("Images without zipfile are currently not supported")
    time_before = time.perf_counter()
    target_path = get_path_for_function(function_version)
    target_path.mkdir(parents=True, exist_ok=True)
    # write code to disk
    target_code = get_code_path_for_function(function_version)
    with NamedTemporaryFile() as file:
        file.write(function_version.code.zip_file)
        file.flush()
        unzip(file.name, str(target_code))
    if config.LAMBDA_PREBUILD_IMAGES:
        prepare_image(target_path, function_version)
    LOG.debug("Version preparation took %0.2fms", (time.perf_counter() - time_before) * 1000)


def cleanup_version(function_version: FunctionVersion) -> None:
    function_path = get_path_for_function(function_version)
    try:
        shutil.rmtree(function_path)
    except OSError as e:
        LOG.debug(
            "Could not cleanup function %s due to error %s while deleting file %s",
            function_version.qualified_arn,
            e.strerror,
            e.filename,
        )
    if config.LAMBDA_PREBUILD_IMAGES:
        CONTAINER_CLIENT.remove_image(get_image_name_for_function(function_version))


class LambdaRuntimeException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class RuntimeExecutor:
    id: str
    function_version: FunctionVersion
    ip: Optional[str]
    executor_endpoint: Optional[ExecutorEndpoint]

    def __init__(
        self, id: str, function_version: FunctionVersion, service_endpoint: ServiceEndpoint
    ) -> None:
        self.id = id
        self.function_version = function_version
        self.ip = None
        self.executor_endpoint = self._build_executor_endpoint(service_endpoint)

    def get_image(self) -> str:
        if not self.function_version.config.runtime:
            raise NotImplementedError("Custom images are currently not supported")
        return (
            get_image_name_for_function(self.function_version)
            if config.LAMBDA_PREBUILD_IMAGES
            else get_image_for_runtime(self.function_version.config.runtime)
        )

    def _build_executor_endpoint(self, service_endpoint: ServiceEndpoint) -> ExecutorEndpoint:
        port = get_free_tcp_port()
        LOG.debug(
            "Creating service endpoint for function %s executor %s",
            self.function_version.qualified_arn,
            self.id,
        )
        executor_endpoint = ExecutorEndpoint(port, service_endpoint=service_endpoint)
        LOG.debug(
            "Finished creating service endpoint for function %s executor %s",
            self.function_version.qualified_arn,
            self.id,
        )
        return executor_endpoint

    def start(self, env_vars: Dict[str, str]) -> None:
        self.executor_endpoint.start()
        network = self.get_network_for_executor()
        container_config = ContainerConfiguration(
            image_name=self.get_image(),
            name=self.id,
            env_vars=env_vars,
            network=network,
            entrypoint=RAPID_ENTRYPOINT,
        )
        CONTAINER_CLIENT.create_container_from_config(container_config)
        if not config.LAMBDA_PREBUILD_IMAGES:
            CONTAINER_CLIENT.copy_into_container(
                self.id, str(get_runtime_client_path()), RAPID_ENTRYPOINT
            )
            CONTAINER_CLIENT.copy_into_container(
                self.id, f"{str(get_code_path_for_function(self.function_version))}/", "/var/task/"
            )

        CONTAINER_CLIENT.start_container(self.id)
        self.ip = CONTAINER_CLIENT.get_container_ipv4_for_network(
            container_name_or_id=self.id, container_network=network
        )
        self.executor_endpoint.container_address = self.ip

    def stop(self) -> None:
        CONTAINER_CLIENT.stop_container(container_name=self.id, timeout=5)
        CONTAINER_CLIENT.remove_container(container_name=self.id)
        try:
            self.executor_endpoint.shutdown()
        except Exception as e:
            LOG.debug(
                "Error while stopping executor endpoint for lambda %s, error: %s",
                self.function_version.qualified_arn,
                e,
            )

    def get_address(self) -> str:
        if not self.ip:
            raise LambdaRuntimeException(f"IP address of executor '{self.id}' unknown")
        return self.ip

    def get_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def get_network_for_executor(self) -> str:
        return get_container_network_for_lambda()

    def invoke(self, payload: Dict[str, str]):
        LOG.debug("Sending invoke-payload '%s' to executor '%s'", payload, self.id)
        self.executor_endpoint.invoke(payload)
