import logging
import re
import shutil
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, Dict, Literal, Optional, Tuple

from localstack import config
from localstack.services.awslambda.lambda_utils import (
    get_container_network_for_lambda,
    get_main_endpoint_from_container,
)
from localstack.utils.archives import unzip

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_service import FunctionVersion

from localstack.utils.container_utils.container_client import ContainerConfiguration
from localstack.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT

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
    raise Exception("Cannot process runtime '%s'" % runtime)


def get_path_for_function(function_version: "FunctionVersion") -> Path:
    return Path(
        f"{config.dirs.tmp}/lambda/{function_version.qualified_arn.replace(':', '_').replace('$', '_')}/"
    )


def get_code_path_for_function(function_version: "FunctionVersion") -> Path:
    return get_path_for_function(function_version) / "code"


def get_image_name_for_function(function_version: "FunctionVersion") -> str:
    return f"localstack/lambda-{function_version.qualified_arn.replace(':', '_').replace('$', '_').lower()}"


def get_image_for_runtime(runtime: str) -> str:
    runtime, version = get_runtime_split(runtime)
    return f"{IMAGE_PREFIX}{runtime}:{version}"


def get_runtime_client_path() -> Path:
    return Path(f"{config.dirs.tmp}/aws-lambda-rie")


def prepare_image(target_path: Path, function_version: "FunctionVersion") -> None:
    if not function_version.runtime:
        LOG.error("Images without runtime are currently not supported")
        raise Exception("Custom images are currently not supported")
    src_init = get_runtime_client_path()
    # copy init file
    target_init = target_path / "aws-lambda-rie"
    shutil.copy(src_init, target_init)
    target_init.chmod(0o755)
    # copy code
    # create dockerfile
    docker_file_path = target_path / "Dockerfile"
    docker_file = LAMBDA_DOCKERFILE.format(
        base_img=get_image_for_runtime(function_version.runtime),
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
        LOG.error("Exception: %s", e)


def prepare_version(function_version: "FunctionVersion") -> None:
    if not function_version.zip_file:
        LOG.error("Images without zip_file are currently not supported")
        raise Exception("Custom images are currently not supported")
    time_before = time.perf_counter()
    target_path = get_path_for_function(function_version)
    target_path.mkdir(parents=True, exist_ok=True)
    # write code to disk
    target_code = get_code_path_for_function(function_version)
    with NamedTemporaryFile() as file:
        file.write(function_version.zip_file)
        file.flush()
        unzip(file.name, str(target_code))
    if config.LAMBDA_PREBUILD_IMAGES:
        prepare_image(target_path, function_version)
    LOG.debug("Version preparation took %0.2fms", (time.perf_counter() - time_before) * 1000)


def cleanup_version(function_version: "FunctionVersion") -> None:
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
    function_version: "FunctionVersion"
    ip: Optional[str]

    def __init__(self, id: str, function_version: "FunctionVersion") -> None:
        self.id = id
        self.function_version = function_version
        self.ip = None

    def get_image(self) -> str:
        if not self.function_version.runtime:
            LOG.error("Images without runtime are currently not supported")
            raise Exception("Custom images are currently not supported")
        return (
            get_image_name_for_function(self.function_version)
            if config.LAMBDA_PREBUILD_IMAGES
            else get_image_for_runtime(self.function_version.runtime)
        )

    def start(self, env_vars: Dict[str, str]) -> None:
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

    def stop(self) -> None:
        CONTAINER_CLIENT.stop_container(container_name=self.id, timeout=5)
        CONTAINER_CLIENT.remove_container(container_name=self.id)

    def get_address(self) -> str:
        if not self.ip:
            raise LambdaRuntimeException(f"IP address of executor '{self.id}' unknown")
        LOG.debug("LS endpoint: %s", self.ip)
        return self.ip

    def get_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def get_network_for_executor(self) -> str:
        return get_container_network_for_lambda()
