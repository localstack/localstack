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
COPY code/ /var/task
COPY aws-lambda-rie {rapid_entrypoint}

ENTRYPOINT {rapid_entrypoint}
"""


# TODO provided runtimes
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


def get_image_name_for_function(function_version: "FunctionVersion"):
    return f"localstack/lambda-{function_version.qualified_arn.replace(':', '_').replace('$', '_').lower()}"


def get_image_for_runtime(runtime: str) -> str:
    # TODO a tad hacky, might cause problems in the future
    runtime, version = get_runtime_split(runtime)
    return f"{IMAGE_PREFIX}{runtime}:{version}"


def prepare_version(function_version: "FunctionVersion") -> None:
    time_before = time.perf_counter()
    src_init = Path(f"{config.dirs.tmp}/aws-lambda-rie")
    target_path = get_path_for_function(function_version)
    target_path.mkdir(parents=True, exist_ok=True)
    # copy init file
    target_init = target_path / "aws-lambda-rie"
    shutil.copy(src_init, target_init)
    target_init.chmod(0o755)
    # copy code
    target_code = target_path / "code"
    with NamedTemporaryFile() as file:
        file.write(function_version.zip_file)
        file.flush()
        unzip(file.name, target_code)
    # create dockerfile
    docker_file_path = target_path / "Dockerfile"
    docker_file = LAMBDA_DOCKERFILE.format(
        base_img=get_image_for_runtime(function_version.runtime),
        code_src=str(target_code),
        init_src=str(target_init),
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

    LOG.debug("Version preparation took %0.2fms", (time.perf_counter() - time_before) * 1000)


def cleanup_version(function_version: "FunctionVersion") -> None:
    CONTAINER_CLIENT.remove_image(get_image_name_for_function(function_version))


class LambdaRuntimeException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class RuntimeExecutor:
    id: str
    runtime: str
    ip: Optional[str]

    def __init__(self, id: str, runtime: str) -> None:
        self.id = id
        self.runtime = runtime
        self.ip = None

    def start(self, env_vars: Dict[str, str], function_version: "FunctionVersion") -> None:
        network = self.get_network_for_executor()
        container_config = ContainerConfiguration(
            image_name=get_image_name_for_function(function_version),
            name=self.id,
            env_vars=env_vars,
            network=network,
            entrypoint=RAPID_ENTRYPOINT,
        )
        CONTAINER_CLIENT.create_container_from_config(container_config)
        CONTAINER_CLIENT.start_container(self.id)
        self.ip = CONTAINER_CLIENT.get_container_ipv4_for_network(
            container_name_or_id=self.id, container_network=network
        )

    def stop(self) -> None:
        CONTAINER_CLIENT.stop_container(container_name=self.id, timeout=5)
        CONTAINER_CLIENT.remove_container(container_name=self.id)

    def get_address(self):
        if not self.ip:
            raise LambdaRuntimeException(f"IP address of executor '{self.id}' unknown")
        LOG.debug("LS endpoint: %s", self.ip)
        return self.ip

    def get_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def get_network_for_executor(self) -> str:
        return get_container_network_for_lambda()
