import re
from typing import Dict, Literal, Optional, Tuple

from localstack.services.awslambda.lambda_utils import (
    get_container_network_for_lambda,
    get_main_endpoint_from_container,
)
from localstack.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT
from localstack.utils.docker_utils import ContainerConfiguration

RUNTIME_REGEX = r"(?P<runtime>[a-z]+)(?P<version>\d+(\.\d+)?(\.al2)?)(?:.*)"

IMAGE_PREFIX = "gallery.ecr.aws/lambda/"

InitializationType = Literal["on-demand", "provisioned-concurrency"]


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

    def get_image(self) -> str:
        # TODO a tad hacky, might cause problems in the future
        runtime, version = get_runtime_split(self.runtime)
        return f"{IMAGE_PREFIX}{runtime}:{version}"

    def start(self, env_vars: Dict[str, str]) -> None:
        network = self.get_network_for_executor()
        container_config = ContainerConfiguration(
            image_name=self.get_image(),
            name=self.id,
            env_vars=env_vars,
            network=network,
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
        return self.ip

    def get_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def get_network_for_executor(self) -> str:
        return get_container_network_for_lambda()
