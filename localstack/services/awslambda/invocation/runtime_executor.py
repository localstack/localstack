import re
from typing import TYPE_CHECKING, Dict, Literal, Tuple

from localstack import config
from localstack.services.awslambda.lambda_utils import (
    get_container_network_for_lambda,
    get_main_endpoint_from_container,
)
from localstack.utils.common import short_uid
from localstack.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT
from localstack.utils.docker_utils import ContainerConfiguration

if TYPE_CHECKING:
    from localstack.services.awslambda.invocation.lambda_service import (
        FunctionVersion,
        LambdaRuntimeConfig,
    )

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


class RuntimeExecutor:
    id: str
    function_version: "FunctionVersion"
    runtime_config: "LambdaRuntimeConfig"
    initialization_type: str

    def __init__(
        self,
        function_version: "FunctionVersion",
        runtime_config: "LambdaRuntimeConfig",
        initialization_type: str,
    ) -> None:
        self.id = short_uid()
        self.function_version = function_version
        self.runtime_config = runtime_config
        self.initialization_type = initialization_type

    def get_image(self) -> str:
        # TODO a tad hacky, might cause problems in the future
        runtime, version = get_runtime_split(self.function_version.runtime)
        return f"{IMAGE_PREFIX}{runtime}:{version}"

    def get_environment_variables(self) -> Dict[str, str]:
        env_vars = {
            # Runtime API specifics
            "LOCALSTACK_RUNTIME_ID": self.id,
            "LAMBDA_FUNCTION_ARN": self.function_version.qualified_arn,
            "AWS_LAMBDA_RUNTIME_API": f"{self.get_endpoint_from_executor()}:{self.runtime_config.api_port}",
            "_HANDLER": self.function_version.handler,
            # General Lambda Environment Variables
            "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/",  # TODO correct value
            "AWS_LAMBDA_LOG_STREAM_NAME": "2022/13/32/...",  # TODO correct value
            "AWS_EXECUTION_ENV": f"Aws_Lambda_{self.function_version.runtime}",
            "AWS_LAMBDA_FUNCTION_NAME": self.function_version.qualified_arn,  # TODO use name instead of arn
            "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "128",  # TODO use correct memory size
            "AWS_LAMBDA_FUNCTION_VERSION": self.function_version.qualified_arn,  # TODO use name instead of arn
            "AWS_DEFAULT_REGION": self.function_version.qualified_arn,  # TODO use region instead of arn
            "AWS_REGION": self.function_version.qualified_arn,  # TODO use region instead of arn
            "TASK_ROOT": "/var/task",  # TODO custom runtimes?
            "RUNTIME_ROOT": "/var/runtime",  # TODO custom runtimes?
            "AWS_LAMBDA_INITIALIZATION_TYPE": self.initialization_type,
            "TZ": ":UTC",  # TODO does this have to match local system time? format?
            # Access IDs for role TODO make dependent on role arn
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_SESSION_TOKEN": "test",
            # TODO xray
            # LocalStack endpoint specifics
            "LOCALSTACK_HOSTNAME": self.get_endpoint_from_executor(),
            "EDGE_PORT": str(config.EDGE_PORT),
            "AWS_ENDPOINT_URL": f"http://{self.get_endpoint_from_executor()}:{config.EDGE_PORT}",
        }
        env_vars.update(self.function_version.environment)
        return env_vars

    def start(self) -> None:
        container_config = ContainerConfiguration(
            image_name=self.get_image(),
            name=self.id,
            env_vars=self.get_environment_variables(),
            network=self.get_network_for_executor(),
        )
        CONTAINER_CLIENT.create_container_from_config(container_config)
        CONTAINER_CLIENT.start_container(self.id)

    def stop(self) -> None:
        CONTAINER_CLIENT.stop_container(container_name=self.id, timeout=5)
        CONTAINER_CLIENT.remove_container(container_name=self.id)

    def get_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def get_network_for_executor(self) -> str:
        return get_container_network_for_lambda()
