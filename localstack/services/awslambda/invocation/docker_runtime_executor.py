import dataclasses
import json
import logging
import shutil
import time
from pathlib import Path
from typing import Callable, Dict, Literal, Optional

from localstack import config
from localstack.aws.api.lambda_ import PackageType, Runtime
from localstack.services.awslambda import hooks as lambda_hooks
from localstack.services.awslambda.invocation.executor_endpoint import (
    INVOCATION_PORT,
    ExecutorEndpoint,
    ServiceEndpoint,
)
from localstack.services.awslambda.invocation.lambda_models import IMAGE_MAPPING, FunctionVersion
from localstack.services.awslambda.invocation.runtime_executor import (
    LambdaRuntimeException,
    RuntimeExecutor,
)
from localstack.services.awslambda.lambda_utils import (
    get_container_network_for_lambda,
    get_main_endpoint_from_container,
)
from localstack.services.awslambda.packages import awslambda_runtime_package
from localstack.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeBind,
    VolumeMappings,
)
from localstack.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT
from localstack.utils.net import get_free_tcp_port
from localstack.utils.strings import truncate

LOG = logging.getLogger(__name__)

IMAGE_PREFIX = "public.ecr.aws/lambda/"
# IMAGE_PREFIX = "amazon/aws-lambda-"

RAPID_ENTRYPOINT = "/var/rapid/init"

InitializationType = Literal["on-demand", "provisioned-concurrency"]

LAMBDA_DOCKERFILE = """FROM {base_img}
COPY aws-lambda-rie {rapid_entrypoint}
COPY code/ /var/task
"""

PULLED_IMAGES: set[str] = set()

HOT_RELOADING_ENV_VARIABLE = "LOCALSTACK_HOT_RELOADING_PATHS"


def get_image_name_for_function(function_version: FunctionVersion) -> str:
    return f"localstack/lambda-{function_version.id.qualified_arn().replace(':', '_').replace('$', '_').lower()}"


def get_default_image_for_runtime(runtime: str) -> str:
    postfix = IMAGE_MAPPING.get(runtime)
    if not postfix:
        raise ValueError(f"Unsupported runtime {runtime}!")
    return f"{IMAGE_PREFIX}{postfix}"


class RuntimeImageResolver:
    """
    Resolves Lambda runtimes to corresponding docker images
    The default behavior resolves based on a prefix (including the repository) and a suffix (per runtime).

    This can be customized via the LAMBDA_RUNTIME_IMAGE_MAPPING config in 2 distinct ways:

    Option A: use a pattern string for the config variable that includes the "<runtime>" string
        e.g. "myrepo/lambda:<runtime>-custom" would resolve the runtime "python3.9" to "myrepo/lambda:python3.9-custom"

    Option B: use a JSON dict string for the config variable, mapping the runtime to the full image name & tag
        e.g. {"python3.9": "myrepo/lambda:python3.9-custom", "python3.8": "myotherrepo/pylambda:3.8"}

        Note that with Option B this will only apply to the runtimes included in the dict.
        All other (non-included) runtimes will fall back to the default behavior.
    """

    _mapping: dict[Runtime, str]
    _default_resolve_fn: Callable[[Runtime], str]

    def __init__(
        self, default_resolve_fn: Callable[[Runtime], str] = get_default_image_for_runtime
    ):
        self._mapping = dict()
        self._default_resolve_fn = default_resolve_fn

    def _resolve(self, runtime: Runtime, custom_image_mapping: str = "") -> str:
        if runtime not in IMAGE_MAPPING:
            raise ValueError(f"Unsupported runtime {runtime}")

        if not custom_image_mapping:
            return self._default_resolve_fn(runtime)

        # Option A (pattern string that includes <runtime> to replace)
        if "<runtime>" in custom_image_mapping:
            return custom_image_mapping.replace("<runtime>", runtime)

        # Option B (json dict mapping with fallback)
        try:
            mapping: dict = json.loads(custom_image_mapping)
            # at this point we're loading the whole dict to avoid parsing multiple times
            for k, v in mapping.items():
                if k not in IMAGE_MAPPING:
                    raise ValueError(
                        f"Unsupported runtime ({runtime}) provided in LAMBDA_RUNTIME_IMAGE_MAPPING"
                    )
                self._mapping[k] = v

            if runtime in self._mapping:
                return self._mapping[runtime]

            # fall back to default behavior if the runtime was not present in the custom config
            return self._default_resolve_fn(runtime)

        except Exception:
            LOG.error(
                f"Failed to load config from LAMBDA_RUNTIME_IMAGE_MAPPING={custom_image_mapping}"
            )
            raise  # TODO: validate config at start and prevent startup

    def get_image_for_runtime(self, runtime: Runtime) -> str:
        if runtime not in self._mapping:
            resolved_image = self._resolve(runtime, config.LAMBDA_RUNTIME_IMAGE_MAPPING)
            self._mapping[runtime] = resolved_image

        return self._mapping[runtime]


resolver = RuntimeImageResolver()


def get_runtime_client_path() -> Path:
    installer = awslambda_runtime_package.get_installer()
    installer.install()
    return Path(installer.get_executable_path())


def prepare_image(target_path: Path, function_version: FunctionVersion) -> None:
    if not function_version.config.runtime:
        raise NotImplementedError("Custom images are currently not supported")
    src_init = get_runtime_client_path()
    # copy init file
    target_init = awslambda_runtime_package.get_installer().get_executable_path()
    shutil.copy(src_init, target_init)
    target_init.chmod(0o755)
    # copy code
    # create dockerfile
    docker_file_path = target_path / "Dockerfile"
    docker_file = LAMBDA_DOCKERFILE.format(
        base_img=resolver.get_image_for_runtime(function_version.config.runtime),
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


@dataclasses.dataclass
class LambdaContainerConfiguration(ContainerConfiguration):
    copy_folders: list[tuple[str, str]] = dataclasses.field(default_factory=list)


class DockerRuntimeExecutor(RuntimeExecutor):
    ip: Optional[str]
    executor_endpoint: Optional[ExecutorEndpoint]

    def __init__(
        self, id: str, function_version: FunctionVersion, service_endpoint: ServiceEndpoint
    ) -> None:
        super(DockerRuntimeExecutor, self).__init__(
            id=id, function_version=function_version, service_endpoint=service_endpoint
        )
        self.ip = None
        self.executor_endpoint = self._build_executor_endpoint(service_endpoint)

    def get_image(self) -> str:
        if not self.function_version.config.runtime:
            raise NotImplementedError("Custom images are currently not supported")
        return (
            get_image_name_for_function(self.function_version)
            if config.LAMBDA_PREBUILD_IMAGES
            else resolver.get_image_for_runtime(self.function_version.config.runtime)
        )

    def _build_executor_endpoint(self, service_endpoint: ServiceEndpoint) -> ExecutorEndpoint:
        LOG.debug(
            "Creating service endpoint for function %s executor %s",
            self.function_version.qualified_arn,
            self.id,
        )
        executor_endpoint = ExecutorEndpoint(self.id, service_endpoint=service_endpoint)
        LOG.debug(
            "Finished creating service endpoint for function %s executor %s",
            self.function_version.qualified_arn,
            self.id,
        )
        return executor_endpoint

    def start(self, env_vars: dict[str, str]) -> None:
        self.executor_endpoint.start()
        network = self._get_network_for_executor()
        container_config = LambdaContainerConfiguration(
            image_name=None,
            name=self.id,
            env_vars=env_vars,
            network=network,
            entrypoint=RAPID_ENTRYPOINT,
            additional_flags=config.LAMBDA_DOCKER_FLAGS,
        )
        if self.function_version.config.package_type == PackageType.Zip:
            if self.function_version.config.code.is_hot_reloading():
                container_config.env_vars[HOT_RELOADING_ENV_VARIABLE] = "/var/task"
                if container_config.volumes is None:
                    container_config.volumes = VolumeMappings()
                container_config.volumes.append(
                    VolumeBind(
                        str(self.function_version.config.code.get_unzipped_code_location()),
                        "/var/task",
                        read_only=True,
                    )
                )
            else:
                container_config.copy_folders.append(
                    (
                        f"{str(self.function_version.config.code.get_unzipped_code_location())}/.",
                        "/var/task",
                    )
                )

        lambda_hooks.start_docker_executor.run(container_config, self.function_version)

        if not container_config.image_name:
            container_config.image_name = self.get_image()
        if config.LAMBDA_DEV_PORT_EXPOSE:
            self.executor_endpoint.container_port = get_free_tcp_port()
            if container_config.ports is None:
                container_config.ports = PortMappings()
            container_config.ports.add(self.executor_endpoint.container_port, INVOCATION_PORT)
        CONTAINER_CLIENT.create_container_from_config(container_config)
        if (
            not config.LAMBDA_PREBUILD_IMAGES
            or self.function_version.config.package_type != PackageType.Zip
        ):
            CONTAINER_CLIENT.copy_into_container(
                self.id, str(get_runtime_client_path()), RAPID_ENTRYPOINT
            )
        if not config.LAMBDA_PREBUILD_IMAGES:
            # copy_folders should be empty here if package type is not zip
            for source, target in container_config.copy_folders:
                CONTAINER_CLIENT.copy_into_container(self.id, source, target)

        CONTAINER_CLIENT.start_container(self.id)
        self.ip = CONTAINER_CLIENT.get_container_ipv4_for_network(
            container_name_or_id=self.id, container_network=network
        )
        if config.LAMBDA_DEV_PORT_EXPOSE:
            self.ip = "127.0.0.1"
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

    def _get_network_for_executor(self) -> str:
        return get_container_network_for_lambda()

    def invoke(self, payload: Dict[str, str]):
        LOG.debug(
            "Sending invoke-payload '%s' to executor '%s'",
            truncate(json.dumps(payload), config.LAMBDA_TRUNCATE_STDOUT),
            self.id,
        )
        self.executor_endpoint.invoke(payload)

    @classmethod
    def prepare_version(cls, function_version: FunctionVersion) -> None:
        time_before = time.perf_counter()
        lambda_hooks.prepare_docker_executor.run(function_version)
        if function_version.config.code:
            function_version.config.code.prepare_for_execution()
            image_name = resolver.get_image_for_runtime(function_version.config.runtime)
            if image_name not in PULLED_IMAGES:
                CONTAINER_CLIENT.pull_image(image_name)
                PULLED_IMAGES.add(image_name)
            if config.LAMBDA_PREBUILD_IMAGES:
                target_path = function_version.config.code.get_unzipped_code_location()
                prepare_image(target_path, function_version)
            LOG.debug(
                "Version preparation of version %s took %0.2fms",
                function_version.qualified_arn,
                (time.perf_counter() - time_before) * 1000,
            )

    @classmethod
    def cleanup_version(cls, function_version: FunctionVersion) -> None:
        if config.LAMBDA_PREBUILD_IMAGES:
            CONTAINER_CLIENT.remove_image(get_image_name_for_function(function_version))

    def get_runtime_endpoint(self) -> str:
        return f"http://{self.get_endpoint_from_executor()}:{config.EDGE_PORT}{self.executor_endpoint.get_endpoint_prefix()}"
