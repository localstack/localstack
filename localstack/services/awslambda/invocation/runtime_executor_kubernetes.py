import copy
import logging
import os
import re
import shutil
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Literal, Optional, Tuple

from kubernetes import client as kubernetes_client
from kubernetes import config as kubernetes_config
from kubernetes import utils as kubernetes_utils

from localstack import config
from localstack.services.awslambda.invocation.executor_endpoint import (
    ExecutorEndpoint,
    ServiceEndpoint,
)
from localstack.services.awslambda.invocation.lambda_models import FunctionVersion
from localstack.services.awslambda.lambda_utils import get_main_endpoint_from_container
from localstack.services.install import LAMBDA_RUNTIME_INIT_PATH
from localstack.utils.archives import unzip
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

LAMBDA_POD_DEF = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": ""},
    "spec": {
        "containers": [
            {
                "image": "",
                "name": "lambda-container",
                "command": [RAPID_ENTRYPOINT],
                "ports": [{"containerPort": 0}],
            }
        ]
    },
}


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
    return f"{config.LAMBDA_KUBERNETES_IMAGE_PREFIX}:lambda-{function_version.id.qualified_arn().replace(':', '_').replace('$', '_').lower()}"


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
        image_name = get_image_name_for_function(function_version)
        CONTAINER_CLIENT.build_image(
            dockerfile_path=str(docker_file_path),
            image_name=image_name,
        )
        CONTAINER_CLIENT.push_image(image_name)
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


class LambdaRuntimeException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class KubernetesRuntimeExecutor:
    id: str
    function_version: FunctionVersion
    # address the container is available at (for LocalStack)
    address: Optional[str]
    executor_endpoint: Optional[ExecutorEndpoint]

    def __init__(
        self, id: str, function_version: FunctionVersion, service_endpoint: ServiceEndpoint
    ) -> None:
        self.id = id
        self.function_version = function_version
        self.address = None
        self.executor_endpoint = self._build_executor_endpoint(service_endpoint)

    @staticmethod
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
        prepare_image(target_path, function_version)
        LOG.debug("Version preparation took %0.2fms", (time.perf_counter() - time_before) * 1000)

    @staticmethod
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
        CONTAINER_CLIENT.remove_image(get_image_name_for_function(function_version))

    def get_image(self) -> str:
        if not self.function_version.config.runtime:
            raise NotImplementedError("Custom images are currently not supported")
        return get_image_name_for_function(self.function_version)

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

    def get_kubernetes_client(self):
        kubernetes_config.load_kube_config(
            config_file=os.path.join(config.dirs.config, "kube", "config")
        )
        return kubernetes_client.ApiClient()

    def start(self, env_vars: Dict[str, str]) -> None:
        self.executor_endpoint.start()
        # deep copy is not really necessary, but let's keep it to be safe
        pod_definition = copy.deepcopy(LAMBDA_POD_DEF)
        pod_definition["spec"]["containers"][0]["image"] = self.get_image()
        pod_definition["metadata"]["name"] = self.id

        # add environment variables
        pod_definition["spec"]["containers"][0]["env"] = [
            {"name": str(k), "value": str(v)} for k, v in env_vars.items()
        ]
        interop_port = get_free_tcp_port()
        pod_definition["spec"]["containers"][0]["env"].append(
            {"name": "LOCALSTACK_INTEROP_PORT", "value": str(interop_port)}
        )

        # address should be localhost then, port a random available port
        self.executor_endpoint.container_address = "localhost"
        self.executor_endpoint.invocation_port = interop_port

        pod_definition["spec"]["containers"][0]["ports"][0]["containerPort"] = interop_port

        # create the pod
        kubernetes_utils.create_from_dict(self.get_kubernetes_client(), pod_definition)
        # TODO proxy through kube https://github.com/kubernetes-client/python/blob/master/examples/pod_portforward.py

    def stop(self) -> None:
        api_client = self.get_kubernetes_client()
        core_v1_client = kubernetes_client.CoreV1Api(api_client)
        core_v1_client.delete_namespaced_pod(name=self.id, namespace="default")
        try:
            self.executor_endpoint.shutdown()
        except Exception as e:
            LOG.debug(
                "Error while stopping executor endpoint for lambda %s, error: %s",
                self.function_version.qualified_arn,
                e,
            )

    def get_address(self) -> str:
        if not self.address:
            raise LambdaRuntimeException(f"Address of executor '{self.id}' unknown")
        return self.address

    def get_executor_endpoint_from_executor(self) -> str:
        return f"{get_main_endpoint_from_container()}:{self.executor_endpoint.port}"

    def get_localstack_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def invoke(self, payload: Dict[str, str]):
        LOG.debug("Sending invoke-payload '%s' to executor '%s'", payload, self.id)
        self.executor_endpoint.invoke(payload)


class ExposeLSUtil:
    pass
