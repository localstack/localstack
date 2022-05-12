"""Diagnostic tool for a localstack instance running in a container."""
import inspect
import os
import socket
from typing import Dict, List, Union

from localstack import config
from localstack.utils import bootstrap
from localstack.utils.container_networking import get_main_container_name
from localstack.utils.container_utils.container_client import NoSuchImage
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import load_file

DIAGNOSE_IMAGES = [
    "localstack/lambda:provided",
    "localstack/lambda:ruby2.7",
    "localstack/lambda:ruby2.5",
    "localstack/lambda:nodejs14.x",
    "localstack/lambda:nodejs12.x",
    "localstack/lambda:nodejs10.x",
    "localstack/lambda:nodejs8.10",
    "localstack/lambda:nodejs6.10",
    "localstack/lambda:nodejs4.3",
    "localstack/lambda:java8",
    "localstack/lambda:java11",
    "localstack/lambda:go1.x",
    "localstack/lambda:dotnetcore3.1",
    "localstack/lambda:dotnetcore2.1",
    "localstack/lambda:dotnetcore2.0",
    "localstack/lambda:python2.7",
    "localstack/lambda:python3.6",
    "localstack/lambda:python3.7",
    "localstack/lambda:python3.8",
    "localstack/bigdata",
    "lambci/lambda:provided",
    "lambci/lambda:ruby2.7",
    "lambci/lambda:ruby2.5",
    "lambci/lambda:nodejs14.x",
    "lambci/lambda:nodejs12.x",
    "lambci/lambda:nodejs10.x",
    "lambci/lambda:nodejs8.10",
    "lambci/lambda:nodejs6.10",
    "lambci/lambda:nodejs4.3",
    "lambci/lambda:java8",
    "lambci/lambda:java11",
    "lambci/lambda:go1.x",
    "lambci/lambda:dotnetcore3.1",
    "lambci/lambda:dotnetcore2.1",
    "lambci/lambda:dotnetcore2.0",
    "lambci/lambda:python2.7",
    "lambci/lambda:python3.6",
    "lambci/lambda:python3.7",
    "lambci/lambda:python3.8",
    "mongo",
]

EXCLUDE_CONFIG_KEYS = {
    "CONFIG_ENV_VARS",
    "DEFAULT_SERVICE_PORTS",
    "copyright",
    "__builtins__",
    "__cached__",
    "__doc__",
    "__file__",
    "__loader__",
    "__name__",
    "__package__",
    "__spec__",
}
ENDPOINT_RESOLVE_LIST = ["localhost.localstack.cloud", "api.localstack.cloud"]
INSPECT_DIRECTORIES = ["/var/lib/localstack", "/tmp"]


def get_localstack_logs() -> Union[str, Dict]:
    try:
        result = DOCKER_CLIENT.get_container_logs(get_main_container_name())
    except Exception as e:
        result = "error getting docker logs for container: %s" % e

    return {"docker": result}


def get_localstack_config() -> Dict:
    result = {}
    for k, v in inspect.getmembers(config):
        if k in EXCLUDE_CONFIG_KEYS:
            continue
        if inspect.isbuiltin(v):
            continue
        if inspect.isfunction(v):
            continue
        if inspect.ismodule(v):
            continue
        if inspect.isclass(v):
            continue
        if "typing." in str(type(v)):
            continue

        if hasattr(v, "__dict__"):
            result[k] = v.__dict__
        else:
            result[k] = v

    return result


def inspect_main_container() -> Union[str, Dict]:
    try:
        return DOCKER_CLIENT.inspect_container(get_main_container_name())
    except Exception as e:
        return f"inspect failed: {e}"


def get_localstack_version() -> Dict[str, str]:
    return {
        "build-date": os.environ.get("LOCALSTACK_BUILD_DATE"),
        "build-git-hash": os.environ.get("LOCALSTACK_BUILD_GIT_HASH"),
        "build-version": os.environ.get("LOCALSTACK_BUILD_VERSION"),
    }


def resolve_endpoints() -> Dict[str, str]:
    result = {}
    for endpoint in ENDPOINT_RESOLVE_LIST:
        try:
            resolved_endpoint = socket.gethostbyname(endpoint)
        except Exception as e:
            resolved_endpoint = f"unable_to_resolve {e}"
        result[endpoint] = resolved_endpoint
    return result


def get_important_image_hashes() -> Dict[str, str]:
    result = {}
    for image in DIAGNOSE_IMAGES:
        try:
            image_version = DOCKER_CLIENT.inspect_image(image, pull=False)["RepoDigests"]
        except NoSuchImage:
            image_version = "not_present"
        except Exception as e:
            image_version = f"error: {e}"
        result[image] = image_version
    return result


def get_service_stats() -> Dict[str, str]:
    from localstack.services.plugins import SERVICE_PLUGINS

    return {service: state.value for service, state in SERVICE_PLUGINS.get_states().items()}


def get_file_tree() -> Dict[str, List[str]]:
    return {d: traverse_file_tree(d) for d in INSPECT_DIRECTORIES}


def traverse_file_tree(root: str) -> List[str]:
    try:
        result = []
        if config.in_docker():
            for root, _, _ in os.walk(root):
                result.append(root)
        return result
    except Exception as e:
        return ["traversing files failed %s" % e]


def get_docker_image_details() -> Dict[str, str]:
    return bootstrap.get_docker_image_details()


def get_host_kernel_version() -> str:
    return load_file("/proc/version", "failed").strip()
