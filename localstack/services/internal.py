"""Module for localstack internal resources, such as health, graph, or _localstack/cloudformation/deploy. """
import inspect
import json
import logging
import os
import socket
from collections import defaultdict
from typing import Any, Dict, Optional

import requests
from werkzeug.exceptions import NotFound

from localstack import config, constants
from localstack.http import Router
from localstack.http.adapters import RouterListener
from localstack.http.dispatcher import resource_dispatcher
from localstack.services.infra import terminate_all_processes_in_docker
from localstack.utils import bootstrap
from localstack.utils.common import (
    load_file,
    merge_recursive,
    parse_json_or_yaml,
    parse_request_data,
    to_str,
)
from localstack.utils.container_utils.container_client import NoSuchImage
from localstack.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

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


class HealthResource:
    """
    Resource for the LocalStack /health endpoint. It provides access to the service states and other components of
    localstack. We support arbitrary data to be put into the health state to support things like the
    run_startup_scripts function in docker-entrypoint.sh which sets the status of the init scripts feature.
    """

    def __init__(self, service_manager) -> None:
        super().__init__()
        self.service_manager = service_manager
        self.state = {}

    def on_post(self, request):
        data = request.json()
        # backdoor API to support restarting the instance
        if data.get("action") in ["kill", "restart"]:
            terminate_all_processes_in_docker()

    def on_get(self, request):
        path = request.path

        reload = "reload" in path

        # get service state
        if reload:
            self.service_manager.check_all()
        services = {
            service: state.value for service, state in self.service_manager.get_states().items()
        }

        # build state dict from internal state and merge into it the service states
        result = dict(self.state)
        result = merge_recursive({"services": services}, result)
        result["version"] = constants.VERSION
        return result

    def on_put(self, request):
        data = json.loads(to_str(request.data or "{}"))

        # keys like "features:initScripts" should be interpreted as ['features']['initScripts']
        state = defaultdict(dict)
        for k, v in data.items():
            if ":" in k:
                path = k.split(":")
            else:
                path = [k]

            d = state
            for p in path[:-1]:
                d = state[p]
            d[path[-1]] = v

        self.state = merge_recursive(state, self.state, overwrite=True)
        return {"status": "OK"}


class ResourceGraph:
    """
    Serves the resource graph for app.localstack.cloud.
    """

    def on_post(self, request):
        return self.serve_resource_graph(request.json())

    def serve_resource_graph(self, data: Dict[str, Any]) -> Dict[str, Any]:
        from localstack.dashboard import infra as dashboard_infra
        from localstack.utils.aws.aws_stack import Environment

        if not data.get("awsEnvironment"):
            raise ValueError("cannot parse aws Environment from empty string")

        env = Environment.from_string(data.get("awsEnvironment"))
        graph = dashboard_infra.get_graph(
            name_filter=data.get("nameFilter") or ".*",
            env=env,
            region=data.get("awsRegion"),
        )
        return graph


class CloudFormationUi:
    def on_get(self, request):

        path = request.path
        data = request.data
        headers = request.headers

        deploy_html_file = os.path.join(
            constants.MODULE_MAIN_PATH, "services", "cloudformation", "deploy.html"
        )
        deploy_html = load_file(deploy_html_file)
        req_params = parse_request_data("GET", path, data, headers)
        params = {
            "stackName": "stack1",
            "templateBody": "{}",
            "errorMessage": "''",
            "regions": json.dumps(sorted(list(config.VALID_REGIONS))),
        }

        download_url = req_params.get("templateURL")
        if download_url:
            try:
                LOG.debug("Attempting to download CloudFormation template URL: %s", download_url)
                template_body = to_str(requests.get(download_url).content)
                template_body = parse_json_or_yaml(template_body)
                params["templateBody"] = json.dumps(template_body)
            except Exception as e:
                msg = f"Unable to download CloudFormation template URL: {e}"
                LOG.info(msg)
                params["errorMessage"] = json.dumps(msg.replace("\n", " - "))

        # using simple string replacement here, for simplicity (could be replaced with, e.g., jinja)
        for key, value in params.items():
            deploy_html = deploy_html.replace(f"<{key}>", value)
        return deploy_html


class DiagnoseResource:
    def on_get(self, request):
        # localstack status
        #  - version
        #  - ..

        # service health
        health = requests.get(f"http://localhost:{config.get_edge_port_http()}/health").json()

        # config
        config_doc = self.collect_config()

        # logs

        # docker information
        #  - docker inspect <container> output

        # file tree
        #  - /var/lib/localstack
        #  - /tmp

        # resolve a few dns records
        #  - localhost.localstack.cloud -> 127.0.0.1
        #  - api.localstack.cloud -> aws apigw

        return {
            "version": {},
            "host": {
                "version": load_file("/proc/version", "failed"),
            },
            "health": health,
            "config": config_doc,
            "logs": {},
            "docker-inspect": self.inspect_main_container(),
            "docker-dependent-image-hashes": self.get_important_image_hashes(),
            "file-tree": {
                "/var/lib/localstack": [],
                "/tmp": [],
            },
            "important-endpoints": self.resolve_endpoints(),
        }

    @staticmethod
    def collect_config():
        exclude_keys = {
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

        result = {}
        for k, v in inspect.getmembers(config):
            if k in exclude_keys:
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

    @staticmethod
    def inspect_main_container():
        try:
            return DOCKER_CLIENT.inspect_container(bootstrap.get_main_container_name())
        except Exception as e:
            return f"inspect failed: {e}"

    @staticmethod
    def resolve_endpoints():
        endpoint_list = ["localhost.localstack.cloud", "api.localstack.cloud"]
        result = {}
        for endpoint in endpoint_list:
            try:
                resolved_endpoint = socket.gethostbyname(endpoint)
            except Exception as e:
                resolved_endpoint = f"unable_to_resolve {e}"
            result[endpoint] = resolved_endpoint
        return result

    @staticmethod
    def get_important_image_hashes():
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


class LocalstackResources(Router):
    """
    Router for localstack-internal HTTP resources.
    """

    def __init__(self):
        super().__init__(dispatcher=resource_dispatcher(pass_response=False))
        self.add_default_routes()
        # TODO: load routes as plugins

    def add_default_routes(self):
        from localstack.services.plugins import SERVICE_PLUGINS

        health_resource = HealthResource(SERVICE_PLUGINS)
        graph_resource = ResourceGraph()

        # two special routes for legacy support (before `/_localstack` was introduced)
        super().add("/health", health_resource)
        super().add("/graph", graph_resource)

        self.add("/health", health_resource)
        self.add("/graph", graph_resource)
        self.add("/cloudformation/deploy", CloudFormationUi())
        self.add("/diagnose", DiagnoseResource())

    def add(self, path, *args, **kwargs):
        super().add(f"{constants.INTERNAL_RESOURCE_PATH}{path}", *args, **kwargs)


class LocalstackResourceHandler(RouterListener):
    """
    Adapter to serve LocalstackResources through the edge proxy.
    """

    resources: LocalstackResources

    def __init__(self, resources: LocalstackResources = None) -> None:
        super().__init__(resources or LocalstackResources(), fall_through=False)

    def forward_request(self, method, path, data, headers):
        try:
            return super().forward_request(method, path, data, headers)
        except NotFound:
            if not path.startswith(constants.INTERNAL_RESOURCE_PATH + "/"):
                # only return 404 if we're accessing an internal resource, otherwise fall back to the other listeners
                return True
            else:
                LOG.warning("Unable to find handler for path: %s", path)
                return 404


INTERNAL_APIS: Optional[LocalstackResources] = None


def get_internal_apis() -> LocalstackResources:
    """
    Get the LocalstackResources singleton.
    """
    global INTERNAL_APIS
    if not INTERNAL_APIS:
        INTERNAL_APIS = LocalstackResources()
    return INTERNAL_APIS
