"""Module for localstack internal resources, such as health, graph, or _localstack/cloudformation/deploy. """
import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import List

import requests
from werkzeug.exceptions import NotFound

from localstack import config, constants
from localstack.deprecations import deprecated_endpoint
from localstack.http import Request, Resource, Response, Router
from localstack.http.dispatcher import handler_dispatcher
from localstack.services.infra import exit_infra, signal_supervisor_restart
from localstack.utils.analytics.metadata import (
    get_client_metadata,
    get_localstack_edition,
    is_license_activated,
)
from localstack.utils.collections import merge_recursive
from localstack.utils.config_listener import update_config_variable
from localstack.utils.files import load_file
from localstack.utils.functions import call_safe
from localstack.utils.json import parse_json_or_yaml
from localstack.utils.numbers import is_number
from localstack.utils.objects import singleton_factory
from localstack.utils.server.http2_server import HTTP_METHODS

LOG = logging.getLogger(__name__)


class DeprecatedResource:
    """
    Resource class which wraps a given resource in the deprecated_endpoint (i.e. logs deprecation warnings on every
    invocation).
    """

    def __init__(self, resource, previous_path: str, deprecation_version: str, new_path: str):
        for http_method in HTTP_METHODS:
            fn_name = f"on_{http_method.lower()}"
            fn = getattr(resource, fn_name, None)
            if fn:
                wrapped = deprecated_endpoint(
                    fn,
                    previous_path=previous_path,
                    deprecation_version=deprecation_version,
                    new_path=new_path,
                )
                setattr(self, fn_name, wrapped)


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

    def on_post(self, request: Request):
        data = request.get_json(True, True)
        if not data:
            return Response("invalid request", 400)

        # backdoor API to support restarting the instance
        if data.get("action") == "restart":
            signal_supervisor_restart()
        elif data.get("action") == "kill":
            exit_infra(0)

        return Response("ok", 200)

    def on_get(self, request: Request):
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
        result["edition"] = get_localstack_edition()
        result["version"] = constants.VERSION
        return result

    def on_head(self, request: Request):
        return Response("ok", 200)

    def on_put(self, request: Request):
        data = request.get_json(True, True) or {}

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


class InfoResource:
    """
    Resource that is exposed to /_localstack/info and used to get generalized information about the current
    localstack instance.
    """

    def on_get(self, request):
        return self.get_info_data()

    @staticmethod
    def get_info_data() -> dict:
        client_metadata = get_client_metadata()
        uptime = int(time.time() - config.load_start_time)

        return {
            "version": client_metadata.version,
            "edition": get_localstack_edition() or "unknown",
            "is_license_activated": is_license_activated(),
            "session_id": client_metadata.session_id,
            "machine_id": client_metadata.machine_id,
            "system": client_metadata.system,
            "is_docker": client_metadata.is_docker,
            "server_time_utc": datetime.utcnow().isoformat(timespec="seconds"),
            "uptime": uptime,
        }


class CloudFormationUi:
    def on_get(self, request):
        from localstack.utils.aws.aws_stack import get_valid_regions

        deploy_html_file = os.path.join(
            constants.MODULE_MAIN_PATH, "services", "cloudformation", "deploy.html"
        )
        deploy_html = load_file(deploy_html_file)
        req_params = request.values
        params = {
            "stackName": "stack1",
            "templateBody": "{}",
            "errorMessage": "''",
            "regions": json.dumps(sorted(list(get_valid_regions()))),
        }

        download_url = req_params.get("templateURL")
        if download_url:
            try:
                LOG.debug("Attempting to download CloudFormation template URL: %s", download_url)
                template_body = requests.get(download_url).text
                template_body = parse_json_or_yaml(template_body)
                params["templateBody"] = json.dumps(template_body)
            except Exception as e:
                msg = f"Unable to download CloudFormation template URL: {e}"
                LOG.info(msg)
                params["errorMessage"] = json.dumps(msg.replace("\n", " - "))

        # using simple string replacement here, for simplicity (could be replaced with, e.g., jinja)
        for key, value in params.items():
            deploy_html = deploy_html.replace(f"<{key}>", value)

        return Response(deploy_html, mimetype="text/html")


class UsageResource:
    def on_get(self, request):
        from localstack.utils import diagnose

        return call_safe(diagnose.get_usage) or {}


class DiagnoseResource:
    def on_get(self, request):
        from localstack.utils import diagnose

        return {
            "version": {
                "image-version": call_safe(diagnose.get_docker_image_details),
                "localstack-version": call_safe(diagnose.get_localstack_version),
                "host": {
                    "kernel": call_safe(diagnose.get_host_kernel_version),
                },
            },
            "info": call_safe(InfoResource.get_info_data),
            "services": call_safe(diagnose.get_service_stats),
            "config": call_safe(diagnose.get_localstack_config),
            "docker-inspect": call_safe(diagnose.inspect_main_container),
            "docker-dependent-image-hashes": call_safe(diagnose.get_important_image_hashes),
            "file-tree": call_safe(diagnose.get_file_tree),
            "important-endpoints": call_safe(diagnose.resolve_endpoints),
            "logs": call_safe(diagnose.get_localstack_logs),
            "usage": call_safe(diagnose.get_usage),
        }


class PluginsResource:
    """
    Resource to list information about plux plugins.
    """

    def on_get(self, request):
        from plugin import PluginManager

        from localstack.runtime import hooks
        from localstack.services.plugins import SERVICE_PLUGINS

        plugin_managers: List[PluginManager] = [
            SERVICE_PLUGINS.plugin_manager,
            hooks.configure_localstack_container.manager,
            hooks.prepare_host.manager,
            hooks.on_infra_ready.manager,
            hooks.on_infra_start.manager,
            hooks.on_infra_shutdown.manager,
        ]

        def get_plugin_details(_manager: PluginManager, _name: str):
            container = _manager.get_container(_name)

            details = {
                "name": _name,
                "is_initialized": container.is_init,
                "is_loaded": container.is_loaded,
            }

            return details

        return {
            manager.namespace: [get_plugin_details(manager, name) for name in manager.list_names()]
            for manager in plugin_managers
        }


class InitScriptsResource:
    def on_get(self, request):
        from localstack.runtime.init import init_script_manager

        manager = init_script_manager()

        return {
            "completed": {
                stage.name: completed for stage, completed in manager.stage_completed.items()
            },
            "scripts": [
                {
                    "stage": script.stage.name,
                    "name": os.path.basename(script.path),
                    "state": script.state.name,
                }
                for scripts in manager.scripts.values()
                for script in scripts
            ],
        }


class InitScriptsStageResource:
    def on_get(self, request, stage: str):
        from localstack.runtime.init import Stage, init_script_manager

        manager = init_script_manager()

        try:
            stage = Stage[stage.upper()]
        except KeyError as e:
            raise NotFound(f"no such stage {stage}") from e

        return {
            "completed": manager.stage_completed.get(stage),
            "scripts": [
                {
                    "stage": script.stage.name,
                    "name": os.path.basename(script.path),
                    "state": script.state.name,
                }
                for script in manager.scripts.get(stage)
            ],
        }


class ConfigResource:
    def on_get(self, request):
        from localstack.utils import diagnose

        return call_safe(diagnose.get_localstack_config)

    def on_post(self, request: Request):
        data = request.get_json(force=True)
        variable = data.get("variable", "")
        if not re.match(r"^[_a-zA-Z0-9]+$", variable):
            return Response("{}", mimetype="application/json", status=400)
        new_value = data.get("value")
        if is_number(new_value):
            new_value = float(new_value)
        update_config_variable(variable, new_value)
        value = getattr(config, variable, None)
        return {
            "variable": variable,
            "value": value,
        }


class LocalstackResources(Router):
    """
    Router for localstack-internal HTTP resources.
    """

    def __init__(self):
        super().__init__(dispatcher=handler_dispatcher())
        self.add_default_routes()
        # TODO: load routes as plugins

    def add_default_routes(self):
        from localstack.services.plugins import SERVICE_PLUGINS

        health_resource = HealthResource(SERVICE_PLUGINS)
        self.add(Resource("/_localstack/health", health_resource))
        self.add(Resource("/_localstack/info", InfoResource()))
        self.add(Resource("/_localstack/plugins", PluginsResource()))
        self.add(Resource("/_localstack/init", InitScriptsResource()))
        self.add(Resource("/_localstack/init/<stage>", InitScriptsStageResource()))
        self.add(Resource("/_localstack/cloudformation/deploy", CloudFormationUi()))

        if config.ENABLE_CONFIG_UPDATES:
            LOG.warning(
                "Enabling config endpoint, "
                "please be aware that this can expose sensitive information via your network."
            )
            self.add(Resource("/_localstack/config", ConfigResource()))

        if config.DEBUG:
            LOG.warning(
                "Enabling diagnose endpoint, "
                "please be aware that this can expose sensitive information via your network."
            )
            self.add(Resource("/_localstack/diagnose", DiagnoseResource()))
            self.add(Resource("/_localstack/usage", UsageResource()))


@singleton_factory
def get_internal_apis() -> LocalstackResources:
    """
    Get the LocalstackResources singleton.
    """
    return LocalstackResources()
