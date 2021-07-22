import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from localstack import config
from localstack.utils.bootstrap import canonicalize_api_names
from localstack.utils.common import clone

# set up logger
LOG = logging.getLogger(__name__)

# map of service plugins, mapping from service name to plugin details
SERVICE_PLUGINS = {}

# maps service names to health status
STATUSES = {}


# -----------------
# PLUGIN UTILITIES
# -----------------


class Plugin(object):
    def __init__(self, name, start, check=None, listener=None, priority=0, active=False):
        self.plugin_name = name
        self.start_function = start
        self.listener = listener
        self.check_function = check
        self.priority = priority
        self.default_active = active

    def start(self, asynchronous):
        kwargs = {"asynchronous": asynchronous}
        if self.listener:
            kwargs["update_listener"] = self.listener
        return self.start_function(**kwargs)

    def check(self, expect_shutdown=False, print_error=False):
        if not self.check_function:
            return
        return self.check_function(expect_shutdown=expect_shutdown, print_error=print_error)

    def name(self):
        return self.plugin_name

    def is_enabled(self, api_names=None):
        if self.default_active:
            return True
        if api_names is None:
            api_names = canonicalize_api_names()
        return self.name() in api_names


def register_plugin(plugin):
    existing = SERVICE_PLUGINS.get(plugin.name())
    if existing:
        if existing.priority > plugin.priority:
            return
    SERVICE_PLUGINS[plugin.name()] = plugin


# -------------------------
# HEALTH CHECK API METHODS
# -------------------------


def get_services_health(reload=False):
    if reload:
        reload_services_health()
    result = clone(dict(STATUSES))
    result.get("services", {}).pop("edge", None)
    return result


def set_services_health(data):
    status = STATUSES["services"] = STATUSES.get("services", {})
    for key, value in dict(data).items():
        parent, _, child = key.partition(":")
        if child:
            STATUSES[parent] = STATUSES.get(parent, {})
            STATUSES[parent][child] = value
            data.pop(key)
    status.update(data or {})
    return get_services_health()


# -----------------------------
# INFRASTRUCTURE HEALTH CHECKS
# -----------------------------


def check_infra(retries=10, expect_shutdown=False, apis=None, additional_checks=[]):
    try:
        apis = apis or canonicalize_api_names()
        print_error = retries <= 0

        # loop through plugins and check service status
        for name, plugin in SERVICE_PLUGINS.items():
            if name in apis:
                check_service_health(
                    api=name, print_error=print_error, expect_shutdown=expect_shutdown
                )

        for additional in additional_checks:
            additional(expect_shutdown=expect_shutdown)
    except Exception as e:
        if retries <= 0:
            LOG.exception("Error checking state of local environment (after some retries)")
            raise e
        time.sleep(3)
        check_infra(
            retries - 1,
            expect_shutdown=expect_shutdown,
            apis=apis,
            additional_checks=additional_checks,
        )


def wait_for_infra_shutdown(apis=None):
    apis = apis or canonicalize_api_names()

    names = [name for name, plugin in SERVICE_PLUGINS.items() if name in apis]

    def check(name):
        check_service_health(api=name, expect_shutdown=True)
        LOG.debug("[shutdown] api %s has shut down", name)

    # no special significance to 10 workers, seems like a reasonable number given the number of services we have
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check, names)


def check_service_health(api, print_error=False, expect_shutdown=False):
    try:
        plugin = SERVICE_PLUGINS.get(api)
        plugin.check(expect_shutdown=expect_shutdown, print_error=print_error)
        record_service_health(api, "running")
    except Exception as e:
        if not expect_shutdown:
            LOG.warning('Service "%s" not yet available, retrying...' % api)
        else:
            LOG.warning('Service "%s" still shutting down, retrying...' % api)
        raise e


def reload_services_health():
    check_infra(retries=0)


def record_service_health(api, status):
    # TODO: consider making in-memory calls here, to optimize performance
    data = {api: status}
    health_url = "%s/health" % config.get_edge_url()
    try:
        requests.put(health_url, data=json.dumps(data), verify=False)
    except Exception:
        # ignore for now, if the service is not running
        pass
