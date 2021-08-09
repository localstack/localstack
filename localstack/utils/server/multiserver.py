import json
import logging
import subprocess
import sys

import requests
from flask_cors import CORS
from moto import server as moto_server
from requests.models import Response

from localstack import config as localstack_config
from localstack import constants
from localstack.services.generic_proxy import ProxyListener, start_proxy_server
from localstack.utils.bootstrap import setup_logging
from localstack.utils.common import (
    TMP_THREADS,
    ShellCommandThread,
    get_free_tcp_port,
    is_port_open,
    json_safe,
    to_str,
    wait_for_port_open,
)
from localstack.utils.run import FuncThread

LOG = logging.getLogger("localstack.multiserver")

# maps API names to server details
API_SERVERS = {}

# network port for multiserver instance (lazily initialized on startup)
MULTI_SERVER_PORT = None

# network port for moto server instance (lazily initialized on startup)
MOTO_SERVER_PORT = None

# API paths
API_PATH_SERVERS = "/servers"

# whether to start the multiserver in a separate process
RUN_SERVER_IN_PROCESS = False


def patch_moto_server():
    def create_backend_app(service):
        if not service:
            LOG.warning('Unable to create moto backend app for empty service: "%s"' % service)
            return None
        backend_app = create_backend_app_orig(service)
        CORS(backend_app)
        return backend_app

    create_backend_app_orig = moto_server.create_backend_app
    moto_server.create_backend_app = create_backend_app


def start_api_server_locally(request):

    if localstack_config.FORWARD_EDGE_INMEM:
        if "__started__" in API_SERVERS:
            return
        API_SERVERS["__started__"] = True

    api = request.get("api")
    port = request.get("port")
    if api in API_SERVERS:
        return API_SERVERS[api]
    result = API_SERVERS[api] = {}

    def thread_func(params):
        if localstack_config.FORWARD_EDGE_INMEM:
            return moto_server.main(["-p", str(port), "-H", constants.BIND_HOST])
        return moto_server.main([api, "-p", str(port), "-H", constants.BIND_HOST])

    thread = FuncThread(thread_func)
    thread.start()
    TMP_THREADS.append(thread)
    result["port"] = port
    result["thread"] = thread
    return result


def start_server(port, asynchronous=False):

    if is_port_open(port):
        LOG.debug("API Multiserver appears to be already running.")
        return

    class ConfigListener(ProxyListener):
        def forward_request(self, method, path, data, **kwargs):
            response = Response()
            response.status_code = 200
            response._content = "{}"
            try:
                if path == API_PATH_SERVERS:
                    if method == "POST":
                        start_api_server_locally(json.loads(to_str(data)))
                    elif method == "GET":
                        response._content = json.dumps(json_safe(API_SERVERS))
            except Exception as e:
                LOG.error("Unable to process request: %s" % e)
                response.status_code = 500
                response._content = str(e)
            return response

    proxy = start_proxy_server(port, update_listener=ConfigListener())
    if asynchronous:
        return proxy
    proxy.join()


def start_api_server(api, port, server_port=None):
    server_port = server_port or get_multi_server_port()
    thread = start_server_process(server_port)
    url = "http://localhost:%s%s" % (server_port, API_PATH_SERVERS)
    if localstack_config.FORWARD_EDGE_INMEM:
        port = get_moto_server_port()
    payload = {"api": api, "port": port}
    result = requests.post(url, json=payload)
    if result.status_code >= 400:
        raise Exception(
            "Unable to start API in multi server (%s): %s" % (result.status_code, result.content)
        )
    return thread


def start_server_process(port):
    if "__server__" in API_SERVERS:
        return API_SERVERS["__server__"]["thread"]
    port = port or get_multi_server_port()
    API_SERVERS["__server__"] = config = {"port": port}
    LOG.info("Starting multi API server process on port %s" % port)
    if RUN_SERVER_IN_PROCESS:
        cmd = '"%s" "%s" %s' % (sys.executable, __file__, port)
        env_vars = {"PYTHONPATH": ".:%s" % constants.LOCALSTACK_ROOT_FOLDER}
        thread = ShellCommandThread(
            cmd, outfile=subprocess.PIPE, env_vars=env_vars, inherit_cwd=True
        )
        thread.start()
    else:
        thread = start_server(port, asynchronous=True)

    TMP_THREADS.append(thread)
    config["thread"] = thread
    wait_for_port_open(port, retries=20, sleep_time=1)
    return thread


def get_multi_server_port():
    global MULTI_SERVER_PORT
    MULTI_SERVER_PORT = MULTI_SERVER_PORT or get_free_tcp_port()
    return MULTI_SERVER_PORT


def get_moto_server_port():
    global MOTO_SERVER_PORT
    MOTO_SERVER_PORT = MOTO_SERVER_PORT or get_free_tcp_port()
    return MOTO_SERVER_PORT


def main():
    setup_logging()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else get_multi_server_port()
    start_server(port)


patch_moto_server()


if __name__ == "__main__":
    main()
