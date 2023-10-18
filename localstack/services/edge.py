import argparse
import gzip
import json
import logging
import re
import shlex
import subprocess
import sys
import threading
from typing import List, Optional, TypeVar
from urllib.parse import urlparse

from requests.models import Response

from localstack import config, constants
from localstack.aws.accounts import (
    get_account_id_from_access_key_id,
    set_aws_access_key_id,
    set_aws_account_id,
)
from localstack.aws.protocol.service_router import determine_aws_service_name
from localstack.config import HostAndPort
from localstack.constants import (
    HEADER_LOCALSTACK_ACCOUNT_ID,
    HEADER_LOCALSTACK_EDGE_URL,
    HEADER_LOCALSTACK_REQUEST_URL,
    LOCALHOST,
    LOCALHOST_IP,
    LOCALSTACK_ROOT_FOLDER,
    LS_LOG_TRACE_INTERNAL,
    TEST_AWS_ACCESS_KEY_ID,
)
from localstack.http import Router
from localstack.http.adapters import create_request_from_parts
from localstack.http.dispatcher import Handler, handler_dispatcher
from localstack.runtime import events
from localstack.services.generic_proxy import ProxyListener, modify_and_forward, start_proxy_server
from localstack.services.infra import PROXY_LISTENERS
from localstack.services.plugins import SERVICE_PLUGINS
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import (
    extract_access_key_id_from_auth_header,
    is_internal_call_context,
    set_default_region_in_headers,
)
from localstack.utils.collections import split_list_by
from localstack.utils.functions import empty_context_manager
from localstack.utils.http import parse_request_data
from localstack.utils.http import safe_requests as requests
from localstack.utils.net import get_free_tcp_port
from localstack.utils.run import is_root, run
from localstack.utils.server.http2_server import HTTPErrorResponse
from localstack.utils.server.proxy_server import start_tcp_proxy
from localstack.utils.strings import to_bytes, truncate
from localstack.utils.threads import FuncThread, start_thread

T = TypeVar("T")

LOG = logging.getLogger(__name__)

# Header to indicate that the process should kill itself. This is required because if
# this process is started as root, then we cannot kill it from a non-root process
HEADER_KILL_SIGNAL = "x-localstack-kill"

# Header to indicate the current API (service) being called
HEADER_TARGET_API = "x-localstack-tgt-api"

# lock obtained during boostrapping (persistence restoration) to avoid concurrency issues
BOOTSTRAP_LOCK = threading.RLock()

PORT_DNS = 53

GZIP_ENCODING = "GZIP"
IDENTITY_ENCODING = "IDENTITY"
S3 = "s3"
API_UNKNOWN = "_unknown_"
# APIs for which no gzip encoding should be applied when returning the response
HEADER_SKIP_RESPONSE_ZIPPING = "_skip_response_gzipping_"
SKIP_GZIP_APIS = [S3]
S3CONTROL_COMMON_PATH = "/v20180820/"


class ProxyListenerEdge(ProxyListener):
    def __init__(self, service_manager=None) -> None:
        super().__init__()
        self.service_manager = service_manager or SERVICE_PLUGINS

    def forward_request(self, method, path, data, headers):
        # kill the process if we receive this header
        headers.get(HEADER_KILL_SIGNAL) and sys.exit(0)

        if events.infra_stopping.is_set():
            return 503

        if config.EDGE_FORWARD_URL:
            return do_forward_request_network(
                0, method, path, data, headers, target_url=config.EDGE_FORWARD_URL
            )

        target = headers.get("x-amz-target", "")
        auth_header = get_auth_string(method, path, headers, data)
        if auth_header and not headers.get("authorization"):
            headers["authorization"] = auth_header
        host = headers.get("host", "")
        orig_req_url = headers.pop(HEADER_LOCALSTACK_REQUEST_URL, "")
        headers[HEADER_LOCALSTACK_EDGE_URL] = (
            re.sub(r"^([^:]+://[^/]+).*", r"\1", orig_req_url) or "http://%s" % host
        )

        # Obtain the access key ID and save it in the thread context
        access_key_id = extract_access_key_id_from_auth_header(headers) or TEST_AWS_ACCESS_KEY_ID
        set_aws_access_key_id(access_key_id)
        # Obtain the account ID
        account_id = get_account_id_from_access_key_id(access_key_id)
        # Save the same account ID in the thread context
        set_aws_account_id(account_id)
        # Make Moto use the same Account ID as LocalStack
        headers["x-moto-account-id"] = account_id

        # re-create an HTTP request from the given parts
        request = create_request_from_parts(method, path, data, headers)

        api = determine_aws_service_name(request)
        port = None
        if api:
            port = get_service_port_for_account(api, headers)

        set_default_region_in_headers(headers)

        should_log_trace = is_trace_logging_enabled(headers)
        if api and should_log_trace:
            # print request trace for debugging, if enabled
            LOG.debug(
                'IN(%s): "%s %s" - headers: %s - data: %s', api, method, path, dict(headers), data
            )

        if not port:
            if method == "OPTIONS":
                if api and should_log_trace:
                    # print request trace for debugging, if enabled
                    LOG.debug('IN(%s): "%s %s" - status: %s', api, method, path, 200)
                return 200

            if api in ["", None, API_UNKNOWN]:
                truncated = truncate(data)
                if auth_header or target or data or path not in ["/", "/favicon.ico"]:
                    LOG.info(
                        (
                            'Unable to find forwarding rule for host "%s", path "%s %s", '
                            'target header "%s", auth header "%s", data "%s"'
                        ),
                        host,
                        method,
                        path,
                        target,
                        auth_header,
                        truncated,
                    )
            else:
                LOG.info(
                    (
                        'Unable to determine forwarding port for API "%s" - please '
                        "make sure this API is enabled via the SERVICES configuration"
                    ),
                    api,
                )
            response = Response()
            response.status_code = 404
            response._content = '{"status": "running"}'
            return response

        if api and not headers.get("Authorization"):
            headers["Authorization"] = aws_stack.mock_aws_request_headers(api)["Authorization"]
        headers[HEADER_TARGET_API] = str(api)

        headers["Host"] = host
        if isinstance(data, dict):
            data = json.dumps(data)

        encoding_type = headers.get("Content-Encoding") or ""
        if encoding_type.upper() == GZIP_ENCODING.upper() and api not in SKIP_GZIP_APIS:
            headers["Content-Encoding"] = IDENTITY_ENCODING
            data = gzip.decompress(data)

        is_internal_call = is_internal_call_context(headers)

        self._require_service(api)

        lock_ctx = BOOTSTRAP_LOCK
        if is_internal_call or not config.is_persistence_enabled():
            lock_ctx = empty_context_manager()

        with lock_ctx:
            result = do_forward_request(api, method, path, data, headers, port=port)
            if should_log_trace and result not in [None, False, True]:
                result_status_code = getattr(result, "status_code", result)
                result_headers = getattr(result, "headers", {})
                result_content = getattr(result, "content", "")
                LOG.debug(
                    'OUT(%s): "%s %s" - status: %s - response headers: %s - response: %s',
                    api,
                    method,
                    path,
                    result_status_code,
                    dict(result_headers or {}),
                    result_content,
                )
            return result

    def return_response(self, method, path, data, headers, response):
        api = headers.get(HEADER_TARGET_API) or ""

        if is_trace_logging_enabled(headers):
            # print response trace for debugging, if enabled
            if api and api != API_UNKNOWN:
                LOG.debug(
                    'OUT(%s): "%s %s" - status: %s - response headers: %s - response: %s',
                    api,
                    method,
                    path,
                    response.status_code,
                    dict(response.headers),
                    response.content,
                )

        if (
            response._content
            and headers.get("Accept-Encoding") == "gzip"
            and api not in SKIP_GZIP_APIS
            and not response.headers.pop(HEADER_SKIP_RESPONSE_ZIPPING, None)
        ):
            # services may decide to set HEADER_SKIP_RESPONSE_ZIPPING in the response, to skip result transformations
            response._content = gzip.compress(to_bytes(response._content))
            response.headers["Content-Length"] = str(len(response._content))
            response.headers["Content-Encoding"] = "gzip"

    def _require_service(self, api):
        if not self.service_manager.exists(api):
            raise HTTPErrorResponse("no provider exists for service %s" % api, code=500)

        try:
            self.service_manager.require(api)
        except Exception as e:
            raise HTTPErrorResponse("failed to get service for %s: %s" % (api, e), code=500)


def do_forward_request(api, method, path, data, headers, port=None):
    if config.FORWARD_EDGE_INMEM:
        result = do_forward_request_inmem(api, method, path, data, headers, port=port)
    else:
        result = do_forward_request_network(port, method, path, data, headers)
    if hasattr(result, "status_code") and int(result.status_code) >= 400 and method == "OPTIONS":
        # fall back to successful response for OPTIONS requests
        return 200
    return result


def get_handler_for_api(api, headers):
    return PROXY_LISTENERS.get(api)


def do_forward_request_inmem(api, method, path, data, headers, port=None):
    listener_details = get_handler_for_api(api, headers)
    if not listener_details:
        message = f'Unable to find listener for service "{api}" - please make sure to include it in $SERVICES'
        LOG.warning(message)
        raise HTTPErrorResponse(message, code=400)
    service_name, backend_port, listener = listener_details
    # TODO determine client address..?
    client_address = LOCALHOST_IP
    server_address = headers.get("host") or LOCALHOST
    forward_url = f"http://{LOCALHOST}:{backend_port}"
    response = modify_and_forward(
        method=method,
        path=path,
        data_bytes=data,
        headers=headers,
        forward_base_url=forward_url,
        listeners=[listener],
        client_address=client_address,
        server_address=server_address,
    )
    return response


def do_forward_request_network(port, method, path, data, headers, target_url=None):
    # TODO: enable per-service endpoints, to allow deploying in distributed settings
    target_url = target_url or f"{config.get_protocol()}://{LOCALHOST}:{port}"
    url = f"{target_url}{path}"
    return requests.request(
        method,
        url,
        data=data,
        headers=headers,
        verify=False,
        stream=True,
        allow_redirects=False,
    )


def get_auth_string(method, path, headers, data=None):
    """
    Get Auth header from Header (this is how aws client's like boto typically
    provide it) or from query string or url encoded parameters sometimes
    happens with presigned requests. Always return to the Authorization Header
    form.

    Typically, an auth string comes in as a header:

        Authorization: AWS4-HMAC-SHA256 \
        Credential=_not_needed_locally_/20210312/us-east-1/sqs/aws4_request, \
        SignedHeaders=content-type;host;x-amz-date, \
        Signature=9277c941f4ecafcc0f290728e50cd7a3fa0e41763fbd2373fcdd3faf2dbddc2e

    Here's what Authorization looks like as part of an presigned GET request:

       &X-Amz-Algorithm=AWS4-HMAC-SHA256\
       &X-Amz-Credential=test%2F20210313%2Fus-east-1%2Fsqs%2Faws4_request\
       &X-Amz-Date=20210313T011059Z&X-Amz-Expires=86400000&X-Amz-SignedHeaders=host\
       &X-Amz-Signature=2c652c7bc9a3b75579db3d987d1e6dd056f0ac776c1e1d4ec91e2ce84e5ad3ae
    """

    if auth_header := headers.get("authorization", ""):
        return auth_header

    data_components = parse_request_data(method, path, data)
    algorithm = data_components.get("X-Amz-Algorithm")
    credential = data_components.get("X-Amz-Credential")
    signature = data_components.get("X-Amz-Signature")
    signed_headers = data_components.get("X-Amz-SignedHeaders")

    if algorithm and credential and signature and signed_headers:
        return (
            f"{algorithm} Credential={credential}, "
            + f"SignedHeaders={signed_headers}, "
            + f"Signature={signature}"
        )

    return ""


def get_service_port_for_account(service, headers):
    # assume we're only using a single account, hence return the static port mapping from config.py
    return config.service_port(service)


PROXY_LISTENER_EDGE = ProxyListenerEdge()

ROUTER: Router[Handler] = Router(dispatcher=handler_dispatcher())
"""This special Router is part of the edge proxy. Use the router to inject custom handlers that are handled before
the actual AWS service call is made."""


def is_trace_logging_enabled(headers) -> bool:
    if not config.LS_LOG:
        return False
    if config.LS_LOG == LS_LOG_TRACE_INTERNAL:
        return True
    return HEADER_LOCALSTACK_ACCOUNT_ID not in headers.keys()


def do_start_edge(
    listen: HostAndPort | List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    from localstack.aws.serving.edge import serve_gateway

    return serve_gateway(listen, use_ssl, asynchronous)


def do_start_edge_proxy(bind_address, port, use_ssl, asynchronous=False):
    from localstack.http.adapters import RouterListener
    from localstack.services.internal import LocalstackResourceHandler

    listeners = [
        LocalstackResourceHandler(),  # handle internal resources first
        RouterListener(ROUTER),  # then custom routes
        PROXY_LISTENER_EDGE,  # then call the edge proxy listener
    ]

    # get port and start Edge
    print("Starting edge router (http%s port %s)..." % ("s" if use_ssl else "", port))
    # use use_ssl=True here because our proxy allows both, HTTP and HTTPS traffic
    proxy = start_proxy_server(
        port,
        bind_address=bind_address,
        use_ssl=use_ssl,
        update_listener=listeners,
        check_port=False,
    )
    if not asynchronous:
        proxy.join()
    return proxy


def can_use_sudo():
    try:
        run("sudo -n -v", print_error=False)
        return True
    except Exception:
        return False


def ensure_can_use_sudo():
    if not is_root() and not can_use_sudo():
        if not sys.stdin.isatty():
            raise IOError("cannot get sudo password from non-tty input")
        print("Please enter your sudo password (required to configure local network):")
        run("sudo -v", stdin=True)


def start_component(
    component: str, listen_str: str | None = None, target_address: str | None = None
):
    if component == "edge":
        return start_edge(listen_str=listen_str)
    if component == "proxy":
        if target_address is None:
            raise ValueError("no target address specified")

        return start_proxy(
            listen_str=listen_str,
            target_address=HostAndPort.parse(
                target_address,
                default_host=config.default_ip,
                default_port=constants.DEFAULT_PORT_EDGE,
            ),
        )
    raise Exception("Unexpected component name '%s' received during start up" % component)


def start_proxy(
    listen_str: str, target_address: HostAndPort, asynchronous: bool = False
) -> FuncThread:
    """
    Starts a TCP proxy to perform a low-level forwarding of incoming requests.
    The proxy's source port (given as method argument) is bound to the EDGE_BIND_HOST.
    The target IP is always 127.0.0.1.
    The target port is parsed from the EDGE_FORWARD_URL (for compatibility with the legacy edge proxy forwarding).
    All other parts of the EDGE_FORWARD_URL are _not_ used any more.

    :param listen_str: address to listen on
    :param target_address: target address to proxy requests to
    :param asynchronous: False if the function should join the proxy thread and block until it terminates.
    :return: created thread executing the proxy
    """
    if config.EDGE_FORWARD_URL != "":
        destination_port = urlparse(config.EDGE_FORWARD_URL).port
        if not destination_port or destination_port < 1 or destination_port > 65535:
            raise ValueError("EDGE_FORWARD_URL does not contain a valid port.")

        listen = f"{constants.LOCALHOST_IP}:{destination_port}"
    else:
        listen_hosts = parse_gateway_listen(
            listen_str,
            default_host=constants.LOCALHOST_IP,
            default_port=constants.DEFAULT_PORT_EDGE,
        )
        listen = listen_hosts[0]
    return do_start_tcp_proxy(listen, target_address, asynchronous)


def do_start_tcp_proxy(
    listen: HostAndPort, target_address: HostAndPort, asynchronous: bool = False
) -> FuncThread:
    src = str(listen)
    dst = str(target_address)

    LOG.debug("Starting Local TCP Proxy: %s -> %s", src, dst)
    proxy = start_thread(
        lambda *args, **kwargs: start_tcp_proxy(src=src, dst=dst, handler=None, **kwargs),
        name="edge-tcp-proxy",
    )
    if not asynchronous:
        proxy.join()
    return proxy


def start_edge(listen_str: str, use_ssl: bool = True, asynchronous: bool = False):
    if listen_str:
        listen = parse_gateway_listen(
            listen_str, default_host=config.default_ip, default_port=constants.DEFAULT_PORT_EDGE
        )
    else:
        listen = config.GATEWAY_LISTEN

    if len(listen) == 0:
        raise ValueError("no listen addresses provided")

    # separate privileged and unprivileged addresses
    unprivileged, privileged = split_list_by(listen, lambda addr: addr.is_unprivileged() or False)

    # if we are root, we can directly bind to privileged ports as well
    if is_root():
        unprivileged = unprivileged + privileged
        privileged = []

    # check that we are actually started the gateway server
    if not unprivileged:
        unprivileged = parse_gateway_listen(
            f":{get_free_tcp_port()}",
            default_host=config.default_ip,
            default_port=constants.DEFAULT_PORT_EDGE,
        )

    # bind the gateway server to unprivileged addresses
    edge_thread = do_start_edge(unprivileged, use_ssl=use_ssl, asynchronous=True)

    # start TCP proxies for the remaining addresses
    proxy_destination = unprivileged[0]
    for address in privileged:
        # escalate to root
        args = [
            "proxy",
            "--gateway-listen",
            str(address),
            "--target-address",
            str(proxy_destination),
        ]
        run_module_as_sudo(
            module="localstack.services.edge",
            arguments=args,
            asynchronous=True,
        )

    if edge_thread is not None:
        edge_thread.join()


def run_module_as_sudo(
    module: str, arguments: Optional[List[str]] = None, asynchronous=False, env_vars=None
):
    # prepare environment
    env_vars = env_vars or {}
    env_vars["PYTHONPATH"] = f".:{LOCALSTACK_ROOT_FOLDER}"

    # start the process as sudo
    python_cmd = sys.executable
    cmd = ["sudo", "-n", "--preserve-env", python_cmd, "-m", module]
    arguments = arguments or []
    shell_cmd = shlex.join(cmd + arguments)

    # make sure we can run sudo commands
    try:
        ensure_can_use_sudo()
    except Exception as e:
        LOG.error("cannot run command as root (%s): %s ", str(e), shell_cmd)
        return

    def run_command(*_):
        run(shell_cmd, outfile=subprocess.PIPE, print_error=False, env_vars=env_vars)

    LOG.debug("Running command as sudo: %s", shell_cmd)
    result = (
        start_thread(run_command, quiet=True, name="sudo-edge") if asynchronous else run_command()
    )
    return result


def parse_gateway_listen(listen: str, default_host: str, default_port: int) -> List[HostAndPort]:
    addresses = []
    for address in listen.split(","):
        addresses.append(HostAndPort.parse(address, default_host, default_port))
    return addresses


if __name__ == "__main__":
    logging.basicConfig()
    parser = argparse.ArgumentParser()
    parser.add_argument("component")
    parser.add_argument("-l", "--gateway-listen", required=False, type=str)
    parser.add_argument("-t", "--target-address", required=False, type=str)
    args = parser.parse_args()

    start_component(args.component, args.gateway_listen, args.target_address)
