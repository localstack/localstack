import gzip
import json
import logging
import os
import re
import subprocess
import sys
import threading
from typing import Dict, Optional

from requests.models import Response

from localstack import config
from localstack.constants import (
    HEADER_LOCALSTACK_EDGE_URL,
    HEADER_LOCALSTACK_REQUEST_URL,
    INTERNAL_AWS_ACCESS_KEY_ID,
    LOCALHOST,
    LOCALHOST_IP,
    LOCALSTACK_ROOT_FOLDER,
    LS_LOG_TRACE_INTERNAL,
    PATH_USER_REQUEST,
)
from localstack.http import Router
from localstack.http.dispatcher import Handler, handler_dispatcher
from localstack.services.generic_proxy import ProxyListener, modify_and_forward, start_proxy_server
from localstack.services.infra import PROXY_LISTENERS
from localstack.services.plugins import SERVICE_PLUGINS
from localstack.services.s3.s3_utils import uses_host_addressing
from localstack.services.sqs.sqs_listener import is_sqs_queue_url
from localstack.utils import common, persistence
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import is_internal_call_context, set_default_region_in_headers
from localstack.utils.aws.request_routing import extract_version_and_action, matches_service_action
from localstack.utils.common import (
    TMP_THREADS,
    empty_context_manager,
    get_service_protocol,
    is_port_open,
    is_root,
    parse_request_data,
    run,
)
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import sleep_forever, start_thread, to_bytes, to_str, truncate
from localstack.utils.server.http2_server import HTTPErrorResponse

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


class ProxyListenerEdge(ProxyListener):
    def __init__(self, service_manager=None) -> None:
        super().__init__()
        self.service_manager = service_manager or SERVICE_PLUGINS

    def forward_request(self, method, path, data, headers):

        if common.INFRA_STOPPED:
            return 503

        if config.EDGE_FORWARD_URL:
            return do_forward_request_network(
                0, method, path, data, headers, target_url=config.EDGE_FORWARD_URL
            )

        # kill the process if we receive this header
        headers.get(HEADER_KILL_SIGNAL) and sys.exit(0)

        target = headers.get("x-amz-target", "")
        auth_header = get_auth_string(method, path, headers, data)
        if auth_header and not headers.get("authorization"):
            headers["authorization"] = auth_header
        host = headers.get("host", "")
        orig_req_url = headers.pop(HEADER_LOCALSTACK_REQUEST_URL, "")
        headers[HEADER_LOCALSTACK_EDGE_URL] = (
            re.sub(r"^([^:]+://[^/]+).*", r"\1", orig_req_url) or "http://%s" % host
        )

        # extract API details
        api, port, path, host = get_api_from_headers(headers, method=method, path=path, data=data)

        set_default_region_in_headers(headers)

        if port and int(port) < 0:
            return 404

        if not port:
            api, port = get_api_from_custom_rules(method, path, data, headers) or (
                api,
                port,
            )

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
            headers.set("Content-Encoding", IDENTITY_ENCODING)
            data = gzip.decompress(data)

        is_internal_call = is_internal_call_context(headers)

        self._require_service(api)

        lock_ctx = BOOTSTRAP_LOCK
        if is_internal_call or persistence.is_persistence_restored():
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
    forward_url = "http://%s:%s" % (LOCALHOST, backend_port)
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
    target_url = target_url or "%s://%s:%s" % (get_service_protocol(), LOCALHOST, port)
    url = "%s%s" % (target_url, path)
    response = requests.request(
        method, url, data=data, headers=headers, verify=False, stream=True, allow_redirects=False
    )
    return response


def get_auth_string(method, path, headers, data=None):
    """
    Get Auth header from Header (this is how aws client's like boto typically
    provide it) or from query string or url encoded parameters (sometimes
    happens with presigned requests. Always return in the Authorization Header
    form.

    Typically an auth string comes in as a header:

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

    auth_header = headers.get("authorization", "")

    if auth_header:
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


# TODO: refactor this function -> returning the port is redundant (given the returned service name)
def get_api_from_headers(headers, method=None, path=None, data=None):
    """Determine API and backend port based on "Authorization" or "Host" headers."""

    # initialize result
    result = API_UNKNOWN, 0

    target = headers.get("x-amz-target", "")
    host = headers.get("host", "")
    auth_header = headers.get("authorization", "")

    if not auth_header and not target and "." not in host:
        return result[0], result[1], path, host

    path = path or "/"

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    try:
        service = extract_service_name_from_auth_header(headers)
        assert service
        result = service, get_service_port_for_account(service, headers)
    except Exception:
        pass

    result_before = result

    # Fallback rules and route customizations applied below
    if host.endswith("cloudfront.net"):
        path = path or "/"
        result = "cloudfront", config.service_port("cloudfront")
    elif target.startswith("AWSCognitoIdentityProviderService") or "cognito-idp." in host:
        result = "cognito-idp", config.service_port("cognito-idp")
    elif target.startswith("AWSCognitoIdentityService") or "cognito-identity." in host:
        result = "cognito-identity", config.service_port("cognito-identity")
    elif result[0] == "s3" or uses_host_addressing(headers):
        result = "s3", config.service_port("s3")
    elif result[0] == "states" in auth_header or host.startswith("states."):
        result = "stepfunctions", config.service_port("stepfunctions")
    elif "route53." in host:
        result = "route53", config.service_port("route53")
    elif result[0] == "monitoring":
        result = "cloudwatch", config.service_port("cloudwatch")
    elif result[0] == "email":
        result = "ses", config.service_port("ses")
    elif result[0] == "execute-api" or ".execute-api." in host:
        result = "apigateway", config.service_port("apigateway")
    elif target.startswith("Firehose_"):
        result = "firehose", config.service_port("firehose")
    elif target.startswith("DynamoDB_"):
        result = "dynamodb", config.service_port("dynamodb")
    elif target.startswith("DynamoDBStreams") or host.startswith("streams.dynamodb."):
        # Note: DDB streams requests use ../dynamodb/.. auth header, hence we also need to update result_before
        result = result_before = "dynamodbstreams", config.service_port("dynamodbstreams")
    elif result[0] == "EventBridge" or target.startswith("AWSEvents"):
        result = "events", config.service_port("events")
    elif target.startswith("ResourceGroupsTaggingAPI_"):
        result = "resourcegroupstaggingapi", config.service_port("resourcegroupstaggingapi")
    elif result[0] == "resource-groups":
        result = "resource-groups", config.service_port("resource-groups")
    elif result[0] == "es" and path is not None and not path.startswith("/2015-01-01/"):
        # For OpenSearch, the auth header points to the API ("es").
        # However, if the path does _not_ start with /2015-01-01 (the API version path prefix for the only ES API
        # version) it is a request to the opensearch API.
        result = "opensearch", config.service_port("opensearch")

    return result[0], result_before[1] or result[1], path, host


def extract_service_name_from_auth_header(headers: Dict) -> Optional[str]:
    try:
        auth_header = headers.get("authorization", "")
        credential_scope = auth_header.split(",")[0].split()[1]
        _, _, _, service, _ = credential_scope.split("/")
        return service
    except Exception:
        return


def is_s3_form_data(data_bytes):
    if to_bytes("key=") in data_bytes:
        return True
    if (
        to_bytes("Content-Disposition: form-data") in data_bytes
        and to_bytes('name="key"') in data_bytes
    ):
        return True
    return False


# TODO: refactor this function -> returning the port is redundant (given the returned service name)
def get_api_from_custom_rules(method, path, data, headers):
    """Determine backend port based on custom rules."""

    # API Gateway invocation URLs
    if ("/%s/" % PATH_USER_REQUEST) in path:
        return "apigateway", config.service_port("apigateway")

    # detect S3 presigned URLs
    if "AWSAccessKeyId=" in path or "Signature=" in path:
        return "s3", config.service_port("s3")

    # heuristic for SQS queue URLs
    if is_sqs_queue_url(path):
        return "sqs", config.service_port("sqs")

    # DynamoDB shell URLs
    if path.startswith("/shell") or path.startswith("/dynamodb/shell"):
        return "dynamodb", config.service_port("dynamodb")

    data_bytes = to_bytes(data or "")
    version, action = extract_version_and_action(path, data_bytes)

    def _in_path_or_payload(search_str):
        return to_str(search_str) in path or to_bytes(search_str) in data_bytes

    if path == "/" and b"QueueName=" in data_bytes:
        return "sqs", config.service_port("sqs")

    if "Action=ConfirmSubscription" in path:
        return "sns", config.service_port("sns")

    if path.startswith("/2015-03-31/functions/"):
        return "lambda", config.service_port("lambda")

    if _in_path_or_payload("Action=AssumeRoleWithWebIdentity"):
        return "sts", config.service_port("sts")

    if _in_path_or_payload("Action=AssumeRoleWithSAML"):
        return "sts", config.service_port("sts")

    if _in_path_or_payload("Action=AssumeRole"):
        return "sts", config.service_port("sts")

    # SQS queue requests
    if _in_path_or_payload("QueueUrl=") and _in_path_or_payload("Action="):
        return "sqs", config.service_port("sqs")
    if matches_service_action("sqs", action, version=version):
        return "sqs", config.service_port("sqs")

    # SNS topic requests
    if matches_service_action("sns", action, version=version):
        return "sns", config.service_port("sns")

    # TODO: move S3 public URLs to a separate port/endpoint, OR check ACLs here first
    stripped = path.strip("/")
    if method in ["GET", "HEAD"] and stripped:
        # assume that this is an S3 GET request with URL path `/<bucket>/<key ...>`
        return "s3", config.service_port("s3")

    # detect S3 URLs
    if stripped and "/" not in stripped:
        if method == "PUT":
            # assume that this is an S3 PUT bucket request with URL path `/<bucket>`
            return "s3", config.service_port("s3")
        if method == "POST" and is_s3_form_data(data_bytes):
            # assume that this is an S3 POST request with form parameters or multipart form in the body
            return "s3", config.service_port("s3")

    # detect S3 requests sent from aws-cli using --no-sign-request option
    if "aws-cli/" in headers.get("User-Agent", ""):
        return "s3", config.service_port("s3")

    # S3 delete object requests
    if (
        method == "POST"
        and "delete=" in path
        and b"<Delete" in data_bytes
        and b"<Key>" in data_bytes
    ):
        return "s3", config.service_port("s3")

    # Put Object API can have multiple keys
    if stripped.count("/") >= 1 and method == "PUT":
        # assume that this is an S3 PUT bucket object request with URL path `/<bucket>/object`
        # or `/<bucket>/object/object1/+`
        return "s3", config.service_port("s3")

    auth_header = headers.get("Authorization") or ""

    # detect S3 requests with "AWS id:key" Auth headers
    if auth_header.startswith("AWS "):
        return "s3", config.service_port("s3")

    # certain EC2 requests from Java SDK contain no Auth headers (issue #3805)
    if b"Version=2016-11-15" in data_bytes:
        return "ec2", config.service_port("ec2")


def get_service_port_for_account(service, headers):
    # assume we're only using a single account, hence return the static port mapping from config.py
    return config.service_port(service)


PROXY_LISTENER_EDGE = ProxyListenerEdge()
# the ROUTER is part of the edge proxy. use the router to inject custom handlers that are handled before actual
# service calls
ROUTER: Router[Handler] = Router(dispatcher=handler_dispatcher())


def is_trace_logging_enabled(headers):
    if not config.LS_LOG:
        return False
    if config.LS_LOG == LS_LOG_TRACE_INTERNAL:
        return True
    auth_header = headers.get("Authorization") or ""
    return INTERNAL_AWS_ACCESS_KEY_ID not in auth_header


def do_start_edge(bind_address, port, use_ssl, asynchronous=False):
    from localstack.http.adapters import RouterListener
    from localstack.services.internal import LocalstackResourceHandler

    start_dns_server(asynchronous=True)

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
        use_ssl=True,
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


def start_component(component: str, port=None, use_ssl=True, asynchronous=False):
    if component == "edge":
        return start_edge(port=port, use_ssl=use_ssl, asynchronous=asynchronous)
    if component == "dns":
        return start_dns_server(asynchronous=asynchronous)
    raise Exception("Unexpected component name '%s' received during start up" % component)


def start_dns_server(asynchronous=False):
    try:
        # start local DNS server, if present
        from localstack_ext import config as config_ext
        from localstack_ext.services import dns_server

        if config_ext.DNS_ADDRESS in config.FALSE_STRINGS:
            return

        if is_port_open(PORT_DNS):
            return

        if is_root():
            result = dns_server.start_servers()
            if not asynchronous:
                sleep_forever()
            return result

        env_vars = {}
        for env_var in config.CONFIG_ENV_VARS:
            if env_var.startswith("DNS_"):
                value = os.environ.get(env_var, None)
                if value is not None:
                    env_vars[env_var] = value

        # note: running in a separate process breaks integration with Route53 (to be fixed for local dev mode!)
        return run_process_as_sudo("dns", PORT_DNS, asynchronous=asynchronous, env_vars=env_vars)
    except Exception:
        pass


def start_edge(port=None, use_ssl=True, asynchronous=False):
    if not port:
        port = config.EDGE_PORT
    if config.EDGE_PORT_HTTP and config.EDGE_PORT_HTTP != port:
        do_start_edge(
            config.EDGE_BIND_HOST,
            config.EDGE_PORT_HTTP,
            use_ssl=False,
            asynchronous=True,
        )
    if port > 1024 or is_root():
        return do_start_edge(config.EDGE_BIND_HOST, port, use_ssl, asynchronous=asynchronous)

    # process requires privileged port but we're not root -> try running as sudo

    class Terminator(object):
        def stop(self, quiet=True):
            try:
                url = "http%s://%s:%s" % ("s" if use_ssl else "", LOCALHOST, port)
                requests.verify_ssl = False
                requests.post(url, headers={HEADER_KILL_SIGNAL: "kill"})
            except Exception:
                pass

    # register a signal handler to terminate the sudo process later on
    TMP_THREADS.append(Terminator())

    return run_process_as_sudo("edge", port, asynchronous=asynchronous)


def run_process_as_sudo(component, port, asynchronous=False, env_vars=None):
    # make sure we can run sudo commands
    try:
        ensure_can_use_sudo()
    except Exception as e:
        LOG.error("cannot start service on privileged port %s: %s", port, str(e))
        return

    # prepare environment
    env_vars = env_vars or {}
    env_vars["PYTHONPATH"] = f".:{LOCALSTACK_ROOT_FOLDER}"
    env_vars["EDGE_FORWARD_URL"] = config.get_edge_url()
    env_vars["EDGE_BIND_HOST"] = config.EDGE_BIND_HOST
    env_vars_str = env_vars_to_string(env_vars)

    # start the process as sudo
    sudo_cmd = "sudo -n"
    python_cmd = sys.executable
    cmd = [
        sudo_cmd,
        env_vars_str,
        python_cmd,
        "-m",
        "localstack.services.edge",
        component,
        str(port),
    ]
    shell_cmd = " ".join(cmd)

    def run_command(*_):
        run(shell_cmd, outfile=subprocess.PIPE, print_error=False, env_vars=env_vars)

    LOG.debug("Running command as sudo: %s", shell_cmd)
    result = start_thread(run_command, quiet=True) if asynchronous else run_command()
    return result


def env_vars_to_string(env_vars: Dict) -> str:
    return " ".join(f"{k}='{v}'" for k, v in env_vars.items())


if __name__ == "__main__":
    logging.basicConfig()
    start_component(sys.argv[1], int(sys.argv[2]))
