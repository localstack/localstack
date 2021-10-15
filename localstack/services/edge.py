import gzip
import json
import logging
import os
import re
import signal
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
from localstack.dashboard import infra as dashboard_infra
from localstack.services import plugins
from localstack.services.cloudwatch.cloudwatch_listener import PATH_GET_RAW_METRICS
from localstack.services.generic_proxy import ProxyListener, modify_and_forward, start_proxy_server
from localstack.services.infra import PROXY_LISTENERS
from localstack.services.plugins import SERVICE_PLUGINS
from localstack.services.s3.s3_utils import uses_host_addressing
from localstack.services.sqs.sqs_listener import is_sqs_queue_url
from localstack.utils import persistence
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import (
    Environment,
    is_internal_call_context,
    set_default_region_in_headers,
)
from localstack.utils.aws.request_routing import extract_version_and_action, matches_service_action
from localstack.utils.common import (
    TMP_THREADS,
    empty_context_manager,
    get_service_protocol,
    in_docker,
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


class ProxyListenerEdge(ProxyListener):
    def __init__(self, service_manager=None) -> None:
        super().__init__()
        self.service_manager = service_manager or SERVICE_PLUGINS

    def forward_request(self, method, path, data, headers):

        if config.EDGE_FORWARD_URL:
            return do_forward_request_network(
                0, method, path, data, headers, target_url=config.EDGE_FORWARD_URL
            )

        if path.split("?")[0] == "/health":
            return serve_health_endpoint(method, path, data)
        if method == "POST" and path == "/graph":
            return serve_resource_graph(data)

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
                'IN(%s): "%s %s" - headers: %s - data: %s'
                % (api, method, path, dict(headers), data)
            )

        if not port:
            if method == "OPTIONS":
                if api and should_log_trace:
                    # print request trace for debugging, if enabled
                    LOG.debug('IN(%s): "%s %s" - status: %s' % (api, method, path, 200))
                return 200

            if api in ["", None, API_UNKNOWN]:
                truncated = truncate(data)
                if auth_header or target or data or path not in ["/", "/favicon.ico"]:
                    LOG.info(
                        (
                            'Unable to find forwarding rule for host "%s", path "%s %s", '
                            'target header "%s", auth header "%s", data "%s"'
                        )
                        % (host, method, path, target, auth_header, truncated)
                    )
            else:
                LOG.info(
                    (
                        'Unable to determine forwarding port for API "%s" - please '
                        "make sure this API is enabled via the SERVICES configuration"
                    )
                    % api
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
        if encoding_type.upper() == GZIP_ENCODING.upper() and api not in [S3]:
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

    def return_response(self, method, path, data, headers, response, request_handler=None):
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

        # Fix Go SDK issue
        # https://github.com/localstack/localstack/issues/3833
        if headers.get("Accept-Encoding") == "gzip" and response._content and api not in [S3]:
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


def do_forward_request_inmem(api, method, path, data, headers, port=None):
    listener_details = PROXY_LISTENERS.get(api)
    if not listener_details:
        message = (
            'Unable to find listener for service "%s" - please make sure to include it in $SERVICES'
            % api
        )
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
        request_handler=None,
        client_address=client_address,
        server_address=server_address,
    )
    return response


def do_forward_request_network(port, method, path, data, headers, target_url=None):
    # TODO: enable per-service endpoints, to allow deploying in distributed settings
    target_url = target_url or "%s://%s:%s" % (get_service_protocol(), LOCALHOST, port)
    url = "%s%s" % (target_url, path)
    response = requests.request(method, url, data=data, headers=headers, verify=False, stream=True)
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
        result = "cloudfront", config.PORT_CLOUDFRONT
    elif target.startswith("AWSCognitoIdentityProviderService") or "cognito-idp." in host:
        result = "cognito-idp", config.PORT_COGNITO_IDP
    elif target.startswith("AWSCognitoIdentityService") or "cognito-identity." in host:
        result = "cognito-identity", config.PORT_COGNITO_IDENTITY
    elif result[0] == "s3" or uses_host_addressing(headers):
        result = "s3", config.PORT_S3
    elif result[0] == "states" in auth_header or host.startswith("states."):
        result = "stepfunctions", config.PORT_STEPFUNCTIONS
    elif "route53." in host:
        result = "route53", config.PORT_ROUTE53
    elif result[0] == "monitoring":
        result = "cloudwatch", config.PORT_CLOUDWATCH
    elif result[0] == "email":
        result = "ses", config.PORT_SES
    elif result[0] == "execute-api" or ".execute-api." in host:
        result = "apigateway", config.PORT_APIGATEWAY
    elif target.startswith("Firehose_"):
        result = "firehose", config.PORT_FIREHOSE
    elif target.startswith("DynamoDB_"):
        result = "dynamodb", config.PORT_DYNAMODB
    elif target.startswith("DynamoDBStreams") or host.startswith("streams.dynamodb."):
        # Note: DDB streams requests use ../dynamodb/.. auth header, hence we also need to update result_before
        result = result_before = "dynamodbstreams", config.PORT_DYNAMODBSTREAMS
    elif result[0] == "EventBridge" or target.startswith("AWSEvents"):
        result = "events", config.PORT_EVENTS
    elif target.startswith("ResourceGroupsTaggingAPI_"):
        result = "resourcegroupstaggingapi", config.PORT_RESOURCEGROUPSTAGGINGAPI
    elif result[0] == "resource-groups":
        result = "resource-groups", config.PORT_RESOURCE_GROUPS

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


def serve_health_endpoint(method, path, data):
    if method == "GET":
        reload = "reload" in path
        return plugins.get_services_health(reload=reload)
    if method == "POST":
        data = json.loads(to_str(data or "{}"))
        # backdoor API to support restarting the instance
        if data.get("action") in ["kill", "restart"]:
            terminate_all_processes_in_docker()
    return {}


def terminate_all_processes_in_docker():
    if not in_docker():
        # make sure we only run this inside docker!
        return
    print("INFO: Received command to restart all processes ...")
    cmd = (
        'ps aux | grep -v supervisor | grep -v docker-entrypoint.sh | grep -v "make infra" | '
        "grep -v localstack_infra.log | awk '{print $1}' | grep -v PID"
    )
    pids = run(cmd).strip()
    pids = re.split(r"\s+", pids)
    pids = [int(pid) for pid in pids]
    this_pid = os.getpid()
    for pid in pids:
        if pid != this_pid:
            try:
                # kill spawned process
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    # kill the process itself
    sys.exit(0)


def serve_resource_graph(data):
    data = json.loads(to_str(data or "{}"))

    if not data.get("awsEnvironment"):
        raise ValueError("cannot parse aws Environment from empty string")

    env = Environment.from_string(data.get("awsEnvironment"))
    graph = dashboard_infra.get_graph(
        name_filter=data.get("nameFilter") or ".*",
        env=env,
        region=data.get("awsRegion"),
    )
    return graph


def get_api_from_custom_rules(method, path, data, headers):
    """Determine backend port based on custom rules."""

    # detect S3 presigned URLs
    if "AWSAccessKeyId=" in path or "Signature=" in path:
        return "s3", config.PORT_S3

    # heuristic for SQS queue URLs
    if is_sqs_queue_url(path):
        return "sqs", config.PORT_SQS

    # DynamoDB shell URLs
    if path.startswith("/shell") or path.startswith("/dynamodb/shell"):
        return "dynamodb", config.PORT_DYNAMODB

    # API Gateway invocation URLs
    if ("/%s/" % PATH_USER_REQUEST) in path:
        return "apigateway", config.PORT_APIGATEWAY

    data_bytes = to_bytes(data or "")
    version, action = extract_version_and_action(path, data_bytes)

    def _in_path_or_payload(search_str):
        return to_str(search_str) in path or to_bytes(search_str) in data_bytes

    if path == "/" and b"QueueName=" in data_bytes:
        return "sqs", config.PORT_SQS

    if "Action=ConfirmSubscription" in path:
        return "sns", config.PORT_SNS

    if path.startswith("/2015-03-31/functions/"):
        return "lambda", config.PORT_LAMBDA

    if _in_path_or_payload("Action=AssumeRoleWithWebIdentity"):
        return "sts", config.PORT_STS

    if _in_path_or_payload("Action=AssumeRoleWithSAML"):
        return "sts", config.PORT_STS

    # CloudWatch backdoor API to retrieve raw metrics
    if path.startswith(PATH_GET_RAW_METRICS):
        return "cloudwatch", config.PORT_CLOUDWATCH

    # SQS queue requests
    if _in_path_or_payload("QueueUrl=") and _in_path_or_payload("Action="):
        return "sqs", config.PORT_SQS
    if matches_service_action("sqs", action, version=version):
        return "sqs", config.PORT_SQS

    # SNS topic requests
    if matches_service_action("sns", action, version=version):
        return "sns", config.PORT_SNS

    # TODO: move S3 public URLs to a separate port/endpoint, OR check ACLs here first
    stripped = path.strip("/")
    if method in ["GET", "HEAD"] and "/" in stripped:
        # assume that this is an S3 GET request with URL path `/<bucket>/<key ...>`
        return "s3", config.PORT_S3

    # detect S3 URLs
    if stripped and "/" not in stripped:
        if method == "HEAD":
            # assume that this is an S3 HEAD bucket request with URL path `/<bucket>`
            return "s3", config.PORT_S3
        if method == "PUT":
            # assume that this is an S3 PUT bucket request with URL path `/<bucket>`
            return "s3", config.PORT_S3
        if method == "POST" and is_s3_form_data(data_bytes):
            # assume that this is an S3 POST request with form parameters or multipart form in the body
            return "s3", config.PORT_S3

    # detect S3 requests sent from aws-cli using --no-sign-request option
    if "aws-cli/" in headers.get("User-Agent", ""):
        return "s3", config.PORT_S3

    # S3 delete object requests
    if (
        method == "POST"
        and "delete=" in path
        and b"<Delete" in data_bytes
        and b"<Key>" in data_bytes
    ):
        return "s3", config.PORT_S3

    # Put Object API can have multiple keys
    if stripped.count("/") >= 1 and method == "PUT":
        # assume that this is an S3 PUT bucket object request with URL path `/<bucket>/object`
        # or `/<bucket>/object/object1/+`
        return "s3", config.PORT_S3

    auth_header = headers.get("Authorization") or ""

    # detect S3 requests with "AWS id:key" Auth headers
    if auth_header.startswith("AWS "):
        return "s3", config.PORT_S3

    # certain EC2 requests from Java SDK contain no Auth headers (issue #3805)
    if b"Version=2016-11-15" in data_bytes:
        return "ec2", config.PORT_EC2


def get_service_port_for_account(service, headers):
    # assume we're only using a single account, hence return the static port mapping from config.py
    return config.service_port(service)


PROXY_LISTENER_EDGE = ProxyListenerEdge()


def is_trace_logging_enabled(headers):
    if not config.LS_LOG:
        return False
    if config.LS_LOG == LS_LOG_TRACE_INTERNAL:
        return True
    auth_header = headers.get("Authorization") or ""
    return INTERNAL_AWS_ACCESS_KEY_ID not in auth_header


def do_start_edge(bind_address, port, use_ssl, asynchronous=False):
    start_dns_server(asynchronous=True)

    # get port and start Edge
    print("Starting edge router (http%s port %s)..." % ("s" if use_ssl else "", port))
    # use use=True here because our proxy allows both, HTTP and HTTPS traffic
    proxy = start_proxy_server(
        port,
        bind_address=bind_address,
        use_ssl=True,
        update_listener=PROXY_LISTENER_EDGE,
    )
    if not asynchronous:
        proxy.join()
    return proxy


def can_use_sudo():
    try:
        run("echo | sudo -S echo", print_error=False)
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
        __file__,
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
