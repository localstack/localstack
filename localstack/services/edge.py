import re
import os
import sys
import json
import logging
from requests.models import Response
from localstack import config
from localstack.services import plugins
from localstack.constants import (
    HEADER_LOCALSTACK_TARGET, HEADER_LOCALSTACK_EDGE_URL, LOCALSTACK_ROOT_FOLDER, PATH_USER_REQUEST)
from localstack.utils.common import run, is_root, TMP_THREADS, to_bytes, truncate, to_str, get_service_protocol
from localstack.utils.common import safe_requests as requests
from localstack.services.generic_proxy import ProxyListener, start_proxy_server
from localstack.services.sqs.sqs_listener import is_sqs_queue_url

LOG = logging.getLogger(__name__)

# Header to indicate that the process should kill itself. This is required because if
# this process is started as root, then we cannot kill it from a non-root process
HEADER_KILL_SIGNAL = 'x-localstack-kill'


class ProxyListenerEdge(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200

        if path.split('?')[0] == '/health':
            return serve_health_endpoint(method, path, data)

        # kill the process if we receive this header
        headers.get(HEADER_KILL_SIGNAL) and os._exit(0)

        target = headers.get('x-amz-target', '')
        auth_header = headers.get('authorization', '')
        host = headers.get('host', '')
        headers[HEADER_LOCALSTACK_EDGE_URL] = 'https://%s' % host

        # extract API details
        api, port, path, host = get_api_from_headers(headers, path)

        if port and int(port) < 0:
            return 404

        if not port:
            port = get_port_from_custom_rules(method, path, data, headers) or port

        if not port:
            if api in ['', None, '_unknown_']:
                truncated = truncate(data)
                LOG.info(('Unable to find forwarding rule for host "%s", path "%s", '
                    'target header "%s", auth header "%s", data "%s"') % (host, path, target, auth_header, truncated))
            else:
                LOG.info(('Unable to determine forwarding port for API "%s" - please '
                    'make sure this API is enabled via the SERVICES configuration') % api)
            response = Response()
            response.status_code = 404
            response._content = '{"status": "running"}'
            return response

        connect_host = '%s:%s' % (config.HOSTNAME, port)
        url = '%s://%s%s' % (get_service_protocol(), connect_host, path)
        headers['Host'] = host
        function = getattr(requests, method.lower())
        if isinstance(data, dict):
            data = json.dumps(data)

        response = function(url, data=data, headers=headers, verify=False, stream=True)
        return response


def get_api_from_headers(headers, path=None):
    """ Determine API and backend port based on Authorization headers. """

    target = headers.get('x-amz-target', '')
    host = headers.get('host', '')
    auth_header = headers.get('authorization', '')
    ls_target = headers.get(HEADER_LOCALSTACK_TARGET, '')
    path = path or '/'

    # initialize result
    result = '_unknown_', 0

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    try:
        credential_scope = auth_header.split(',')[0].split()[1]
        _, _, _, service, _ = credential_scope.split('/')
        result = service, get_service_port_for_account(service, headers)
    except Exception:
        pass

    result_before = result

    # Fallback rules and route customizations applied below

    if host.endswith('cloudfront.net'):
        path = path or '/'
        result = 'cloudfront', config.PORT_CLOUDFRONT
    elif target.startswith('AWSCognitoIdentityProviderService') or 'cognito-idp.' in host:
        result = 'cognito-idp', config.PORT_COGNITO_IDP
    elif target.startswith('AWSCognitoIdentityService') or 'cognito-identity.' in host:
        result = 'cognito-identity', config.PORT_COGNITO_IDENTITY
    elif result[0] == 's3' or re.match(r'.*s3(\-website)?\.([^\.]+\.)?amazonaws.com', host):
        host = re.sub(r's3-website\..*\.amazonaws', 's3.amazonaws', host)
        result = 's3', config.PORT_S3
    elif result[0] == 'states' in auth_header or host.startswith('states.'):
        result = 'stepfunctions', config.PORT_STEPFUNCTIONS
    elif result[0] == 'monitoring':
        result = 'cloudwatch', config.PORT_CLOUDWATCH
    elif '.execute-api.' in host:
        result = 'apigateway', config.PORT_APIGATEWAY
    elif target.startswith('DynamoDBStreams') or host.startswith('streams.dynamodb.'):
        # Note: DDB streams requests use ../dynamodb/.. auth header, hence we also need to update result_before
        result = result_before = 'dynamodbstreams', config.PORT_DYNAMODBSTREAMS
    elif ls_target == 'web' or path == '/graph':
        result = 'web', config.PORT_WEB_UI

    return result[0], result_before[1] or result[1], path, host


def is_s3_form_data(data_bytes):
    if(to_bytes('key=') in data_bytes):
        return True
    if(to_bytes('Content-Disposition: form-data') in data_bytes and to_bytes('name="key"') in data_bytes):
        return True
    return False


def serve_health_endpoint(method, path, data):
    if method == 'GET':
        reload = 'reload' in path
        return plugins.get_services_health(reload=reload)
    if method == 'PUT':
        data = json.loads(to_str(data))
        plugins.set_services_health(data)
        return {'status': 'OK'}


def get_port_from_custom_rules(method, path, data, headers):
    """ Determine backend port based on custom rules. """

    # detect S3 presigned URLs
    if 'AWSAccessKeyId=' in path or 'Signature=' in path:
        return config.PORT_S3

    # heuristic for SQS queue URLs
    if is_sqs_queue_url(path):
        return config.PORT_SQS

    # DynamoDB shell URLs
    if path.startswith('/shell') or path.startswith('/dynamodb/shell'):
        return config.PORT_DYNAMODB

    # API Gateway invocation URLs
    if ('/%s/' % PATH_USER_REQUEST) in path:
        return config.PORT_APIGATEWAY

    data_bytes = to_bytes(data or '')

    if path == '/' and to_bytes('QueueName=') in data_bytes:
        return config.PORT_SQS

    # TODO: move S3 public URLs to a separate port/endpoint, OR check ACLs here first
    stripped = path.strip('/')
    if method in ['GET', 'HEAD'] and '/' in stripped:
        # assume that this is an S3 GET request with URL path `/<bucket>/<key ...>`
        return config.PORT_S3

    # detect S3 URLs
    if stripped and '/' not in stripped:
        if method == 'PUT':
            # assume that this is an S3 PUT bucket request with URL path `/<bucket>`
            return config.PORT_S3
        if method == 'POST' and is_s3_form_data(data_bytes):
            # assume that this is an S3 POST request with form parameters or multipart form in the body
            return config.PORT_S3

    if stripped and '/' in stripped:
        if method == 'PUT':
            # assume that this is an S3 PUT bucket object request with URL path `/<bucket>/object`
            return config.PORT_S3

    # detect S3 requests sent from aws-cli using --no-sign-request option
    if 'aws-cli/' in headers.get('User-Agent', ''):
        return config.PORT_S3


def get_service_port_for_account(service, headers):
    # assume we're only using a single account, hence return the static port mapping from config.py
    return config.service_port(service)


def do_start_edge(port, use_ssl, asynchronous=False):
    try:
        # start local DNS server, if present
        from localstack_ext.services import dns_server
        dns_server.start_servers()
    except Exception:
        pass

    # get port and start Edge
    print('Starting edge router (http%s port %s)...' % ('s' if use_ssl else '', port))
    # use use=True here because our proxy allows both, HTTP and HTTPS traffic
    proxy = start_proxy_server(port, use_ssl=True, update_listener=ProxyListenerEdge())
    if not asynchronous:
        proxy.join()
    return proxy


def can_use_sudo():
    try:
        run('echo | sudo -S echo', print_error=False)
        return True
    except Exception:
        return False


def ensure_can_use_sudo():
    if not is_root() and not can_use_sudo():
        print('Please enter your sudo password (required to configure local network):')
        run('sudo echo', stdin=True)


def start_edge(port=None, use_ssl=True, asynchronous=False):
    if not port:
        port = config.EDGE_PORT
    if config.EDGE_PORT_HTTP:
        do_start_edge(config.EDGE_PORT_HTTP, use_ssl=False, asynchronous=True)
    if port > 1024 or is_root():
        return do_start_edge(port, use_ssl, asynchronous=asynchronous)

    # process requires priviledged port but we're not root -> try running as sudo

    class Terminator(object):

        def stop(self, quiet=True):
            try:
                url = 'http%s://localhost:%s' % ('s' if use_ssl else '', port)
                requests.verify_ssl = False
                requests.post(url, headers={HEADER_KILL_SIGNAL: 'kill'})
            except Exception:
                pass

    # make sure we can run sudo commands
    ensure_can_use_sudo()

    # register a signal handler to terminate the sudo process later on
    TMP_THREADS.append(Terminator())

    # start the process as sudo
    sudo_cmd = 'sudo '
    python_cmd = sys.executable
    cmd = '%sPYTHONPATH=.:%s %s %s %s' % (sudo_cmd, LOCALSTACK_ROOT_FOLDER, python_cmd, __file__, port)
    process = run(cmd, asynchronous=asynchronous)
    return process


if __name__ == '__main__':
    logging.basicConfig()
    start_edge(int(sys.argv[1]))
