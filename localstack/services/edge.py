import re
import os
import sys
import json
import logging
from requests.models import Response
from localstack import config
from localstack.constants import HEADER_LOCALSTACK_TARGET, HEADER_LOCALSTACK_EDGE_URL, LOCALSTACK_ROOT_FOLDER
from localstack.utils.common import run, is_root, TMP_THREADS
from localstack.utils.common import safe_requests as requests
from localstack.services.generic_proxy import ProxyListener, GenericProxy

LOG = logging.getLogger(__name__)

# Header to indicate that the process should kill itself. This is required because if
# this process is started as root, then we cannot kill it from a non-root process
HEADER_KILL_SIGNAL = 'x-localstack-kill'


class ProxyListenerEdge(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200

        # kill the process if we receive this header
        headers.get(HEADER_KILL_SIGNAL) and os._exit(0)

        target = headers.get('x-amz-target', '')
        auth_header = headers.get('authorization', '')
        host = headers.get('host', '')
        headers[HEADER_LOCALSTACK_EDGE_URL] = 'https://%s' % host

        # extract API details
        _, port, path, host = get_api_from_headers(headers, path)

        if not port:
            # detect S3 presigned URLs
            if 'AWSAccessKeyId=' in path or 'Signature=' in path:
                port = config.PORT_S3

        if not port:
            LOG.info('Unable to find forwarding rule for host "%s", path "%s", target header "%s", auth header "%s"' %
                     (host, path, target, auth_header))
            response = Response()
            response.status_code = 404
            response._content = '{"status": "running"}'
            return response

        use_ssl = config.USE_SSL

        connect_host = '%s:%s' % (config.HOSTNAME, port)
        url = 'http%s://%s%s' % ('s' if use_ssl else '', connect_host, path)
        headers['Host'] = host
        function = getattr(requests, method.lower())
        if isinstance(data, dict):
            data = json.dumps(data)

        response = function(url, data=data, headers=headers, verify=False)
        return response


def get_api_from_headers(headers, path=None):
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
        result = service, config.service_port(service)
    except Exception:
        pass

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
    elif '.execute-api.' in host:
        result = 'apigateway', config.PORT_APIGATEWAY
    elif target.startswith('DynamoDBStreams') or host.startswith('streams.dynamodb.'):
        result = 'dynamodbstreams', config.PORT_DYNAMODBSTREAMS
    elif ls_target == 'web' or path == '/graph':
        result = 'web', config.PORT_WEB_UI

    return result[0], result[1], path, host


def do_start_edge(port, use_ssl, asynchronous=False):
    # get port and start Edge
    print('Starting edge router (http%s port %s)...' % ('s' if use_ssl else '', port))
    # use use=True here because our proxy allows both, HTTP and HTTPS traffic
    proxy = GenericProxy(port, ssl=True, update_listener=ProxyListenerEdge())
    proxy.start()
    if not asynchronous:
        proxy.join()
    return proxy


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
