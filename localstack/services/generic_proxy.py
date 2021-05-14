import re
import os
import ssl
import json
import socket
import inspect
import logging
import requests
from asyncio.selector_events import BaseSelectorEventLoop
from flask_cors import CORS
from flask_cors.core import ACL_ORIGIN, ACL_METHODS, ACL_ALLOW_HEADERS, ACL_EXPOSE_HEADERS, ACL_REQUEST_HEADERS
from requests.models import Response, Request
from six.moves.urllib.parse import urlparse
from localstack import config
from localstack.config import EXTRA_CORS_ALLOWED_HEADERS, EXTRA_CORS_EXPOSE_HEADERS
from localstack.constants import APPLICATION_JSON, HEADER_LOCALSTACK_REQUEST_URL
from localstack.utils.aws import aws_stack
from localstack.utils.server import http2_server
from localstack.utils.common import generate_ssl_cert, json_safe, path_from_url, Mock
from localstack.utils.aws.aws_responses import LambdaResponse

# set up logger
LOG = logging.getLogger(__name__)

# path for test certificate
SERVER_CERT_PEM_FILE = 'server.test.pem'

# CORS constants
CORS_ALLOWED_HEADERS = ['authorization', 'content-type', 'content-length', 'content-md5', 'cache-control',
    'x-amz-content-sha256', 'x-amz-date', 'x-amz-security-token', 'x-amz-user-agent',
    'x-amz-target', 'x-amz-acl', 'x-amz-version-id', 'x-localstack-target', 'x-amz-tagging']
if EXTRA_CORS_ALLOWED_HEADERS:
    CORS_ALLOWED_HEADERS += EXTRA_CORS_ALLOWED_HEADERS.split(',')

CORS_ALLOWED_METHODS = ('HEAD', 'GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'PATCH')

CORS_EXPOSE_HEADERS = ('x-amz-version-id', )
if EXTRA_CORS_EXPOSE_HEADERS:
    CORS_EXPOSE_HEADERS += tuple(EXTRA_CORS_EXPOSE_HEADERS.split(','))

ALLOWED_CORS_RESPONSE_HEADERS = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
    'Access-Control-Allow-Headers', 'Access-Control-Max-Age', 'Access-Control-Allow-Credentials',
    'Access-Control-Expose-Headers']


class ProxyListener(object):

    # List of `ProxyListener` instances that are enabled by default for all requests
    DEFAULT_LISTENERS = []

    def forward_request(self, method, path, data, headers):
        """ This interceptor method is called by the proxy when receiving a new request
            (*before* forwarding the request to the backend service). It receives details
            of the incoming request, and returns either of the following results:

            * True if the request should be forwarded to the backend service as-is (default).
            * An integer (e.g., 200) status code to return directly to the client without
              calling the backend service.
            * An instance of requests.models.Response to return directly to the client without
              calling the backend service.
            * An instance of requests.models.Request which represents a new/modified request
              that will be forwarded to the backend service.
            * Any other value, in which case a 503 Bad Gateway is returned to the client
              without calling the backend service.
        """
        return True

    def return_response(self, method, path, data, headers, response, request_handler=None):
        """ This interceptor method is called by the proxy when returning a response
            (*after* having forwarded the request and received a response from the backend
            service). It receives details of the incoming request as well as the response
            from the backend service, and returns either of the following results:

            * An instance of requests.models.Response to return to the client instead of the
              actual response returned from the backend service.
            * Any other value, in which case the response from the backend service is
              returned to the client.
        """
        return None

    def get_forward_url(self, method, path, data, headers):
        """ Return a custom URL to forward the given request to. If a falsy value is returned,
            then the default URL will be used.
        """
        return None


# -------------------
# BASE BACKEND UTILS
# -------------------

class RegionBackend(object):
    """ Base class for region-specific backends for the different APIs. """

    @classmethod
    def get(cls, region=None):
        regions = cls.regions()
        region = region or cls.get_current_request_region()
        regions[region] = regions.get(region) or cls()
        return regions[region]

    @classmethod
    def regions(cls):
        if not hasattr(cls, 'REGIONS'):
            # maps region name to region backend instance
            cls.REGIONS = {}
        return cls.REGIONS

    @classmethod
    def get_current_request_region(cls):
        return aws_stack.get_region()


# ---------------------
# PROXY LISTENER UTILS
# ---------------------


def append_cors_headers(response=None):
    # Note: Use "response is not None" here instead of "not response"!
    headers = {} if response is None else response.headers

    # In case we have LambdaResponse copy multivalue headers to regular headers, since
    # CaseInsensitiveDict does not support "__contains__" and it's easier to deal with
    # a single headers object
    if isinstance(response, LambdaResponse):
        for key in response.multi_value_headers.keys():
            headers[key] = ','.join(
                response.multi_value_headers[key] + ([] if key not in response.headers else [response.headers[key]])
            )
        response.multi_value_headers = {}

    if ACL_ORIGIN not in headers:
        headers[ACL_ORIGIN] = '*'
    if ACL_METHODS not in headers:
        headers[ACL_METHODS] = ','.join(CORS_ALLOWED_METHODS)
    if ACL_ALLOW_HEADERS not in headers:
        requested_headers = headers.get(ACL_REQUEST_HEADERS, '')
        requested_headers = re.split(r'[,\s]+', requested_headers) + CORS_ALLOWED_HEADERS
        headers[ACL_ALLOW_HEADERS] = ','.join([h for h in requested_headers if h])
    if ACL_EXPOSE_HEADERS not in headers:
        headers[ACL_EXPOSE_HEADERS] = ','.join(CORS_EXPOSE_HEADERS)

    for header in ALLOWED_CORS_RESPONSE_HEADERS:
        if headers.get(header) == '':
            del headers[header]


def modify_and_forward(method=None, path=None, data_bytes=None, headers=None, forward_base_url=None,
        listeners=None, request_handler=None, client_address=None, server_address=None):
    """ This is the central function that coordinates the incoming/outgoing messages
        with the proxy listeners (message interceptors). """

    listeners = ProxyListener.DEFAULT_LISTENERS + (listeners or [])
    listeners = [lis for lis in listeners if lis]
    data = data_bytes

    def is_full_url(url):
        return re.match(r'[a-zA-Z]+://.+', url)

    if is_full_url(path):
        path = path.split('://', 1)[1]
        path = '/%s' % (path.split('/', 1)[1] if '/' in path else '')
    proxy_url = '%s%s' % (forward_base_url, path)

    for listener in listeners:
        proxy_url = listener.get_forward_url(method, path, data, headers) or proxy_url

    target_url = path
    if not is_full_url(target_url):
        target_url = '%s%s' % (forward_base_url, target_url)

    # update original "Host" header (moto s3 relies on this behavior)
    if not headers.get('Host'):
        headers['host'] = urlparse(target_url).netloc
    headers['X-Forwarded-For'] = build_x_forwarded_for(headers, client_address, server_address)

    response = None
    modified_request = None

    # update listener (pre-invocation)
    for listener in listeners:
        listener_result = listener.forward_request(method=method,
            path=path, data=data, headers=headers)
        if isinstance(listener_result, Response):
            response = listener_result
            break
        if isinstance(listener_result, LambdaResponse):
            response = listener_result
            break
        if isinstance(listener_result, dict):
            response = Response()
            response._content = json.dumps(json_safe(listener_result))
            response.headers['Content-Type'] = APPLICATION_JSON
            response.status_code = 200
            break
        elif isinstance(listener_result, Request):
            modified_request = listener_result
            data = modified_request.data
            headers = modified_request.headers
            break
        elif http2_server.get_async_generator_result(listener_result):
            return listener_result
        elif listener_result is not True:
            # get status code from response, or use Bad Gateway status code
            code = listener_result if isinstance(listener_result, int) else 503
            response = Response()
            response.status_code = code
            response._content = ''
            response.headers['Content-Length'] = '0'
            append_cors_headers(response)
            return response

    # perform the actual invocation of the backend service
    if response is None:
        headers['Connection'] = headers.get('Connection') or 'close'
        data_to_send = data_bytes
        request_url = proxy_url
        if modified_request:
            if modified_request.url:
                request_url = '%s%s' % (forward_base_url, modified_request.url)
            data_to_send = modified_request.data

        # make sure we drop "chunked" transfer encoding from the headers to be forwarded
        headers.pop('Transfer-Encoding', None)
        requests_method = getattr(requests, method.lower())
        response = requests_method(request_url, data=data_to_send,
            headers=headers, stream=True, verify=False)

    # prevent requests from processing response body (e.g., to pass-through gzip encoded content unmodified)
    pass_raw = ((hasattr(response, '_content_consumed') and not response._content_consumed) or
        response.headers.get('content-encoding') in ['gzip'])
    if pass_raw and getattr(response, 'raw', None):
        new_content = response.raw.read()
        if new_content:
            response._content = new_content

    # update listener (post-invocation)
    if listeners:
        update_listener = listeners[-1]
        kwargs = {
            'method': method,
            'path': path,
            'data': data_bytes,
            'headers': headers,
            'response': response
        }
        if 'request_handler' in inspect.getargspec(update_listener.return_response)[0]:
            # some listeners (e.g., sqs_listener.py) require additional details like the original
            # request port, hence we pass in a reference to this request handler as well.
            kwargs['request_handler'] = request_handler

        updated_response = update_listener.return_response(**kwargs)
        if isinstance(updated_response, Response):
            response = updated_response

    # allow pre-flight CORS headers by default
    from localstack.services.s3.s3_listener import ProxyListenerS3
    is_s3_listener = any([isinstance(service_listener, ProxyListenerS3) for service_listener in listeners])
    if not is_s3_listener:
        append_cors_headers(response)

    return response


def build_x_forwarded_for(headers, client_address, server_address):
    x_forwarded_for = headers.get('X-Forwarded-For')

    if x_forwarded_for:
        x_forwarded_for_list = (x_forwarded_for, client_address, server_address)
    else:
        x_forwarded_for_list = (client_address, server_address)

    return ', '.join(x_forwarded_for_list)


class DuplexSocket(ssl.SSLSocket):
    """ Simple duplex socket wrapper that allows serving HTTP/HTTPS over the same port. """

    def accept(self):
        newsock, addr = socket.socket.accept(self)
        if DuplexSocket.is_ssl_socket(newsock) is not False:
            newsock = self.context.wrap_socket(newsock,
                do_handshake_on_connect=self.do_handshake_on_connect,
                suppress_ragged_eofs=self.suppress_ragged_eofs,
                server_side=True)

        return newsock, addr

    @staticmethod
    def is_ssl_socket(newsock):
        """ Returns True/False if the socket uses SSL or not, or None if the status cannot be determined """
        def peek_ssl_header():
            peek_bytes = 5
            first_bytes = newsock.recv(peek_bytes, socket.MSG_PEEK)
            if len(first_bytes or '') != peek_bytes:
                return
            first_byte = first_bytes[0]
            return first_byte < 32 or first_byte >= 127

        try:
            return peek_ssl_header()
        except Exception:
            # Fix for "[Errno 11] Resource temporarily unavailable" - This can
            #   happen if we're using a non-blocking socket in a blocking thread.
            newsock.setblocking(1)
            newsock.settimeout(1)
            try:
                return peek_ssl_header()
            except Exception:
                return False


# set globally defined SSL socket implementation class
ssl.SSLContext.sslsocket_class = DuplexSocket


class GenericProxy(object):
    # TODO: move methods to different class?
    @classmethod
    def create_ssl_cert(cls, serial_number=None):
        cert_pem_file = get_cert_pem_file_path()
        return generate_ssl_cert(cert_pem_file, serial_number=serial_number)

    @classmethod
    def get_flask_ssl_context(cls, serial_number=None):
        if config.USE_SSL:
            _, cert_file_name, key_file_name = cls.create_ssl_cert(serial_number=serial_number)
            return (cert_file_name, key_file_name)
        return None


async def _accept_connection2(self, protocol_factory, conn, extra, sslcontext, *args, **kwargs):
    is_ssl_socket = DuplexSocket.is_ssl_socket(conn)
    if is_ssl_socket is False:
        sslcontext = None
    result = await _accept_connection2_orig(self, protocol_factory, conn, extra, sslcontext, *args, **kwargs)
    return result


# patch asyncio server to accept SSL and non-SSL traffic over same port
if hasattr(BaseSelectorEventLoop, '_accept_connection2') and not hasattr(BaseSelectorEventLoop, '_ls_patched'):
    _accept_connection2_orig = BaseSelectorEventLoop._accept_connection2
    BaseSelectorEventLoop._accept_connection2 = _accept_connection2
    BaseSelectorEventLoop._ls_patched = True


def get_cert_pem_file_path():
    return os.path.join(config.TMP_FOLDER, SERVER_CERT_PEM_FILE)


def start_proxy_server(port, forward_url=None, use_ssl=None, update_listener=None,
        quiet=False, params={}, asynchronous=True):
    def handler(request, data):
        parsed_url = urlparse(request.url)
        path_with_params = path_from_url(request.url)
        method = request.method
        headers = request.headers
        headers[HEADER_LOCALSTACK_REQUEST_URL] = str(request.url)

        request_handler = Mock()
        request_handler.proxy = Mock()
        request_handler.proxy.port = port
        response = modify_and_forward(method=method, path=path_with_params, data_bytes=data, headers=headers,
            forward_base_url=forward_url, listeners=[update_listener], request_handler=None,
            client_address=request.remote_addr, server_address=parsed_url.netloc)

        return response

    ssl_creds = (None, None)
    if use_ssl:
        _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)
        ssl_creds = (cert_file_name, key_file_name)

    return http2_server.run_server(port, handler=handler, asynchronous=asynchronous, ssl_creds=ssl_creds)


def serve_flask_app(app, port, quiet=True, host=None, cors=True):
    if cors:
        CORS(app)
    if quiet:
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
    if not host:
        host = '0.0.0.0'
    ssl_context = None
    if not config.FORWARD_EDGE_INMEM:
        ssl_context = GenericProxy.get_flask_ssl_context(serial_number=port)
    app.config['ENV'] = 'development'

    def noecho(*args, **kwargs):
        pass

    try:
        import click
        click.echo = noecho
    except Exception:
        pass

    app.run(port=int(port), threaded=True, host=host, ssl_context=ssl_context)
    return app
