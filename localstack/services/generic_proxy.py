import re
import os
import sys
import ssl
import json
import socket
import inspect
import logging
import traceback
import requests
from ssl import SSLError
from flask_cors import CORS
from requests.structures import CaseInsensitiveDict
from requests.models import Response, Request
from six import iteritems
from six.moves.socketserver import ThreadingMixIn
from six.moves.urllib.parse import urlparse
from six.moves.BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from localstack.config import TMP_FOLDER, USE_SSL, EXTRA_CORS_ALLOWED_HEADERS, EXTRA_CORS_EXPOSE_HEADERS
from localstack.constants import ENV_INTERNAL_TEST_RUN, APPLICATION_JSON
from localstack.utils.common import FuncThread, generate_ssl_cert, to_bytes
from localstack.utils.aws.aws_responses import LambdaResponse

QUIET = False

# path for test certificate
SERVER_CERT_PEM_FILE = '%s/server.test.pem' % (TMP_FOLDER)


CORS_ALLOWED_HEADERS = ['authorization', 'content-type', 'content-md5', 'cache-control',
    'x-amz-content-sha256', 'x-amz-date', 'x-amz-security-token', 'x-amz-user-agent',
    'x-amz-target', 'x-amz-acl', 'x-amz-version-id', 'x-localstack-target', 'x-amz-tagging']
if EXTRA_CORS_ALLOWED_HEADERS:
    CORS_ALLOWED_HEADERS += EXTRA_CORS_ALLOWED_HEADERS.split(',')

CORS_ALLOWED_METHODS = ('HEAD', 'GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'PATCH')

CORS_EXPOSE_HEADERS = ('x-amz-version-id', )
if EXTRA_CORS_EXPOSE_HEADERS:
    CORS_EXPOSE_HEADERS += tuple(EXTRA_CORS_EXPOSE_HEADERS.split(','))

# set up logger
LOG = logging.getLogger(__name__)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a separate thread."""
    daemon_threads = True


class ProxyListener(object):

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


class GenericProxyHandler(BaseHTTPRequestHandler):

    # List of `ProxyListener` instances that are enabled by default for all requests
    DEFAULT_LISTENERS = []

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.proxy = server.my_object
        self.data_bytes = None
        self.protocol_version = self.proxy.protocol_version
        try:
            BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        except SSLError as e:
            LOG.warning('SSL error when handling request: %s' % e)
        except Exception as e:
            if 'cannot read from timed out object' not in str(e):
                LOG.warning('Unknown error: %s' % e)

    def parse_request(self):
        result = BaseHTTPRequestHandler.parse_request(self)
        if not result:
            return result
        if sys.version_info[0] >= 3:
            return result
        # Required fix for Python 2 (otherwise S3 uploads are hanging), based on the Python 3 code:
        # https://sourcecodebrowser.com/python3.2/3.2.3/http_2server_8py_source.html#l00332
        expect = self.headers.get('Expect', '')
        if (expect.lower() == '100-continue' and
                self.protocol_version >= 'HTTP/1.1' and
                self.request_version >= 'HTTP/1.1'):
            if self.request_version != 'HTTP/0.9':
                self.wfile.write(('%s %d %s\r\n' %
                    (self.protocol_version, 100, 'Continue')).encode('latin1', 'strict'))
                self.end_headers()
        return result

    def do_GET(self):
        self.method = requests.get
        self.read_content()
        self.forward('GET')

    def do_PUT(self):
        self.method = requests.put
        self.read_content()
        self.forward('PUT')

    def do_POST(self):
        self.method = requests.post
        self.read_content()
        self.forward('POST')

    def do_DELETE(self):
        self.data_bytes = None
        self.method = requests.delete
        self.forward('DELETE')

    def do_HEAD(self):
        self.data_bytes = None
        self.method = requests.head
        self.forward('HEAD')

    def do_PATCH(self):
        self.method = requests.patch
        self.read_content()
        self.forward('PATCH')

    def do_OPTIONS(self):
        self.data_bytes = None
        self.method = requests.options
        self.forward('OPTIONS')

    def do_CONNECT(self):
        self.method = None
        self.headers['Connection'] = self.headers.get('Connection') or 'keep-alive'
        self.forward('CONNECT')

    def read_content(self):
        content_length = self.headers.get('Content-Length')
        if content_length:
            self.data_bytes = self.rfile.read(int(content_length))
            return

        self.data_bytes = None
        if self.method in (requests.post, requests.put):
            LOG.warning('Expected Content-Length header not found in POST/PUT request')

            # If the Content-Length header is missing, try to read
            # content from the socket using a socket timeout.
            socket_timeout_secs = 0.5
            self.request.settimeout(socket_timeout_secs)
            block_length = 1
            while True:
                try:
                    # TODO find a more efficient way to do this!
                    tmp = self.rfile.read(block_length)
                    if self.data_bytes is None:
                        self.data_bytes = tmp
                    else:
                        self.data_bytes += tmp
                except socket.timeout:
                    break

    def build_x_forwarded_for(self, headers):
        x_forwarded_for = headers.get('X-Forwarded-For')

        client_address = self.client_address[0]
        server_address = ':'.join(map(str, self.server.server_address))

        if x_forwarded_for:
            x_forwarded_for_list = (x_forwarded_for, client_address, server_address)
        else:
            x_forwarded_for_list = (client_address, server_address)

        return ', '.join(x_forwarded_for_list)

    def forward(self, method):
        data = self.data_bytes
        forward_headers = CaseInsensitiveDict(self.headers)

        # force close connection
        connection_header = forward_headers.get('Connection') or ''
        if connection_header.lower() not in ['keep-alive', '']:
            self.close_connection = 1

        def is_full_url(url):
            return re.match(r'[a-zA-Z]+://.+', url)

        path = self.path
        if is_full_url(path):
            path = path.split('://', 1)[1]
            path = '/%s' % (path.split('/', 1)[1] if '/' in path else '')
        forward_base_url = self.proxy.forward_base_url
        proxy_url = '%s%s' % (forward_base_url, path)

        for listener in self._listeners():
            if listener:
                proxy_url = listener.get_forward_url(method, path, data, forward_headers) or proxy_url

        target_url = self.path
        if not is_full_url(target_url):
            target_url = '%s%s' % (forward_base_url, target_url)

        # update original "Host" header (moto s3 relies on this behavior)
        if not forward_headers.get('Host'):
            forward_headers['host'] = urlparse(target_url).netloc
        if 'localhost.atlassian.io' in forward_headers.get('Host'):
            forward_headers['host'] = 'localhost'
        forward_headers['X-Forwarded-For'] = self.build_x_forwarded_for(forward_headers)

        try:
            response = None
            modified_request = None
            # update listener (pre-invocation)
            for listener in self._listeners():
                if not listener:
                    continue
                listener_result = listener.forward_request(method=method,
                    path=path, data=data, headers=forward_headers)
                if isinstance(listener_result, Response):
                    response = listener_result
                    break
                if isinstance(listener_result, LambdaResponse):
                    response = listener_result
                    break
                if isinstance(listener_result, dict):
                    response = Response()
                    response._content = json.dumps(listener_result)
                    response.headers['Content-Type'] = APPLICATION_JSON
                    response.status_code = 200
                    break
                elif isinstance(listener_result, Request):
                    modified_request = listener_result
                    data = modified_request.data
                    forward_headers = modified_request.headers
                    break
                elif listener_result is not True:
                    # get status code from response, or use Bad Gateway status code
                    code = listener_result if isinstance(listener_result, int) else 503
                    self.send_response(code)
                    self.send_header('Content-Length', '0')
                    # allow pre-flight CORS headers by default
                    self._send_cors_headers()
                    self.end_headers()
                    return

            # perform the actual invocation of the backend service
            if response is None:
                forward_headers['Connection'] = connection_header or 'close'
                data_to_send = self.data_bytes
                request_url = proxy_url
                if modified_request:
                    if modified_request.url:
                        request_url = '%s%s' % (forward_base_url, modified_request.url)
                    data_to_send = modified_request.data

                response = self.method(request_url, data=data_to_send,
                    headers=forward_headers, stream=True)

                # prevent requests from processing response body
                if not response._content_consumed and response.raw:
                    response._content = response.raw.read()

            # update listener (post-invocation)
            if self.proxy.update_listener:
                kwargs = {
                    'method': method,
                    'path': path,
                    'data': self.data_bytes,
                    'headers': forward_headers,
                    'response': response
                }
                if 'request_handler' in inspect.getargspec(self.proxy.update_listener.return_response)[0]:
                    # some listeners (e.g., sqs_listener.py) require additional details like the original
                    # request port, hence we pass in a reference to this request handler as well.
                    kwargs['request_handler'] = self
                updated_response = self.proxy.update_listener.return_response(**kwargs)
                if isinstance(updated_response, Response):
                    response = updated_response

            # copy headers and return response
            self.send_response(response.status_code)

            content_length_sent = False
            for header_key, header_value in iteritems(response.headers):
                # filter out certain headers that we don't want to transmit
                if header_key.lower() not in ('transfer-encoding', 'date', 'server'):
                    self.send_header(header_key, header_value)
                    content_length_sent = content_length_sent or header_key.lower() == 'content-length'

            if not content_length_sent:
                self.send_header('Content-Length', '%s' % len(response.content) if response.content else 0)

            if isinstance(response, LambdaResponse):
                self.send_multi_value_headers(response.multi_value_headers)

            # allow pre-flight CORS headers by default
            self._send_cors_headers(response)

            self.end_headers()
            if response.content and len(response.content):
                self.wfile.write(to_bytes(response.content))
        except Exception as e:
            trace = str(traceback.format_exc())
            conn_errors = ('ConnectionRefusedError', 'NewConnectionError',
                           'Connection aborted', 'Unexpected EOF', 'Connection reset by peer',
                           'cannot read from timed out object')
            conn_error = any(e in trace for e in conn_errors)
            error_msg = 'Error forwarding request: %s %s' % (e, trace)
            if 'Broken pipe' in trace:
                LOG.warn('Connection prematurely closed by client (broken pipe).')
            elif not self.proxy.quiet or not conn_error:
                LOG.error(error_msg)
                if os.environ.get(ENV_INTERNAL_TEST_RUN):
                    # During a test run, we also want to print error messages, because
                    # log messages are delayed until the entire test run is over, and
                    # hence we are missing messages if the test hangs for some reason.
                    print('ERROR: %s' % error_msg)
            self.send_response(502)  # bad gateway
            self.end_headers()
            # force close connection
            self.close_connection = 1
        finally:
            try:
                self.wfile.flush()
            except Exception as e:
                LOG.warning('Unable to flush write file: %s' % e)

    def _send_cors_headers(self, response=None):
        # Note: Use "response is not None" here instead of "not response"!
        headers = response is not None and response.headers or {}
        if 'Access-Control-Allow-Origin' not in headers:
            self.send_header('Access-Control-Allow-Origin', '*')
        if 'Access-Control-Allow-Methods' not in headers:
            self.send_header('Access-Control-Allow-Methods', ','.join(CORS_ALLOWED_METHODS))
        if 'Access-Control-Allow-Headers' not in headers:
            requested_headers = self.headers.get('Access-Control-Request-Headers', '')
            requested_headers = re.split(r'[,\s]+', requested_headers) + CORS_ALLOWED_HEADERS
            self.send_header('Access-Control-Allow-Headers', ','.join([h for h in requested_headers if h]))
        if 'Access-Control-Expose-Headers' not in headers:
            self.send_header('Access-Control-Expose-Headers', ','.join(CORS_EXPOSE_HEADERS))

    def _listeners(self):
        return self.DEFAULT_LISTENERS + [self.proxy.update_listener]

    def log_message(self, format, *args):
        return

    def send_multi_value_headers(self, multi_value_headers):
        for key, values in multi_value_headers.items():
            for value in values:
                self.send_header(key, value)


class DuplexSocket(ssl.SSLSocket):
    """ Simple duplex socket wrapper that allows serving HTTP/HTTPS over the same port. """

    def accept(self):
        newsock, addr = socket.socket.accept(self)
        peek_bytes = 5
        first_bytes = newsock.recv(peek_bytes, socket.MSG_PEEK)
        if len(first_bytes or '') == peek_bytes:
            first_byte = first_bytes[0]
            if first_byte < 32 or first_byte >= 127:
                newsock = self.context.wrap_socket(newsock,
                            do_handshake_on_connect=self.do_handshake_on_connect,
                            suppress_ragged_eofs=self.suppress_ragged_eofs,
                            server_side=True)

        return newsock, addr


# set globally defined SSL socket implementation class
ssl.SSLContext.sslsocket_class = DuplexSocket


class GenericProxy(FuncThread):
    def __init__(self, port, forward_url=None, ssl=False, host=None, update_listener=None, quiet=False, params={}):
        FuncThread.__init__(self, self.run_cmd, params, quiet=quiet)
        self.httpd = None
        self.port = port
        self.ssl = ssl
        self.quiet = quiet
        if forward_url:
            if '://' not in forward_url:
                forward_url = 'http://%s' % forward_url
            forward_url = forward_url.rstrip('/')
        self.forward_base_url = forward_url
        self.update_listener = update_listener
        self.server_stopped = False
        # Required to enable 'Connection: keep-alive' for S3 uploads
        self.protocol_version = params.get('protocol_version') or 'HTTP/1.1'
        self.listen_host = host or ''

    def run_cmd(self, params):
        try:
            self.httpd = ThreadedHTTPServer((self.listen_host, self.port), GenericProxyHandler)
            if self.ssl:
                # make sure we have a cert generated
                combined_file, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=self.port)
                self.httpd.socket = ssl.wrap_socket(self.httpd.socket,
                    server_side=True, certfile=combined_file)
            self.httpd.my_object = self
            self.httpd.serve_forever()
        except Exception as e:
            if not self.quiet or not self.server_stopped:
                LOG.error('Exception running proxy on port %s: %s %s' % (self.port, e, traceback.format_exc()))

    def stop(self, quiet=False):
        self.quiet = quiet
        if self.httpd:
            self.httpd.server_close()
            self.server_stopped = True

    @classmethod
    def create_ssl_cert(cls, serial_number=None):
        return generate_ssl_cert(SERVER_CERT_PEM_FILE, serial_number=serial_number)

    @classmethod
    def get_flask_ssl_context(cls, serial_number=None):
        if USE_SSL:
            _, cert_file_name, key_file_name = cls.create_ssl_cert(serial_number=serial_number)
            return (cert_file_name, key_file_name)
        return None


def serve_flask_app(app, port, quiet=True, host=None, cors=True):
    if cors:
        CORS(app)
    if quiet:
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
    if not host:
        host = '0.0.0.0'
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
