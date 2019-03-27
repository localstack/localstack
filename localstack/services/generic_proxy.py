import os
import sys
import ssl
import socket
import inspect
import logging
import traceback
import requests
from flask_cors import CORS
from requests.structures import CaseInsensitiveDict
from requests.models import Response, Request
from six import iteritems
from six.moves.socketserver import ThreadingMixIn
from six.moves.urllib.parse import urlparse
from six.moves.BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from localstack.config import TMP_FOLDER, USE_SSL
from localstack.constants import ENV_INTERNAL_TEST_RUN
from localstack.utils.common import FuncThread, generate_ssl_cert, to_bytes

QUIET = False

# path for test certificate
SERVER_CERT_PEM_FILE = '%s/server.test.pem' % (TMP_FOLDER)

# CORS settings
CORS_ALLOWED_HEADERS = ('authorization', 'content-type', 'content-md5', 'cache-control',
    'x-amz-content-sha256', 'x-amz-date', 'x-amz-security-token', 'x-amz-user-agent')
CORS_ALLOWED_METHODS = ('HEAD', 'GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'PATCH')

# set up logger
LOGGER = logging.getLogger(__name__)


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

    def return_response(self, method, path, data, headers, response):
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
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

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

    def read_content(self):
        content_length = self.headers.get('Content-Length')
        if content_length:
            self.data_bytes = self.rfile.read(int(content_length))
        else:
            self.data_bytes = None
            if self.method in (requests.post, requests.put):
                # If the Content-Length header is missing, try to read
                # content from the socket using a socket timeout.
                socket_timeout_secs = 0.5
                self.request.settimeout(socket_timeout_secs)
                while True:
                    try:
                        # TODO find a more efficient way to do this!
                        tmp = self.rfile.read(1)
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
        path = self.path
        if '://' in path:
            path = '/' + path.split('://', 1)[1].split('/', 1)[1]
        proxy_url = '%s%s' % (self.proxy.forward_url, path)
        target_url = self.path
        if '://' not in target_url:
            target_url = '%s%s' % (self.proxy.forward_url, target_url)
        data = self.data_bytes

        forward_headers = CaseInsensitiveDict(self.headers)
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
            for listener in self.DEFAULT_LISTENERS + [self.proxy.update_listener]:
                if not listener:
                    continue
                listener_result = listener.forward_request(method=method,
                    path=path, data=data, headers=forward_headers)
                if isinstance(listener_result, Response):
                    response = listener_result
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
                    self.end_headers()
                    return
            # perform the actual invocation of the backend service
            if response is None:
                if modified_request:
                    response = self.method(proxy_url, data=modified_request.data,
                        headers=modified_request.headers, stream=True)
                else:
                    response = self.method(proxy_url, data=self.data_bytes,
                        headers=forward_headers, stream=True)
                # prevent requests from processing response body
                if not response._content_consumed and response.raw:
                    response._content = response.raw.read()
            # update listener (post-invocation)
            if self.proxy.update_listener:
                kwargs = {
                    'method': method,
                    'path': path,
                    'data': data,
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

            # allow pre-flight CORS headers by default
            if 'Access-Control-Allow-Origin' not in response.headers:
                self.send_header('Access-Control-Allow-Origin', '*')
            if 'Access-Control-Allow-Methods' not in response.headers:
                self.send_header('Access-Control-Allow-Methods', ','.join(CORS_ALLOWED_METHODS))
            if 'Access-Control-Allow-Headers' not in response.headers:
                self.send_header('Access-Control-Allow-Headers', ','.join(CORS_ALLOWED_HEADERS))

            self.end_headers()
            if response.content and len(response.content):
                self.wfile.write(to_bytes(response.content))
            self.wfile.flush()
        except Exception as e:
            trace = str(traceback.format_exc())
            conn_errors = ('ConnectionRefusedError', 'NewConnectionError')
            conn_error = any(e in trace for e in conn_errors)
            error_msg = 'Error forwarding request: %s %s' % (e, trace)
            if 'Broken pipe' in trace:
                LOGGER.warn('Connection prematurely closed by client (broken pipe).')
            elif not self.proxy.quiet or not conn_error:
                LOGGER.error(error_msg)
                if os.environ.get(ENV_INTERNAL_TEST_RUN):
                    # During a test run, we also want to print error messages, because
                    # log messages are delayed until the entire test run is over, and
                    # hence we are missing messages if the test hangs for some reason.
                    print('ERROR: %s' % error_msg)
            self.send_response(502)  # bad gateway
            self.end_headers()
            # force close connection
            self.close_connection = 1

    def log_message(self, format, *args):
        return


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
        self.forward_url = forward_url
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
                combined_file, cert_file_name, key_file_name = GenericProxy.create_ssl_cert()
                self.httpd.socket = ssl.wrap_socket(self.httpd.socket,
                    server_side=True, certfile=combined_file)
            self.httpd.my_object = self
            self.httpd.serve_forever()
        except Exception as e:
            if not self.quiet or not self.server_stopped:
                LOGGER.error('Exception running proxy on port %s: %s %s' % (self.port, e, traceback.format_exc()))

    def stop(self, quiet=False):
        self.quiet = quiet
        if self.httpd:
            self.httpd.server_close()
            self.server_stopped = True

    @classmethod
    def create_ssl_cert(cls, random=True):
        return generate_ssl_cert(SERVER_CERT_PEM_FILE, random=random)

    @classmethod
    def get_flask_ssl_context(cls):
        if USE_SSL:
            combined_file, cert_file_name, key_file_name = cls.create_ssl_cert()
            return (cert_file_name, key_file_name)
        return None


def serve_flask_app(app, port, quiet=True, host=None, cors=True):
    if cors:
        CORS(app)
    if quiet:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
    if not host:
        host = '0.0.0.0'
    ssl_context = GenericProxy.get_flask_ssl_context()
    app.run(port=int(port), threaded=True, host=host, ssl_context=ssl_context)
    return app
