from six.moves.BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import requests
import os
import json
import traceback
import logging
from requests.models import Response, Request
from six import iteritems, string_types
from six.moves.socketserver import ThreadingMixIn
from six.moves.urllib.parse import urlparse
from localstack.config import DEFAULT_ENCODING
from localstack.utils.common import FuncThread
from localstack.utils.compat import bytes_


QUIET = False

# set up logger
LOGGER = logging.getLogger(__name__)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a separate thread."""


class GenericProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.proxy = server.my_object
        self.data_bytes = None
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        self.method = requests.get
        content_length = self.headers.get('Content-Length')
        if content_length:
            self.data_bytes = self.rfile.read(int(content_length))
        self.forward('GET')

    def do_PUT(self):
        self.data_bytes = self.rfile.read(int(self.headers['Content-Length']))
        self.method = requests.put
        self.forward('PUT')

    def do_POST(self):
        self.data_bytes = self.rfile.read(int(self.headers['Content-Length']))
        self.method = requests.post
        self.forward('POST')

    def do_DELETE(self):
        self.method = requests.delete
        self.forward('DELETE')

    def do_HEAD(self):
        self.method = requests.head
        self.forward('HEAD')

    def do_PATCH(self):
        self.method = requests.patch
        self.data_bytes = self.rfile.read(int(self.headers['Content-Length']))
        self.forward('PATCH')

    def forward(self, method):
        path = self.path
        if '://' in path:
            path = '/' + path.split('://', 1)[1].split('/', 1)[1]
        proxy_url = 'http://%s%s' % (self.proxy.forward_host, path)
        target_url = self.path
        if '://' not in target_url:
            target_url = 'http://%s%s' % (self.proxy.forward_host, target_url)
        data = None
        if method in ['POST', 'PUT', 'PATCH']:
            data_string = self.data_bytes
            try:
                if not isinstance(data_string, string_types):
                    data_string = data_string.decode(DEFAULT_ENCODING)
                data = json.loads(data_string)
            except Exception as e:
                # unable to parse JSON, fallback to verbatim string/bytes
                data = data_string

        forward_headers = dict(self.headers)
        # update original "Host" header
        forward_headers['host'] = urlparse(target_url).netloc
        try:
            response = None
            modified_request = None
            # update listener (pre-invocation)
            if self.proxy.update_listener:
                listener_result = self.proxy.update_listener(method=method, path=path,
                    data=data, headers=forward_headers, return_forward_info=True)
                if isinstance(listener_result, Response):
                    response = listener_result
                elif isinstance(listener_result, Request):
                    modified_request = listener_result
                elif listener_result is not True:
                    # get status code from response, or use Bad Gateway status code
                    code = listener_result if isinstance(listener_result, int) else 503
                    self.send_response(code)
                    self.end_headers()
                    return
            if response is None:
                if modified_request:
                    response = self.method(proxy_url, data=modified_request.data,
                        headers=modified_request.headers)
                else:
                    response = self.method(proxy_url, data=self.data_bytes,
                        headers=forward_headers)
            # update listener (post-invocation)
            if self.proxy.update_listener:
                self.proxy.update_listener(method=method, path=path,
                    data=data, headers=self.headers, response=response)
            # copy headers and return response
            self.send_response(response.status_code)
            for header_key, header_value in iteritems(response.headers):
                self.send_header(header_key, header_value)
            self.end_headers()
            self.wfile.write(bytes_(response.content))
        except Exception as e:
            if not self.proxy.quiet:
                LOGGER.exception("Error forwarding request: %s" % str(e))

    def log_message(self, format, *args):
        return


class GenericProxy(FuncThread):
    def __init__(self, port, forward_host=None, update_listener=None, quiet=False, params={}):
        FuncThread.__init__(self, self.run_cmd, params, quiet=quiet)
        self.httpd = None
        self.port = port
        self.quiet = quiet
        self.forward_host = forward_host
        self.update_listener = update_listener

    def run_cmd(self, params):
        try:
            self.httpd = ThreadedHTTPServer(("", self.port), GenericProxyHandler)
            self.httpd.my_object = self
            self.httpd.serve_forever()
        except Exception as e:
            if not self.quiet:
                LOGGER.error('Exception running proxy on port %s: %s' % (self.port, traceback.format_exc()))
            raise

    def stop(self, quiet=False):
        self.quiet = quiet
        if self.httpd:
            self.httpd.server_close()
