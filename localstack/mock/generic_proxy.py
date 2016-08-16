from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import requests
import os
import json
import traceback
import logging
from SocketServer import ThreadingMixIn
import __init__
from localstack.utils.common import FuncThread


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
        self.data_string = None
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        self.method = requests.get
        self.forward('GET')

    def do_PUT(self):
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        self.method = requests.put
        self.forward('PUT')

    def do_POST(self):
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
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
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
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
            try:
                data = json.loads(self.data_string)
            except Exception, e:
                # unable to parse JSON, fallback to verbatim string
                data = self.data_string
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        try:
            if self.proxy.update_listener:
                do_forward = self.proxy.update_listener(method=method, path=path,
                    data=data, headers=self.headers, return_forward_info=True)
                if do_forward is not True:
                    # LOGGER.info('Proxy forward decision negative, dropping message.')
                    code = do_forward if isinstance(do_forward, int) else 503
                    self.send_response(code)  # Bad Gateway status code
                    self.end_headers()
                    return
            response = self.method(target_url, data=self.data_string,
                headers=self.headers, proxies=proxies)
            self.send_response(response.status_code)
            self.end_headers()
            self.wfile.write(response.text)
            if self.proxy.update_listener:
                self.proxy.update_listener(method=method, path=path,
                    data=data, headers=self.headers, response=response)
        except Exception, e:
            if not QUIET:
                LOGGER.error("Error forwarding request: %s" % traceback.format_exc(e))

    def log_message(self, format, *args):
        return


class GenericProxy(FuncThread):
    def __init__(self, port, forward_host, update_listener=None, params={}):
        FuncThread.__init__(self, self.run_cmd, params, quiet=True)
        self.httpd = None
        self.port = port
        self.forward_host = forward_host
        self.update_listener = update_listener

    def run_cmd(self, params):
        try:
            self.httpd = ThreadedHTTPServer(("", self.port), GenericProxyHandler)
            self.httpd.my_object = self
            self.httpd.serve_forever()
        except Exception, e:
            if not self.quiet:
                LOGGER.error(traceback.format_exc(e))
            raise

    def stop(self, quiet=False):
        self.quiet = quiet
        if self.httpd:
            self.httpd.server_close()
