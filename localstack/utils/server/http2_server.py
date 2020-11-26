import os
import asyncio
import logging
import threading
import traceback
import h11
from quart import make_response, request, Quart
from quart.app import _cancel_all_tasks
from hypercorn import utils as hypercorn_utils
from hypercorn.config import Config
from hypercorn.events import Closed
from hypercorn.asyncio import serve, tcp_server
from hypercorn.protocol import http_stream
from localstack import config
from localstack.utils.common import TMP_THREADS, FuncThread, load_file, retry
from localstack.utils.http_utils import uses_chunked_encoding
from localstack.utils.async_utils import run_sync, ensure_event_loop

LOG = logging.getLogger(__name__)

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']

# cache of SSL contexts (indexed by cert file names)
SSL_CONTEXTS = {}
SSL_LOCK = threading.RLock()


def setup_quart_logging():
    # set up loggers to avoid duplicate log lines in quart
    for name in ['quart.app', 'quart.serving']:
        log = logging.getLogger(name)
        log.setLevel(logging.INFO if config.DEBUG else logging.WARNING)
        for hdl in list(log.handlers):
            log.removeHandler(hdl)


def apply_patches():

    def InformationalResponse_init(self, *args, **kwargs):
        if kwargs.get('status_code') == 100 and not kwargs.get('reason'):
            # add missing "100 Continue" keyword which makes boto3 HTTP clients fail/hang
            kwargs['reason'] = 'Continue'
        InformationalResponse_init_orig(self, *args, **kwargs)

    InformationalResponse_init_orig = h11.InformationalResponse.__init__
    h11.InformationalResponse.__init__ = InformationalResponse_init

    # skip error logging for ssl.SSLError in hypercorn tcp_server.py

    async def _read_data(self) -> None:
        try:
            return await _read_data_orig(self)
        except Exception:
            await self.protocol.handle(Closed())

    _read_data_orig = tcp_server.TCPServer._read_data
    tcp_server.TCPServer._read_data = _read_data

    # avoid SSL context initialization errors when running multiple server threads in parallel

    def create_ssl_context(self, *args, **kwargs):
        with SSL_LOCK:
            key = '%s%s' % (self.certfile, self.keyfile)
            if key not in SSL_CONTEXTS:
                # perform retries to circumvent "ssl.SSLError: [SSL] PEM lib (_ssl.c:4012)"
                def _do_create():
                    SSL_CONTEXTS[key] = create_ssl_context_orig(self, *args, **kwargs)
                retry(_do_create, retries=3, sleep=0.5)
            return SSL_CONTEXTS[key]

    create_ssl_context_orig = Config.create_ssl_context
    Config.create_ssl_context = create_ssl_context

    # avoid "h11._util.LocalProtocolError: Too little data for declared Content-Length" for certain status codes

    def suppress_body(method, status_code):
        if status_code == 412:
            return False
        return suppress_body_orig(method, status_code)

    suppress_body_orig = hypercorn_utils.suppress_body
    hypercorn_utils.suppress_body = suppress_body
    http_stream.suppress_body = suppress_body


class HTTPErrorResponse(Exception):
    def __init__(self, *args, code=None, **kwargs):
        super(HTTPErrorResponse, self).__init__(*args, **kwargs)
        self.code = code


def run_server(port, handler=None, asynchronous=True, ssl_creds=None):

    ensure_event_loop()
    app = Quart(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024  # 256 MB request payload limit

    @app.route('/', methods=HTTP_METHODS, defaults={'path': ''})
    @app.route('/<path:path>', methods=HTTP_METHODS)
    async def index(path=None):
        response = await make_response('{}')
        if handler:
            data = await request.get_data()
            try:
                result = await run_sync(handler, request, data)
                if isinstance(result, Exception):
                    raise result
            except Exception as e:
                LOG.warning('Error in proxy handler for request %s %s: %s %s' %
                    (request.method, request.url, e, traceback.format_exc()))
                response.status_code = 500
                if isinstance(e, HTTPErrorResponse):
                    response.status_code = e.code or response.status_code
                return response
            if result is not None:
                is_chunked = uses_chunked_encoding(result)
                result_content = result.content or ''
                response = await make_response(result_content)
                response.status_code = result.status_code
                if is_chunked:
                    response.headers.pop('Content-Length', None)
                result.headers.pop('Server', None)
                result.headers.pop('Date', None)
                headers = {k: str(v).replace('\n', r'\n') for k, v in result.headers.items()}
                response.headers.update(headers)
                # set multi-value headers
                multi_value_headers = getattr(result, 'multi_value_headers', {})
                for key, values in multi_value_headers.items():
                    for value in values:
                        response.headers.add_header(key, value)
                # set default headers, if required
                if not is_chunked and request.method not in ['OPTIONS', 'HEAD']:
                    response_data = await response.get_data()
                    response.headers['Content-Length'] = str(len(response_data or ''))
                if 'Connection' not in response.headers:
                    response.headers['Connection'] = 'close'
        return response

    def run_app_sync(*args, loop=None, shutdown_event=None):
        kwargs = {}
        config = Config()
        cert_file_name, key_file_name = ssl_creds or (None, None)
        if cert_file_name:
            kwargs['certfile'] = cert_file_name
            config.certfile = cert_file_name
        if key_file_name:
            kwargs['keyfile'] = key_file_name
            config.keyfile = key_file_name
        setup_quart_logging()
        config.bind = ['0.0.0.0:%s' % port]
        loop = loop or ensure_event_loop()
        run_kwargs = {}
        if shutdown_event:
            run_kwargs['shutdown_trigger'] = shutdown_event.wait
        try:
            try:
                return loop.run_until_complete(serve(app, config, **run_kwargs))
            except Exception as e:
                LOG.info('Error running server event loop on port %s: %s %s' % (port, e, traceback.format_exc()))
                if 'SSL' in str(e):
                    c_exists = os.path.exists(cert_file_name)
                    k_exists = os.path.exists(key_file_name)
                    c_size = len(load_file(cert_file_name)) if c_exists else 0
                    k_size = len(load_file(key_file_name)) if k_exists else 0
                    LOG.warning('Unable to create SSL context. Cert files exist: %s %s (%sB), %s %s (%sB)' %
                                (cert_file_name, c_exists, c_size, key_file_name, k_exists, k_size))
                raise
        finally:
            try:
                _cancel_all_tasks(loop)
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                loop.close()

    class ProxyThread(FuncThread):
        def __init__(self):
            FuncThread.__init__(self, self.run_proxy, None)

        def run_proxy(self, *args):
            loop = ensure_event_loop()
            self.shutdown_event = asyncio.Event()
            run_app_sync(loop=loop, shutdown_event=self.shutdown_event)

        def stop(self, quiet=None):
            self.shutdown_event.set()

    def run_in_thread():
        thread = ProxyThread()
        thread.start()
        TMP_THREADS.append(thread)
        return thread

    if asynchronous:
        return run_in_thread()

    return run_app_sync()


# apply patches on startup
apply_patches()
