import types
import asyncio
import logging
import traceback
import concurrent.futures
import h11
from contextvars import copy_context
from quart import make_response, request, Quart
from localstack import config
from localstack.utils.common import start_thread

LOG = logging.getLogger(__name__)

THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=10)


def setup_quart_logging():
    # set up loggers to avoid duplicate log lines in quart
    for name in ['quart.app', 'quart.serving']:
        log = logging.getLogger(name)
        log.setLevel(logging.INFO if config.DEBUG else logging.WARNING)
        for hdl in list(log.handlers):
            log.removeHandler(hdl)


async def run_sync(func, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        THREAD_POOL, copy_context().run, func, *args)


def apply_patches():

    def InformationalResponse_init(self, *args, **kwargs):
        if kwargs.get('status_code') == 100 and not kwargs.get('reason'):
            # add missing "100 Continue" keyword which makes boto3 HTTP clients fail/hang
            kwargs['reason'] = 'Continue'
        InformationalResponse_init_orig(self, *args, **kwargs)

    InformationalResponse_init_orig = h11.InformationalResponse.__init__
    h11.InformationalResponse.__init__ = InformationalResponse_init


def ensure_event_loop():
    try:
        return asyncio.get_event_loop()
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def run_server(port, handler=None, asynchronous=True, ssl_creds=None):

    ensure_event_loop()
    app = Quart(__name__)

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']

    @app.route('/', methods=methods, defaults={'path': ''})
    @app.route('/<path:path>', methods=methods)
    async def index(path=None):
        response = await make_response('{}')
        if handler:
            do_load_data = True
            data = await request.get_data() if do_load_data else ''
            try:
                result = await run_sync(handler, request, data)
            except Exception as e:
                LOG.warning('Error in proxy handler for request %s %s: %s %s' %
                    (request.method, request.url, e, traceback.format_exc()))
                response.status_code = 500
                return response
            if result is not None:
                response = await make_response(result.content or '')
                multi_value_headers = getattr(result, 'multi_value_headers', {})
                response.headers.update(dict(result.headers))
                for key, values in multi_value_headers.items():
                    for value in values:
                        response.headers.add_header(key, value)
                response.status_code = result.status_code
        return response

    cert_file_name, key_file_name = ssl_creds or (None, None)

    def run_app_sync(*args, loop=None):
        kwargs = {}
        if cert_file_name:
            kwargs['certfile'] = cert_file_name
        if key_file_name:
            kwargs['keyfile'] = key_file_name
        setup_quart_logging()
        return app.run(host='0.0.0.0', port=port, loop=loop, use_reloader=False, **kwargs)

    def run_in_thread():
        def _run(*args):
            loop = asyncio.new_event_loop()

            def fix_add_signal_handler(self, *args, **kwargs):
                # fix for error "RuntimeError: set_wakeup_fd only works in main thread" in quart/app.py
                try:
                    add_signal_handler_orig(*args, **kwargs)
                except Exception:
                    raise NotImplementedError()

            add_signal_handler_orig = loop.add_signal_handler
            loop.add_signal_handler = types.MethodType(fix_add_signal_handler, loop)
            asyncio.set_event_loop(loop)
            run_app_sync(loop=loop)

        return start_thread(_run)

    if asynchronous:
        return run_in_thread()

    return run_app_sync()


# apply patches on startup
apply_patches()
