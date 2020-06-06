import types
import asyncio
import logging
from quart import make_response, request, Quart
from localstack import config
from localstack.utils.common import start_thread


def setup_quart_logging():
    # set up loggers to avoid duplicate log lines in quart
    for name in ['quart.app', 'quart.serving']:
        log = logging.getLogger(name)
        log.setLevel(logging.INFO if config.DEBUG else logging.WARNING)
        for hdl in list(log.handlers):
            log.removeHandler(hdl)


def run_server(port, handler=None, asynchronous=True, ssl_creds=None):

    app = Quart(__name__)

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']

    @app.route('/', methods=methods, defaults={'path': ''})
    @app.route('/<path:path>', methods=methods)
    async def index(path=None):
        response = await make_response('{}')
        if handler:
            data = await request.get_data()
            result = handler(request, data)
            if result:
                response = await make_response(result.content)
                response.headers.update(dict(result.headers))
                response.status_code = result.status_code
        return response

    cert_file_name, key_file_name = ssl_creds or (None, None)

    def run_sync(*args, loop=None):
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
            run_sync(loop=loop)
        start_thread(_run)

    if asynchronous:
        return run_in_thread()

    return run_sync()
