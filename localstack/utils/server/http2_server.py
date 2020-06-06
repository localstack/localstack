import types
import asyncio
from quart import make_response, request, Quart
from localstack.utils.common import start_thread
from localstack.services.generic_proxy import GenericProxy, modify_and_forward


class T:
    pass


def run_proxy_server(port, listener=None, forward_url=None, asynchronous=True):
    def handler(request, data):
        if not listener:
            return
        method = request.method
        path = request.path
        headers = request.headers

        request_handler = T()
        request_handler.proxy = T()
        request_handler.proxy.port = port
        response = modify_and_forward(method=method, path=path, data_bytes=data, headers=headers,
            forward_base_url=forward_url, listeners=[listener], request_handler=None,
            client_address='TODO', server_address='TODO')

        return response

    return run_server(port, handler=handler, asynchronous=asynchronous)


def run_server(port, handler=None, asynchronous=True):

    app = Quart(__name__)

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']

    @app.route('/', methods=methods, defaults={'path': ''})
    @app.route('/<path:path>', methods=methods)
    async def index(path=None):
        response = None
        if handler:
            data = await request.get_data()
            result = handler(request, data)
            response = await make_response(result.content)
            response.headers.update(dict(result.headers))
            response.status_code = result.status_code

        if response is None:
            response = await make_response('{}')
        return response

    _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)

    def run_sync(*args, loop=None):
        return app.run(host='0.0.0.0', port=port, certfile=cert_file_name, keyfile=key_file_name, loop=loop)

    def run_in_thread():
        def _run(*args):
            loop = asyncio.new_event_loop()

            def fix_add_signal_handler(self, *args, **kwargs):
                try:
                    add_signal_handler_orig(*args, **kwargs)
                except Exception:
                    raise NotImplementedError()

            # fix for error "RuntimeError: set_wakeup_fd only works in main thread" in quart/app.py
            add_signal_handler_orig = loop.add_signal_handler
            loop.add_signal_handler = types.MethodType(fix_add_signal_handler, loop)
            asyncio.set_event_loop(loop)
            run_sync(loop=loop)
        start_thread(_run)

    if asynchronous:
        return run_in_thread()

    return run_sync()
