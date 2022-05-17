import json
import logging
import time
from queue import Queue
from threading import Thread
from typing import List

import pytest
import requests
from hypercorn import Config
from hypercorn.typing import ASGI3Framework
from werkzeug import Request, Response

from localstack.http.asgi import ASGIAdapter
from localstack.http.hypercorn import HypercornServer
from localstack.utils import net
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


@pytest.fixture()
def serve_app():
    _servers = []

    def _create(app: ASGI3Framework, config: Config = None) -> HypercornServer:
        if not config:
            config = Config()
            config.bind = f"localhost:{net.get_free_tcp_port()}"

        srv = HypercornServer(app, config)
        _servers.append(srv)
        srv.start()
        assert srv.wait_is_up(timeout=10), "gave up waiting for server to start up"
        return srv

    yield _create

    for server in _servers:
        server.shutdown()
        assert poll_condition(
            lambda: not server.is_up(), timeout=10
        ), "gave up waiting for server to shut down"


def test_serve_app(serve_app):
    request_list: List[Request] = []

    @Request.application
    def app(request: Request) -> Response:
        request_list.append(request)
        return Response("ok", 200)

    server = serve_app(ASGIAdapter(app))

    response0 = requests.get(server.url + "/foobar?foo=bar", headers={"x-amz-target": "testing"})
    assert response0.ok
    assert response0.text == "ok"

    response1 = requests.get(server.url + "/compute", data='{"foo": "bar"}')
    assert response1.ok
    assert response1.text == "ok"

    request0 = request_list[0]
    assert request0.path == "/foobar"
    assert request0.query_string == b"foo=bar"
    assert request0.full_path == "/foobar?foo=bar"
    assert request0.headers["x-amz-target"] == "testing"
    assert dict(request0.args) == {"foo": "bar"}

    request1 = request_list[1]
    assert request1.path == "/compute"
    assert request1.get_data() == b'{"foo": "bar"}'


def test_requests_are_not_blocking_the_server(serve_app):
    queue = Queue()

    @Request.application
    def app(request: Request) -> Response:
        time.sleep(1)
        queue.put_nowait(request)
        return Response("ok", 200)

    server = serve_app(ASGIAdapter(app))

    then = time.time()

    Thread(target=requests.get, args=(server.url,)).start()
    Thread(target=requests.get, args=(server.url,)).start()
    Thread(target=requests.get, args=(server.url,)).start()
    Thread(target=requests.get, args=(server.url,)).start()

    # get the four responses
    queue.get(timeout=5)
    queue.get(timeout=5)
    queue.get(timeout=5)
    queue.get(timeout=5)

    assert (time.time() - then) < 4, "requests did not seem to be parallelized"


def test_chunked_transfer_encoding_response(serve_app):
    # this test makes sure that creating a response with a generator automatically creates a
    # transfer-encoding=chunked response

    @Request.application
    def app(_request: Request) -> Response:
        def _gen():
            yield "foo"
            yield "bar\n"
            yield "baz\n"

        return Response(_gen(), 200)

    server = serve_app(ASGIAdapter(app))

    response = requests.get(server.url)

    assert response.headers["Transfer-Encoding"] == "chunked"

    it = response.iter_lines()

    assert next(it) == b"foobar"
    assert next(it) == b"baz"


def test_chunked_transfer_encoding_request(serve_app):
    request_list: List[Request] = []

    @Request.application
    def app(request: Request) -> Response:
        request_list.append(request)

        stream = request.stream
        data = bytearray()

        for i, item in enumerate(stream):
            data.extend(item)

            if i == 0:
                assert item == b"foobar\n"
            if i == 1:
                assert item == b"baz"

        return Response(data.decode("utf-8"), 200)

    server = serve_app(ASGIAdapter(app))

    def gen():
        yield b"foo"
        yield b"bar\n"
        yield b"baz"

    response = requests.post(server.url, gen())
    assert response.ok
    assert response.text == "foobar\nbaz"

    assert request_list[0].headers["Transfer-Encoding"].lower() == "chunked"


def test_input_stream_methods(serve_app):
    @Request.application
    def app(request: Request) -> Response:
        assert request.stream.read(1) == b"f"
        assert request.stream.readline(10) == b"ood\n"
        assert request.stream.readline(3) == b"bar"
        assert next(request.stream) == b"ber\n"
        assert request.stream.readlines(3) == [b"fizz\n"]
        assert request.stream.readline() == b"buzz\n"
        assert request.stream.read() == b"really\ndone"
        assert request.stream.read(10) == b""

        return Response("ok", 200)

    server = serve_app(ASGIAdapter(app))

    def gen():
        yield b"fo"
        yield b"od\n"
        yield b"barber\n"
        yield b"fizz\n"
        yield b"buzz\n"
        yield b"really\n"
        yield b"done"

    response = requests.post(server.url, data=gen())
    assert response.ok
    assert response.text == "ok"


def test_input_stream_readlines(serve_app):
    @Request.application
    def app(request: Request) -> Response:
        assert request.stream.readlines() == [b"fizz\n", b"buzz\n", b"done"]
        return Response("ok", 200)

    server = serve_app(ASGIAdapter(app))

    def gen():
        yield b"fizz\n"
        yield b"buzz\n"
        yield b"done"

    response = requests.post(server.url, data=gen())
    assert response.ok
    assert response.text == "ok"


def test_input_stream_readlines_with_limit(serve_app):
    @Request.application
    def app(request: Request) -> Response:
        assert request.stream.readlines(1000) == [b"fizz\n", b"buzz\n", b"done"]
        return Response("ok", 200)

    server = serve_app(ASGIAdapter(app))

    def gen():
        yield b"fizz\n"
        yield b"buzz\n"
        yield b"done"

    response = requests.post(server.url, data=gen())
    assert response.ok
    assert response.text == "ok"


def test_multipart_post(serve_app):
    @Request.application
    def app(request: Request) -> Response:
        assert request.mimetype == "multipart/form-data"

        result = {}
        for k, file_storage in request.files.items():
            result[k] = file_storage.stream.read().decode("utf-8")

        return Response(json.dumps(result), 200)

    server = serve_app(ASGIAdapter(app))

    response = requests.post(server.url, files={"foo": "bar", "baz": "ed"})
    assert response.ok
    assert response.json() == {"foo": "bar", "baz": "ed"}


def test_utf8_path(serve_app):
    @Request.application
    def app(request: Request) -> Response:
        assert request.path == "/foo/Ā0Ä"
        assert request.environ["PATH_INFO"] == "/foo/Ä\x800Ã\x84"

        return Response("ok", 200)

    server = serve_app(ASGIAdapter(app))

    response = requests.get(server.url + "/foo/Ā0Ä")
    assert response.ok
