import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Thread
from typing import List

import pytest
import requests
from werkzeug import Request, Response

from localstack.http.asgi import ASGILifespanListener

LOG = logging.getLogger(__name__)


def test_serve_asgi_adapter(serve_asgi_adapter):
    request_list: List[Request] = []

    @Request.application
    def app(request: Request) -> Response:
        request_list.append(request)
        return Response("ok", 200)

    server = serve_asgi_adapter(app)

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


def test_requests_are_not_blocking_the_server(serve_asgi_adapter):
    queue = Queue()

    @Request.application
    def app(request: Request) -> Response:
        time.sleep(1)
        queue.put_nowait(request)
        return Response("ok", 200)

    server = serve_asgi_adapter(app)

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


def test_chunked_transfer_encoding_response(serve_asgi_adapter):
    # this test makes sure that creating a response with a generator automatically creates a
    # transfer-encoding=chunked response

    @Request.application
    def app(_request: Request) -> Response:
        def _gen():
            yield "foo"
            yield "bar\n"
            yield "baz\n"

        return Response(_gen(), 200)

    server = serve_asgi_adapter(app)

    response = requests.get(server.url)

    assert response.headers["Transfer-Encoding"] == "chunked"

    it = response.iter_lines()

    assert next(it) == b"foobar"
    assert next(it) == b"baz"


def test_chunked_transfer_encoding_client_timeout(serve_asgi_adapter):
    # this test makes sure that creating a response with a generator automatically creates a
    # transfer-encoding=chunked response

    generator_exited = threading.Event()
    continue_request = threading.Event()

    @Request.application
    def app(_request: Request) -> Response:
        def _gen():
            try:
                yield "foo"
                yield "bar\n"
                continue_request.wait()
                # only three are needed, let's send some more to make sure
                for _ in range(10):
                    yield "baz\n"
            except GeneratorExit:
                generator_exited.set()

        return Response(_gen(), 200)

    server = serve_asgi_adapter(app)

    with requests.get(server.url, stream=True) as response:
        assert response.headers["Transfer-Encoding"] == "chunked"

        it = response.iter_lines()

        assert next(it) == b"foobar"

    # request is now closed, continue the response generator
    continue_request.set()
    # this flag is only set when generator is exited
    assert generator_exited.wait(timeout=10)


def test_chunked_transfer_encoding_request(serve_asgi_adapter):
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

    server = serve_asgi_adapter(app)

    def gen():
        yield b"foo"
        yield b"bar\n"
        yield b"baz"

    response = requests.post(server.url, gen())
    assert response.ok
    assert response.text == "foobar\nbaz"

    assert request_list[0].headers["Transfer-Encoding"].lower() == "chunked"


def test_close_iterable_response(serve_asgi_adapter):
    class IterableResponse:
        def __init__(self, data: list[bytes]):
            self.data = data
            self.closed = False

        def __iter__(self):
            for packet in self.data:
                yield packet

        def close(self):
            # should be called through the werkzeug layers
            self.closed = True

    iterable = IterableResponse([b"foo", b"bar"])

    @Request.application
    def app(request: Request) -> Response:
        return Response(iterable, 200)

    server = serve_asgi_adapter(app)

    response = requests.get(server.url, stream=True)

    gen = response.iter_content(chunk_size=3)
    assert next(gen) == b"foo"
    assert next(gen) == b"bar"
    assert not iterable.closed

    with pytest.raises(StopIteration):
        next(gen)

    assert iterable.closed


def test_input_stream_methods(serve_asgi_adapter):
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

    server = serve_asgi_adapter(app)

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


def test_input_stream_readlines(serve_asgi_adapter):
    @Request.application
    def app(request: Request) -> Response:
        assert request.stream.readlines() == [b"fizz\n", b"buzz\n", b"done"]
        return Response("ok", 200)

    server = serve_asgi_adapter(app)

    def gen():
        yield b"fizz\n"
        yield b"buzz\n"
        yield b"done"

    response = requests.post(server.url, data=gen())
    assert response.ok
    assert response.text == "ok"


def test_input_stream_readlines_with_limit(serve_asgi_adapter):
    @Request.application
    def app(request: Request) -> Response:
        assert request.stream.readlines(1000) == [b"fizz\n", b"buzz\n", b"done"]
        return Response("ok", 200)

    server = serve_asgi_adapter(app)

    def gen():
        yield b"fizz\n"
        yield b"buzz\n"
        yield b"done"

    response = requests.post(server.url, data=gen())
    assert response.ok
    assert response.text == "ok"


def test_multipart_post(serve_asgi_adapter):
    @Request.application
    def app(request: Request) -> Response:
        assert request.mimetype == "multipart/form-data"

        result = {}
        for k, file_storage in request.files.items():
            result[k] = file_storage.stream.read().decode("utf-8")

        return Response(json.dumps(result), 200)

    server = serve_asgi_adapter(app)

    response = requests.post(server.url, files={"foo": "bar", "baz": "ed"})
    assert response.ok
    assert response.json() == {"foo": "bar", "baz": "ed"}


def test_multipart_post_large_payload(serve_asgi_adapter):
    @Request.application
    def app(request: Request) -> Response:
        try:
            assert request.mimetype == "multipart/form-data"

            result = {}
            for k, file_storage in request.files.items():
                result[k] = len(file_storage.stream.read())

            return Response(json.dumps(result), 200)
        except Exception:
            LOG.exception("error")
            raise

    server = serve_asgi_adapter(app)

    payload = (
        "\0" * 70_000
    )  # there's a chunk size of 65536 configured in werkzeug which is what we're testing here

    response = requests.post(server.url, files={"file": payload})
    assert response.ok
    assert response.json() == {"file": 70_000}


def test_utf8_path(serve_asgi_adapter):
    @Request.application
    def app(request: Request) -> Response:
        assert request.path == "/foo/Ā0Ä"
        assert request.environ["PATH_INFO"] == "/foo/Ä\x800Ã\x84"

        return Response("ok", 200)

    server = serve_asgi_adapter(app)

    response = requests.get(server.url + "/foo/Ā0Ä")
    assert response.ok


def test_serve_multiple_apps(serve_asgi_adapter):
    @Request.application
    def app0(request: Request) -> Response:
        return Response("ok0", 200)

    @Request.application
    def app1(request: Request) -> Response:
        return Response("ok1", 200)

    server0 = serve_asgi_adapter(app0)
    server1 = serve_asgi_adapter(app1)

    executor = ThreadPoolExecutor(6)

    response0_ftr = executor.submit(requests.get, server0.url)
    response1_ftr = executor.submit(requests.get, server1.url)
    response2_ftr = executor.submit(requests.get, server0.url)
    response3_ftr = executor.submit(requests.get, server1.url)
    response4_ftr = executor.submit(requests.get, server0.url)
    response5_ftr = executor.submit(requests.get, server1.url)

    executor.shutdown()

    result0 = response0_ftr.result(timeout=2)
    assert result0.ok
    assert result0.text == "ok0"
    result1 = response1_ftr.result(timeout=2)
    assert result1.ok
    assert result1.text == "ok1"
    result2 = response2_ftr.result(timeout=2)
    assert result2.ok
    assert result2.text == "ok0"
    result3 = response3_ftr.result(timeout=2)
    assert result3.ok
    assert result3.text == "ok1"
    result4 = response4_ftr.result(timeout=2)
    assert result4.ok
    assert result4.text == "ok0"
    result5 = response5_ftr.result(timeout=2)
    assert result5.ok
    assert result5.text == "ok1"


def test_lifespan_listener(serve_asgi_adapter):
    events = Queue()

    @Request.application
    def app(request: Request) -> Response:
        events.put("request")
        return Response("ok", 200)

    class LifespanListener(ASGILifespanListener):
        def on_startup(self):
            events.put("startup")

        def on_shutdown(self):
            events.put("shutdown")

    listener = LifespanListener()

    server = serve_asgi_adapter(app, listener)

    assert events.get(timeout=5) == "startup"
    assert events.qsize() == 0

    assert requests.get(server.url).ok

    assert events.get(timeout=5) == "request"
    assert events.qsize() == 0

    server.shutdown()

    assert events.get(timeout=5) == "shutdown"
    assert events.qsize() == 0
