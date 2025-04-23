import json
import multiprocessing as mp
import os
import socket
import sys
import time
from typing import IO

from orjson import orjson
from twisted.internet.tcp import Port

from localstack.aws.api import ServiceException
from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.skeleton import (
    FakeOperation,
    FakeRequest,
    FakeService,
    JsonContext,
    create_dispatch_table,
)
from localstack.config import HostAndPort
from localstack.services.moto import MotoFallbackDispatcher
from localstack.services.s3.storage import LimitedIterableStream
from localstack.utils.patch import patch

from .twisted import serve_gateway


class StreamingBody(IO):
    def __init__(self, body: IO[bytes], length: int):
        self.body = body
        self.length = length

    def read(self, n=0) -> bytes:
        return self.body.read(n or self.length or -1)

    def writable(self):
        return False


class ServiceWsgiApp:
    def __init__(self, provider, dispatch_table_factory):
        self.provider = provider
        self._dispatch_table = dispatch_table_factory(provider)

    def _invoke_orjson(self, body: StreamingBody, payload: bytes, streaming_body: str):
        req = orjson.loads(payload)
        context = JsonContext(**req["context"])
        context.service = FakeService(**context.service)
        context.operation = FakeOperation(**context.operation)
        context.request = FakeRequest(**context.request)
        context.request.query_string = context.request.query_string.encode("utf-8")
        if streaming_body:
            req["instance"][streaming_body] = body

        instance = req["instance"]
        handler = self._dispatch_table[context.operation.name]
        stream_response = None
        stream_key = None
        try:
            response = {"response": handler(context, instance)}
            for key, value in response["response"].items():
                if hasattr(value, "read") or isinstance(value, LimitedIterableStream):
                    stream_key = key
                    stream_response = value
                    response["response"].pop(key)
                    break
        except ServiceException as e:
            # we could serialize something somewhat here?
            response = {"error": e.to_dict()}
        return json.dumps(response), stream_key, stream_response

    def __call__(self, environ, start_response):
        content_length = environ.get("CONTENT_LENGTH", 0)
        body = StreamingBody(environ["wsgi.input"], content_length)
        payload = environ["HTTP_AWS_PAYLOAD"]
        stream_field = environ.get("HTTP_STREAM_FIELD")
        _invoke_result, stream_key, stream_body = self._invoke_orjson(body, payload, stream_field)
        status = "200 OK"
        response_headers = [
            ("Content-type", "application/json"),
            ("Response-Payload", _invoke_result),
        ]
        if stream_key:
            response_headers.append(("Response-Key", stream_key))
        start_response(status, response_headers)
        if stream_key:
            return stream_body
        else:
            return [b""]


def wsgi_app():
    service_name = os.environ.get("SERVICE")
    if not service_name:
        raise ValueError("No service name set")
    match service_name:
        case "sqs":
            from localstack.services.sqs.provider import SqsProvider

            provider = SqsProvider()
        case "dynamodb":
            from localstack.services.dynamodb.provider import DynamoDBProvider

            provider = DynamoDBProvider()
        case "s3":
            from localstack.services.s3.provider import S3Provider

            provider = S3Provider()
        case "sns":
            from localstack.services.sns.provider import SnsProvider

            provider = SnsProvider()
        case _:
            raise ValueError(f"Unknown service name {service_name}")
    if hasattr(provider, "on_after_init"):
        provider.on_after_init()
    if hasattr(provider, "on_before_start"):
        provider.on_before_start()
    if service_name in {"sns"}:
        dispatch_table_factory = MotoFallbackDispatcher
    else:
        dispatch_table_factory = create_dispatch_table
    return ServiceWsgiApp(provider, dispatch_table_factory=dispatch_table_factory)


@patch(target=Port.createInternetSocket)
def _twisted_create_internet_socket(fn, *args, **kwargs):
    s = fn(*args, **kwargs)
    # this is good, but doesn't work on macOS/BSD: only the last process gets the requests... :(
    if sys.platform != "darwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return s


def run_twisted_in_process(stop_event: mp.Event, port: int):
    gateway = LocalstackAwsGateway()
    listen = HostAndPort("0.0.0.0", port)
    srv, shutdown = serve_gateway(gateway, [listen], use_ssl=False, asynchronous=True)
    print(f"Process {os.getpid()} listens on {listen.port}")
    stop_event.wait()

    shutdown()
    srv.stop()


if __name__ == "__main__":
    is_macos = sys.platform == "darwin"
    processes = []
    ev = mp.Event()
    if is_macos:
        start_port = 4567
    else:
        start_port = 4566

    for i in range(10):
        proc_port = start_port + i if is_macos else start_port
        p = mp.Process(target=run_twisted_in_process, args=(ev, proc_port))
        processes.append(p)

    try:
        for p in processes:
            p.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ev.set()
        for p in processes:
            p.join()
