import dataclasses
import json
import multiprocessing as mp
import os
import socket
import sys
import time

from orjson import orjson
from twisted.internet.tcp import Port

from localstack.aws.api import ServiceException
from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.skeleton import create_dispatch_table
from localstack.config import HostAndPort
from localstack.services.sqs.provider import SqsProvider
from localstack.utils.patch import patch

from .twisted import serve_gateway


@dataclasses.dataclass
class FakeRequest:
    scheme: str


fake_req = FakeRequest(scheme="http")


@dataclasses.dataclass
class FakeOperation:
    name: str


@dataclasses.dataclass
class FakeService:
    protocol: str


@dataclasses.dataclass
class JsonContext:
    account_id: str
    region: str
    request_id: str
    partition: str
    operation: FakeOperation
    service: FakeService
    request: FakeRequest


class ServiceWsgiApp:
    def __init__(self, provider):
        self.provider = provider
        self._dispatch_table = create_dispatch_table(provider)

    def _invoke_orjson(self, payload: bytes):
        req = orjson.loads(payload)
        # context = JsonContext(**req["context"], request=fake_req)
        # context.service = FakeService(**context.service)
        # context.operation = FakeOperation(**context.operation)

        # instance = req["instance"]
        # handler = self._dispatch_table[context.operation.name]
        try:
            response = {"response": {}}
        except ServiceException as e:
            # we could serialize something somewhat here?
            response = {"error": e.to_dict()}
        return json.dumps(response).encode("utf-8")

    def __call__(self, environ, start_response):
        content_length = int(environ["CONTENT_LENGTH"])
        input = environ["wsgi.input"].read(content_length)
        _invoke_result = self._invoke_orjson(input)
        status = "200 OK"
        response_headers = [("Content-type", "application/json")]
        start_response(status, response_headers)
        return [_invoke_result]


def wsgi_app():
    provider = SqsProvider()
    # provider.on_after_init()
    # provider.on_before_start()
    return ServiceWsgiApp(provider)


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
