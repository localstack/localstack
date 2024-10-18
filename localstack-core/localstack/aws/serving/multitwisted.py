import asyncio
import dataclasses
import itertools
import json
import multiprocessing as mp
import os
import socket
import sys
import time

import nats
from orjson import orjson
from rolo.gateway.asgi import _ThreadPool
from twisted.internet.tcp import Port

from localstack.aws.api import RequestContext, ServiceException
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


def run_twisted_in_process(stop_event: mp.Event, port: int):
    counter = itertools.count()

    def call_count():
        return next(counter)

    loop = asyncio.new_event_loop()
    gateway = LocalstackAwsGateway()

    def _add_loop_context(_, context: RequestContext, __):
        context._loop = loop
        call_count()

    gateway.request_handlers.insert(0, _add_loop_context)
    listen = HostAndPort("0.0.0.0", port)
    srv, shutdown = serve_gateway(gateway, [listen], use_ssl=False, asynchronous=True)
    print(f"Process {os.getpid()} listens on {listen.port}")

    async def _run():
        while not stop_event.is_set():
            # print(os.getpid(), port, call_count())
            await asyncio.sleep(1)

    loop.run_until_complete(_run())

    shutdown()
    srv.stop()


@patch(target=Port.createInternetSocket)
def _twisted_create_internet_socket(fn, *args, **kwargs):
    s = fn(*args, **kwargs)
    # this is good, but doesn't work on macOS/BSD: only the last process gets the requests... :(
    if sys.platform != "darwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return s


def run_sqs_service_in_process(stop_event: mp.Event):
    provider = SqsProvider()
    _dispatch_table = create_dispatch_table(provider)
    executor = _ThreadPool(5000, thread_name_prefix="sqs_srv")

    # def _invoke_json(payload: bytes):
    #     req = json.loads(payload)
    #     handler = _dispatch_table[req["op_name"]]
    #     response = handler(RequestContext(), req["payload"])
    #     return json.dumps(response).encode("utf-8")

    # @log_duration(min_ms=0)
    # def _invoke_dill(payload: bytes):
    # req = dill.loads(payload)
    # context = req["context"]
    # instance = req["instance"]
    # handler = _dispatch_table[context.operation.name]
    # try:
    #     response = handler(context, instance)
    # except ServiceException:
    #     response = {"Error": "exception"}
    # return json.dumps({}).encode("utf-8")

    # @log_duration(min_ms=0)
    def _invoke_orjson(payload: bytes):
        req = orjson.loads(payload)
        context = JsonContext(**req["context"], request=fake_req)
        context.service = FakeService(**context.service)
        context.operation = FakeOperation(**context.operation)

        instance = req["instance"]
        handler = _dispatch_table[context.operation.name]
        try:
            response = handler(context, instance)
        except ServiceException:
            # we could serialize something somewhat here?
            response = {"Error": "exception"}
        return json.dumps(response).encode("utf-8")

    async def main():
        nc = await nats.connect("nats://localhost:4222")

        async def invoke(msg):
            response = await loop.run_in_executor(executor, _invoke_orjson, msg.data)
            # response = _invoke_dill(msg.data)
            # response = _invoke_orjson(msg.data)

            await msg.respond(response)

        sub = await nc.subscribe("services.sqs", cb=invoke)
        print(f"Subbed! {sub=}")

        while not stop_event.is_set():
            await asyncio.sleep(1)

        await sub.unsubscribe()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())

    executor.shutdown(wait=False, cancel_futures=True)


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

    service_p = mp.Process(target=run_sqs_service_in_process, args=(ev,))
    processes.append(service_p)

    try:
        for p in processes:
            p.start()
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        ev.set()
        for p in processes:
            p.join()
