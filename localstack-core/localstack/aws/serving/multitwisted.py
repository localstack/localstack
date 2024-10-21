import asyncio
import dataclasses
import itertools
import json
import multiprocessing as mp
import os
import socket
import sys
import textwrap
import time

import nats
from orjson import orjson
from rolo.gateway.asgi import _ThreadPool
from twisted.internet.tcp import Port

from localstack.aws.api import RequestContext
from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.skeleton import create_dispatch_table
from localstack.config import HostAndPort
from localstack.services.sqs.provider import SqsProvider
from localstack.utils.files import new_tmp_file
from localstack.utils.net import wait_for_port_open
from localstack.utils.patch import patch
from localstack.utils.run import ShellCommandThread

from .twisted import serve_gateway

MIXCTL_PATH = "/Users/benjaminsimon/Projects/localstack-utils/mixctl/mixctl"


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

        # instance = req["instance"]
        # handler = _dispatch_table[context.operation.name]
        # try:
        #     response = handler(context, instance)
        # except ServiceException:
        #     # we could serialize something somewhat here?
        #     response = {"Error": "exception"}
        response = {
            "MessageId": "cfcd8be4-7d9e-42c4-965f-ada0d77c3779",
            "MD5OfMessageBody": "99914b932bd37a50b983c5e7c90ae93b",
            "MD5OfMessageAttributes": None,
            "SequenceNumber": None,
            "MD5OfMessageSystemAttributes": None,
        }
        return json.dumps(response).encode("utf-8")

    async def main():
        nc = await nats.connect("nats://localhost:4222")

        async def invoke(msg):
            # response = await loop.run_in_executor(executor, _invoke_orjson, msg.data)
            # response = _invoke_dill(msg.data)
            response = _invoke_orjson(msg.data)

            await msg.respond(response)

        sub = await nc.subscribe("services.sqs", queue="sqs.workers", cb=invoke)
        print(f"Subbed! {sub=}")

        while not stop_event.is_set():
            await asyncio.sleep(1)

        await sub.unsubscribe()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())

    executor.shutdown(wait=False, cancel_futures=True)


def create_nats_server() -> ShellCommandThread:
    nats_thread = ShellCommandThread(
        ["nats-server"],
        strip_color=True,
        auto_restart=True,
        name="nats",
    )
    return nats_thread


def create_mixctl_load_balancer(_start_port: int, num_ports: int) -> ShellCommandThread:
    # /Users/benjaminsimon/Projects/localstack-utils/mixctl/mixctl

    # create config files with ports
    base_mixctl_cfg = textwrap.dedent("""
    version: 0.1
    rules:
    - name: localstack
      from: 127.0.0.1:4566
      to:
    """)
    mixctl_cfg = base_mixctl_cfg + "".join(
        [f"    - 127.0.0.1:{_port}\n" for _port in range(_start_port, _start_port + num_ports)]
    )
    tmp_path = new_tmp_file(suffix="mixctl-cfg")
    with open(tmp_path, "w") as fp:
        fp.write(mixctl_cfg)

    mixctl_thread = ShellCommandThread(
        [MIXCTL_PATH, "-f", tmp_path],
        strip_color=True,
        auto_restart=True,
        name="mixctl",
    )
    return mixctl_thread


if __name__ == "__main__":
    is_macos = sys.platform == "darwin"
    processes = []
    threads = []
    ev = mp.Event()
    proc_amount = 8
    if is_macos:
        start_port = 4567
    else:
        start_port = 4566

    nats = create_nats_server()
    threads.append(nats)
    nats.start()
    try:
        wait_for_port_open(4222)
    except Exception:
        nats.stop()
        exit()

    for i in range(proc_amount):
        proc_port = start_port + i if is_macos else start_port
        p = mp.Process(target=run_twisted_in_process, args=(ev, proc_port))
        processes.append(p)

    for _ in range(3):
        service_p = mp.Process(target=run_sqs_service_in_process, args=(ev,))
        processes.append(service_p)

    if is_macos:
        mixctl = create_mixctl_load_balancer(start_port, proc_amount)
        threads.append(mixctl)
        mixctl.start()
        try:
            wait_for_port_open(4566)
        except Exception:
            nats.stop()
            mixctl.stop()
            exit()

    try:
        for p in processes:
            p.start()
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        ev.set()
        for t in threads:
            t.stop()
            t.join()

        for p in processes:
            p.join()
