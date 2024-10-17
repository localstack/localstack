import multiprocessing as mp
import socket
import threading
import time

import rpyc
from twisted.internet.tcp import Port

from localstack import config
from localstack.aws.api import RequestContext, ServiceRequest
from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.skeleton import create_dispatch_table
from localstack.services.sqs.provider import SqsProvider
from localstack.utils.patch import patch

from .twisted import serve_gateway


def run_twisted_in_process(stop_event: mp.Event):
    gateway = LocalstackAwsGateway()
    srv, shutdown = serve_gateway(gateway, config.GATEWAY_LISTEN, use_ssl=False, asynchronous=True)
    while not stop_event.is_set():
        time.sleep(1)

    shutdown()
    srv.stop()


@patch(target=Port.createInternetSocket)
def _twisted_create_internet_socket(fn, *args, **kwargs):
    s = fn(*args, **kwargs)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return s


@rpyc.service
class SQSService(rpyc.Service):
    def __init__(self):
        self._provider = SqsProvider()
        self._dispatch_table = create_dispatch_table(self._provider)

    @rpyc.exposed
    def invoke(self, context: RequestContext, instance: ServiceRequest):
        handler = self._dispatch_table[context.operation.name]
        return handler(context, instance) or {}


def run_service_in_process(stop_event: mp.Event):
    server = rpyc.ThreadedServer(
        SQSService(), port=12000, protocol_config={"allow_public_attrs": True}
    )
    t = threading.Thread(target=server.start)
    t.start()
    while not stop_event.is_set():
        time.sleep(1)

    server.close()
    t.join()


if __name__ == "__main__":
    processes = []
    ev = mp.Event()
    for _ in range(3):
        p = mp.Process(target=run_twisted_in_process, args=(ev,))
        processes.append(p)

    service_p = mp.Process(target=run_service_in_process, args=(ev,))
    processes.append(service_p)

    try:
        for p in processes:
            p.start()
        while True:
            time.sleep(100)

    except KeyboardInterrupt:
        ev.set()
        for p in processes:
            p.join()
