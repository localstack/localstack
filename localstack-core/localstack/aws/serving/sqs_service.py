import argparse
import asyncio
import dataclasses
import json
import multiprocessing as mp
import time

import nats
from orjson import orjson
from rolo.gateway.asgi import _ThreadPool

from localstack.aws.api import ServiceException
from localstack.aws.skeleton import create_dispatch_table
from localstack.services.sqs.provider import SqsProvider
from localstack.utils.net import wait_for_port_open
from localstack.utils.run import ShellCommandThread


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


def run_sqs_service_in_process(stop_event: mp.Event, **kwargs):
    provider = SqsProvider()
    _dispatch_table = create_dispatch_table(provider)
    executor = _ThreadPool(5000, thread_name_prefix="sqs_srv")
    account_id = kwargs.get("account_id")

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

        # response = {
        #     "MessageId": "cfcd8be4-7d9e-42c4-965f-ada0d77c3779",
        #     "MD5OfMessageBody": "99914b932bd37a50b983c5e7c90ae93b",
        #     "MD5OfMessageAttributes": None,
        #     "SequenceNumber": None,
        #     "MD5OfMessageSystemAttributes": None,
        # }
        return json.dumps(response).encode("utf-8")

    async def main():
        nc = await nats.connect("nats://localhost:4222")

        async def invoke(msg):
            response = await loop.run_in_executor(executor, _invoke_orjson, msg.data)
            # response = _invoke_dill(msg.data)
            # response = _invoke_orjson(msg.data)

            await msg.respond(response)

        subject = f"services.sqs.{account_id}" if account_id else "services.sqs.>"
        _queue = None if account_id else "sqs.workers"
        sub = await nc.subscribe(subject, queue=_queue, cb=invoke)
        print(f"Subbed! {sub.subject=} / {sub.queue=}")

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--worker", required=False, default=1, type=int)
    parser.add_argument("-n", "--nats", action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    start_nats = args.nats
    service_amount = args.worker

    processes = []
    threads = []
    ev = mp.Event()
    if start_nats:
        nats = create_nats_server()
        threads.append(nats)
        nats.start()

        try:
            wait_for_port_open(4222)
        except Exception:
            nats.stop()
            exit()

    for _ in range(service_amount):
        service_p = mp.Process(target=run_sqs_service_in_process, args=(ev,))
        processes.append(service_p)

    # Account Id sharding per process

    # account_ids = [
    #     "000000000000",
    #     "000000000001",
    #     "000000000002",
    # ]
    # for acc_id in account_ids:
    #     service_p = mp.Process(
    #         target=run_sqs_service_in_process, args=(ev,), kwargs={"account_id": acc_id}
    #     )
    #     processes.append(service_p)

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

# DISABLE_EVENTS=1 LS_LOG=warning SQS_DISABLE_CLOUDWATCH_METRICS=1 SERVICES=sqs python -m localstack.aws.serving.sqs_service -w 1
