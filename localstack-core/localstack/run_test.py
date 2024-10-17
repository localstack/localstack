import multiprocessing as mp
import time

from localstack import config
from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.serving.twisted import serve_gateway


def run_twisted_in_process(stop_event: mp.Event):
    gateway = LocalstackAwsGateway()
    srv, shutdown = serve_gateway(gateway, config.GATEWAY_LISTEN, use_ssl=False, asynchronous=True)
    while not stop_event.is_set():
        time.sleep(1)

    shutdown()
    srv.stop()


if __name__ == "__main__":
    processes = []
    ev = mp.Event()
    for _ in range(3):
        p = mp.Process(target=run_twisted_in_process, args=(ev,))
        processes.append(p)

    try:
        for p in processes:
            p.start()
        while True:
            time.sleep(100)

    except KeyboardInterrupt:
        ev.set()
        for p in processes:
            p.join()
