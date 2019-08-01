import os
import signal
import threading
from localstack import config
from localstack.services import infra
from localstack.constants import ENV_INTERNAL_TEST_RUN
from localstack.utils.common import cleanup, safe_requests, FuncThread
from localstack.utils.analytics.profiler import profiled

mutex = threading.Semaphore(0)


def setup_package():
    try:
        os.environ[ENV_INTERNAL_TEST_RUN] = '1'
        # disable SSL verification for local tests
        safe_requests.verify_ssl = False
        # start profiling
        FuncThread(start_profiling).start()
        # start infrastructure services
        infra.start_infra(asynchronous=True)
    except Exception as e:
        # make sure to tear down the infrastructure
        infra.stop_infra()
        raise e


def teardown_package():
    print('Shutdown')
    mutex.release()
    cleanup(files=True)
    infra.stop_infra()


def start_profiling(*args):
    if not config.USE_PROFILER:
        return

    @profiled()
    def profile_func():
        # keep profiler active until tests have finished
        mutex.acquire()

    print('Start profiling...')
    profile_func()
    print('Done profiling...')


def signal_handler(sig, frame):
    try:
        teardown_package()
    finally:
        raise KeyboardInterrupt()


signal.signal(signal.SIGINT, signal_handler)
