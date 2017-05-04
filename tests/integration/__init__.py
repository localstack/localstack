import threading
from localstack.mock import infra
from localstack.utils.common import cleanup


def setup_package():
    infra.start_infra(async=True)


def teardown_package():
    print("Shutdown")
    cleanup(files=True)
    infra.stop_infra()
    print("Terminating")
