import sys
import threading
import logging
from localstack.mock import infra
from localstack.utils.common import cleanup


def setup_package():
    try:
        infra.start_infra(async=True)
    except Exception as e:
        # make sure to tear down the infrastructure
        infra.stop_infra()
        raise e


def teardown_package():
    print("Shutdown")
    cleanup(files=True)
    infra.stop_infra()
