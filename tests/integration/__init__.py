import os
from localstack.constants import ENV_INTERNAL_TEST_RUN
from localstack.services import infra
from localstack.utils.common import cleanup, safe_requests


def setup_package():
    try:
        os.environ[ENV_INTERNAL_TEST_RUN] = '1'
        # disable SSL verification for local tests
        safe_requests.verify_ssl = False
        # start infrastructure services
        infra.start_infra(async=True)
    except Exception as e:
        # make sure to tear down the infrastructure
        infra.stop_infra()
        raise e


def teardown_package():
    print("Shutdown")
    cleanup(files=True)
    infra.stop_infra()
