import logging
import traceback
from localstack.constants import DEFAULT_PORT_S3_BACKEND
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open

LOGGER = logging.getLogger(__name__)


def check_s3(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for port to be opened
        wait_for_port_open(DEFAULT_PORT_S3_BACKEND)
        # check S3
        out = aws_stack.connect_to_service(service_name='s3').list_buckets()
    except Exception as e:
        if print_error:
            LOGGER.error('S3 health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['Buckets'], list)
