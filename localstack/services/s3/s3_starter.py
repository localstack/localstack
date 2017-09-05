import logging
import traceback
from localstack.utils.aws import aws_stack

LOGGER = logging.getLogger(__name__)


def check_s3(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check S3
        out = aws_stack.connect_to_service(service_name='s3').list_buckets()
    except Exception as e:
        if print_error:
            LOGGER.error('S3 health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['Buckets'], list)
