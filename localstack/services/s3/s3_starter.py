import sys
import logging
import traceback
from moto.s3 import models as s3_models
from moto.server import main as moto_main
from localstack import config
from localstack.constants import DEFAULT_PORT_S3_BACKEND
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open
from localstack.services.infra import (
    get_service_protocol, start_proxy_for_service, do_run, setup_logging)

LOGGER = logging.getLogger(__name__)

# max file size for S3 objects (in MB)
S3_MAX_FILE_SIZE_MB = 128


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


def start_s3(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_S3
    backend_port = DEFAULT_PORT_S3_BACKEND
    cmd = 'python "%s" s3 -p %s -H 0.0.0.0' % (__file__, backend_port)
    print('Starting mock S3 (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('s3', port, backend_port, update_listener)
    env_vars = {'PYTHONPATH': ':'.join(sys.path)}
    return do_run(cmd, asynchronous, env_vars=env_vars)


def apply_patches():
    s3_models.DEFAULT_KEY_BUFFER_SIZE = S3_MAX_FILE_SIZE_MB * 1024 * 1024

    def init(self, name, value, storage='STANDARD', etag=None, is_versioned=False, version_id=0, max_buffer_size=None):
        return original_init(self, name, value, storage=storage, etag=etag, is_versioned=is_versioned,
            version_id=version_id, max_buffer_size=s3_models.DEFAULT_KEY_BUFFER_SIZE)

    original_init = s3_models.FakeKey.__init__
    s3_models.FakeKey.__init__ = init


def main():
    setup_logging()
    # patch moto implementation
    apply_patches()
    # start API
    sys.exit(moto_main())


if __name__ == '__main__':
    main()
