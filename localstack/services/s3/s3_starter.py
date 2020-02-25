import sys
import types
import logging
import traceback
from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.responses import (
    minidom,
    MalformedXML,
    undo_clean_key_name
)
from moto.server import main as moto_main
from localstack import config
from localstack.constants import DEFAULT_PORT_S3_BACKEND
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open
from localstack.services.infra import (
    get_service_protocol, start_proxy_for_service, do_run)
from localstack.utils.bootstrap import setup_logging

LOG = logging.getLogger(__name__)

# max file size for S3 objects (in MB)
S3_MAX_FILE_SIZE_MB = 2048

# temporary state
TMP_STATE = {}


def check_s3(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for port to be opened
        wait_for_port_open(DEFAULT_PORT_S3_BACKEND)
        # check S3
        out = aws_stack.connect_to_service(service_name='s3').list_buckets()
    except Exception as e:
        if print_error:
            LOG.error('S3 health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['Buckets'], list)


def start_s3(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_S3
    backend_port = DEFAULT_PORT_S3_BACKEND
    cmd = '%s "%s" s3 -p %s -H 0.0.0.0' % (sys.executable, __file__, backend_port)
    print('Starting mock S3 (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('s3', port, backend_port, update_listener)
    env_vars = {'PYTHONPATH': ':'.join(sys.path)}
    return do_run(cmd, asynchronous, env_vars=env_vars)


def apply_patches():
    s3_models.DEFAULT_KEY_BUFFER_SIZE = S3_MAX_FILE_SIZE_MB * 1024 * 1024

    def init(self, name, value, storage='STANDARD', etag=None,
            is_versioned=False, version_id=0, max_buffer_size=None, *args, **kwargs):
        return original_init(self, name, value, storage=storage, etag=etag, is_versioned=is_versioned,
            version_id=version_id, max_buffer_size=s3_models.DEFAULT_KEY_BUFFER_SIZE, *args, **kwargs)

    original_init = s3_models.FakeKey.__init__
    s3_models.FakeKey.__init__ = init

    def s3_update_acls(self, request, query, bucket_name, key_name):
        # fix for - https://github.com/localstack/localstack/issues/1733
        #         - https://github.com/localstack/localstack/issues/1170
        acl_key = 'acl|%s|%s' % (bucket_name, key_name)
        acl = self._acl_from_headers(request.headers)
        if acl:
            TMP_STATE[acl_key] = acl
        if not query.get('uploadId'):
            return
        bucket = self.backend.get_bucket(bucket_name)
        key = bucket and self.backend.get_key(bucket_name, key_name)
        if not key:
            return
        acl = acl or TMP_STATE.pop(acl_key, None) or bucket.acl
        if acl:
            key.set_acl(acl)

    # patch _key_response_post(..)

    def s3_key_response_post(self, request, body, bucket_name, query, key_name, *args, **kwargs):
        result = s3_key_response_post_orig(request, body, bucket_name, query, key_name, *args, **kwargs)
        s3_update_acls(self, request, query, bucket_name, key_name)
        return result

    s3_key_response_post_orig = s3_responses.S3ResponseInstance._key_response_post
    s3_responses.S3ResponseInstance._key_response_post = types.MethodType(
        s3_key_response_post, s3_responses.S3ResponseInstance)

    # patch _key_response_put(..)

    def s3_key_response_put(self, request, body, bucket_name, query, key_name, headers, *args, **kwargs):
        result = s3_key_response_put_orig(request, body, bucket_name, query, key_name, headers, *args, **kwargs)
        s3_update_acls(self, request, query, bucket_name, key_name)
        return result

    s3_key_response_put_orig = s3_responses.S3ResponseInstance._key_response_put
    s3_responses.S3ResponseInstance._key_response_put = types.MethodType(
        s3_key_response_put, s3_responses.S3ResponseInstance)

    # patch DeleteObjectTagging

    def s3_key_response_delete(self, bucket_name, query, key_name, *args, **kwargs):
        # Fixes https://github.com/localstack/localstack/issues/1083
        if query.get('tagging'):
            self._set_action('KEY', 'DELETE', query)
            self._authenticate_and_authorize_s3_action()
            key = self.backend.get_key(bucket_name, key_name)
            key.tags = s3_models.FakeTagging()
            return 204, {}, ''
        result = s3_key_response_delete_orig(bucket_name, query, key_name, *args, **kwargs)
        return result

    s3_key_response_delete_orig = s3_responses.S3ResponseInstance._key_response_delete
    s3_responses.S3ResponseInstance._key_response_delete = types.MethodType(
        s3_key_response_delete, s3_responses.S3ResponseInstance)
    s3_responses.ACTION_MAP['KEY']['DELETE']['tagging'] = 'DeleteObjectTagging'

    # patch max-keys

    def s3_truncate_result(self, result_keys, max_keys):
        return s3_truncate_result_orig(result_keys, max_keys or 1000)

    s3_truncate_result_orig = s3_responses.S3ResponseInstance._truncate_result
    s3_responses.S3ResponseInstance._truncate_result = types.MethodType(
        s3_truncate_result, s3_responses.S3ResponseInstance)

    # patch _bucket_response_delete_keys(..)
    # https://github.com/localstack/localstack/issues/2077

    s3_delete_keys_response_template = """<?xml version="1.0" encoding="UTF-8"?>
    <DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">
    {% for k in deleted %}
    <Deleted>
    <Key>{{k.key}}</Key>
    <VersionId>{{k.version_id}}</VersionId>
    </Deleted>
    {% endfor %}
    {% for k in delete_errors %}
    <Error>
    <Key>{{k}}</Key>
    </Error>
    {% endfor %}
    </DeleteResult>"""

    def s3_bucket_response_delete_keys(self, request, body, bucket_name):
        template = self.response_template(s3_delete_keys_response_template)

        elements = minidom.parseString(body).getElementsByTagName('Object')
        if len(elements) == 0:
            raise MalformedXML()

        deleted_names = []
        error_names = []

        keys = []
        for element in elements:
            if len(element.getElementsByTagName('VersionId')) == 0:
                version_id = None
            else:
                version_id = element.getElementsByTagName('VersionId')[0].firstChild.nodeValue

            keys.append({
                'key_name': element.getElementsByTagName('Key')[0].firstChild.nodeValue,
                'version_id': version_id
            })

        for k in keys:
            key_name = k['key_name']
            version_id = k['version_id']
            success = self.backend.delete_key(
                bucket_name, undo_clean_key_name(key_name), version_id
            )

            if success:
                deleted_names.append({
                    'key': key_name,
                    'version_id': version_id
                })
            else:
                error_names.append(key_name)

        return (
            200,
            {},
            template.render(deleted=deleted_names, delete_errors=error_names),
        )

    s3_responses.S3ResponseInstance._bucket_response_delete_keys = types.MethodType(
        s3_bucket_response_delete_keys, s3_responses.S3ResponseInstance
    )


def main():
    setup_logging()
    # patch moto implementation
    apply_patches()
    # start API
    sys.exit(moto_main())


if __name__ == '__main__':
    main()
