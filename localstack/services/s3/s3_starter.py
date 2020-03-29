import types
import logging
import traceback
from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.responses import (
    minidom, MalformedXML, undo_clean_key_name
)
from localstack import config
from localstack.constants import DEFAULT_PORT_S3_BACKEND
from localstack.utils.aws import aws_stack
from localstack.services.s3 import s3_listener
from localstack.utils.common import wait_for_port_open
from localstack.services.infra import start_moto_server
from localstack.services.awslambda.lambda_api import BUCKET_MARKER_LOCAL

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
    backend_port = backend_port or DEFAULT_PORT_S3_BACKEND

    apply_patches()

    return start_moto_server(
        key='s3', name='S3', asynchronous=asynchronous,
        port=port, backend_port=backend_port, update_listener=update_listener
    )


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

    # patch Bucket.create_from_cloudformation_json in moto
    @classmethod
    def Bucket_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        result = create_from_cloudformation_json_orig(resource_name, cloudformation_json, region_name)
        # remove the bucket from the backend, as our template_deployer will take care of creating the resource
        resource_name = s3_listener.normalize_bucket_name(resource_name)
        s3_models.s3_backend.buckets.pop(resource_name)
        return result

    create_from_cloudformation_json_orig = s3_models.FakeBucket.create_from_cloudformation_json
    s3_models.FakeBucket.create_from_cloudformation_json = Bucket_create_from_cloudformation_json

    # patch S3Bucket.create_bucket(..)
    def create_bucket(self, bucket_name, region_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        return create_bucket_orig(bucket_name, region_name, *args, **kwargs)

    create_bucket_orig = s3_models.s3_backend.create_bucket
    s3_models.s3_backend.create_bucket = types.MethodType(create_bucket, s3_models.s3_backend)

    # patch S3Bucket.get_bucket(..)
    def get_bucket(self, bucket_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        if bucket_name == BUCKET_MARKER_LOCAL:
            return None
        return get_bucket_orig(bucket_name, *args, **kwargs)

    get_bucket_orig = s3_models.s3_backend.get_bucket
    s3_models.s3_backend.get_bucket = types.MethodType(get_bucket, s3_models.s3_backend)

    # patch S3Bucket.get_bucket(..)
    def delete_bucket(self, bucket_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        return delete_bucket_orig(bucket_name, *args, **kwargs)

    delete_bucket_orig = s3_models.s3_backend.delete_bucket
    s3_models.s3_backend.delete_bucket = types.MethodType(delete_bucket, s3_models.s3_backend)

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
                bucket_name, undo_clean_key_name(key_name), version_id)

            if success:
                deleted_names.append({
                    'key': key_name,
                    'version_id': version_id
                })
            else:
                error_names.append(key_name)

        return (200, {},
            template.render(deleted=deleted_names, delete_errors=error_names))

    s3_responses.S3ResponseInstance._bucket_response_delete_keys = types.MethodType(
        s3_bucket_response_delete_keys, s3_responses.S3ResponseInstance)

    # Patch _handle_range_header(..)
    # https://github.com/localstack/localstack/issues/2146
    s3_response_handle_range_header_orig = s3_responses.S3ResponseInstance._handle_range_header

    def s3_response_handle_range_header(self, request, headers, response_content):
        rs_code, rs_headers, rs_content = s3_response_handle_range_header_orig(request, headers, response_content)
        if rs_code == 206:
            for k in ['ETag', 'last-modified']:
                v = headers.get(k)
                if v and not rs_headers.get(k):
                    rs_headers[k] = v

        return rs_code, rs_headers, rs_content

    s3_responses.S3ResponseInstance._handle_range_header = types.MethodType(
        s3_response_handle_range_header, s3_responses.S3ResponseInstance)
