import logging
import os
import types
from urllib.parse import urlparse

from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.exceptions import S3ClientError
from moto.s3.responses import S3_ALL_MULTIPARTS, MalformedXML, is_delete_keys, minidom
from moto.s3.utils import undo_clean_key_name
from moto.s3bucket_path import utils as s3bucket_path_utils

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.services.s3 import s3_listener, s3_utils
from localstack.utils.aws import aws_stack
from localstack.utils.common import get_free_tcp_port, wait_for_port_open
from localstack.utils.generic.dict_utils import get_safe
from localstack.utils.server import multiserver

LOG = logging.getLogger(__name__)

# max file size for S3 objects kept in memory (500 KB by default)
S3_MAX_FILE_SIZE_BYTES = 512 * 1024

# temporary state
TMP_STATE = {}
TMP_TAG = {}

# Key for tracking patch applience
PATCHES_APPLIED = "S3_PATCHED"


def check_s3(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for port to be opened
        wait_for_port_open(s3_listener.PORT_S3_BACKEND)
        # check S3
        endpoint_url = f"http://127.0.0.1:{s3_listener.PORT_S3_BACKEND}"
        out = aws_stack.connect_to_service(
            service_name="s3", endpoint_url=endpoint_url
        ).list_buckets()
    except Exception:
        if print_error:
            LOG.exception("S3 health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out and isinstance(out.get("Buckets"), list)


def start_s3(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_S3
    if not backend_port:
        if config.FORWARD_EDGE_INMEM:
            backend_port = multiserver.get_moto_server_port()
        else:
            backend_port = get_free_tcp_port()
        s3_listener.PORT_S3_BACKEND = backend_port

    apply_patches()

    return start_moto_server(
        key="s3",
        name="S3",
        asynchronous=asynchronous,
        port=port,
        backend_port=backend_port,
        update_listener=update_listener,
    )


def apply_patches():
    if TMP_STATE.get(PATCHES_APPLIED, False):
        return

    TMP_STATE[PATCHES_APPLIED] = True

    if not os.environ.get("MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"):
        os.environ["MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"] = str(S3_MAX_FILE_SIZE_BYTES)

    def s3_update_acls(self, request, query, bucket_name, key_name):
        # fix for - https://github.com/localstack/localstack/issues/1733
        #         - https://github.com/localstack/localstack/issues/1170
        acl_key = "acl|%s|%s" % (bucket_name, key_name)
        acl = self._acl_from_headers(request.headers)
        if acl:
            TMP_STATE[acl_key] = acl
        if not query.get("uploadId"):
            return
        bucket = self.backend.get_bucket(bucket_name)
        key = bucket and self.backend.get_object(bucket_name, key_name)
        if not key:
            return
        acl = acl or TMP_STATE.pop(acl_key, None) or bucket.acl
        if acl:
            key.set_acl(acl)

    # patch Bucket.create_from_cloudformation_json in moto
    @classmethod
    def Bucket_create_from_cloudformation_json(
        cls, resource_name, cloudformation_json, region_name
    ):
        result = create_from_cloudformation_json_orig(
            resource_name, cloudformation_json, region_name
        )
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
        if bucket_name == config.BUCKET_MARKER_LOCAL:
            return None
        return get_bucket_orig(bucket_name, *args, **kwargs)

    get_bucket_orig = s3_models.s3_backend.get_bucket
    s3_models.s3_backend.get_bucket = types.MethodType(get_bucket, s3_models.s3_backend)

    def _bucket_response_head(self, bucket_name, *args, **kwargs):
        code, headers, body = _bucket_response_head_orig(self, bucket_name, *args, **kwargs)
        bucket = s3_models.s3_backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
        return code, headers, body

    _bucket_response_head_orig = s3_responses.ResponseObject._bucket_response_head
    s3_responses.ResponseObject._bucket_response_head = _bucket_response_head

    def _bucket_response_get(self, bucket_name, querystring, *args, **kwargs):
        result = _bucket_response_get_orig(self, bucket_name, querystring, *args, **kwargs)
        # for some reason in the "get-bucket-location" call, moto doesn't return a code, headers, body triple as a result
        if isinstance(result, tuple) and len(result) == 3:
            code, headers, body = result
            bucket = s3_models.s3_backend.get_bucket(bucket_name)
            headers["x-amz-bucket-region"] = bucket.region_name
        return result

    _bucket_response_get_orig = s3_responses.ResponseObject._bucket_response_get
    # note: method type is only required when the method is part of an object instance (make a method out of a function)
    s3_responses.ResponseObject._bucket_response_get = _bucket_response_get

    # patch S3Bucket.get_bucket(..)
    def delete_bucket(self, bucket_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        s3_listener.remove_bucket_notification(bucket_name)
        return delete_bucket_orig(bucket_name, *args, **kwargs)

    delete_bucket_orig = s3_models.s3_backend.delete_bucket
    s3_models.s3_backend.delete_bucket = types.MethodType(delete_bucket, s3_models.s3_backend)

    # patch _key_response_post(..)
    def s3_key_response_post(self, request, body, bucket_name, query, key_name, *args, **kwargs):
        result = s3_key_response_post_orig(
            request, body, bucket_name, query, key_name, *args, **kwargs
        )
        s3_update_acls(self, request, query, bucket_name, key_name)
        try:
            if query.get("uploadId"):
                if (bucket_name, key_name) in TMP_TAG:
                    key = self.backend.get_object(bucket_name, key_name)
                    self.backend.set_key_tags(
                        key, TMP_TAG.get((bucket_name, key_name), None), key_name
                    )
                    TMP_TAG.pop((bucket_name, key_name))
        except Exception:
            pass
        if query.get("uploads") and request.headers.get("X-Amz-Tagging"):
            tags = self._tagging_from_headers(request.headers)
            TMP_TAG[(bucket_name, key_name)] = tags
        return result

    s3_key_response_post_orig = s3_responses.S3ResponseInstance._key_response_post
    s3_responses.S3ResponseInstance._key_response_post = types.MethodType(
        s3_key_response_post, s3_responses.S3ResponseInstance
    )

    # patch _key_response_put(..)
    def s3_key_response_put(
        self, request, body, bucket_name, query, key_name, headers, *args, **kwargs
    ):
        result = s3_key_response_put_orig(
            request, body, bucket_name, query, key_name, headers, *args, **kwargs
        )
        s3_update_acls(self, request, query, bucket_name, key_name)
        return result

    s3_key_response_put_orig = s3_responses.S3ResponseInstance._key_response_put
    s3_responses.S3ResponseInstance._key_response_put = types.MethodType(
        s3_key_response_put, s3_responses.S3ResponseInstance
    )

    # patch DeleteObjectTagging
    def s3_key_response_delete(self, headers, bucket_name, query, key_name, *args, **kwargs):
        # Fixes https://github.com/localstack/localstack/issues/1083
        if query.get("tagging"):
            self._set_action("KEY", "DELETE", query)
            self._authenticate_and_authorize_s3_action()
            key = self.backend.get_object(bucket_name, key_name)
            key.tags = {}
            self.backend.tagger.delete_all_tags_for_resource(key.arn)
            return 204, {}, ""
        result = s3_key_response_delete_orig(headers, bucket_name, query, key_name, *args, **kwargs)
        return result

    s3_key_response_delete_orig = s3_responses.S3ResponseInstance._key_response_delete
    s3_responses.S3ResponseInstance._key_response_delete = types.MethodType(
        s3_key_response_delete, s3_responses.S3ResponseInstance
    )
    action_map = s3_responses.ACTION_MAP
    action_map["KEY"]["DELETE"]["tagging"] = (
        action_map["KEY"]["DELETE"].get("tagging") or "DeleteObjectTagging"
    )

    # patch _key_response_get(..)
    # https://github.com/localstack/localstack/issues/2724
    class InvalidObjectState(S3ClientError):
        code = 400

        def __init__(self, *args, **kwargs):
            super(InvalidObjectState, self).__init__(
                "InvalidObjectState",
                "The operation is not valid for the object's storage class.",
                *args,
                **kwargs,
            )

    def s3_key_response_get(self, bucket_name, query, key_name, headers, *args, **kwargs):
        resp_status, resp_headers, resp_value = s3_key_response_get_orig(
            bucket_name, query, key_name, headers, *args, **kwargs
        )

        if resp_headers.get("x-amz-storage-class") == "DEEP_ARCHIVE" and not resp_headers.get(
            "x-amz-restore"
        ):
            raise InvalidObjectState()

        return resp_status, resp_headers, resp_value

    s3_key_response_get_orig = s3_responses.S3ResponseInstance._key_response_get
    s3_responses.S3ResponseInstance._key_response_get = types.MethodType(
        s3_key_response_get, s3_responses.S3ResponseInstance
    )

    # patch max-keys
    def s3_truncate_result(self, result_keys, max_keys):
        return s3_truncate_result_orig(result_keys, max_keys or 1000)

    s3_truncate_result_orig = s3_responses.S3ResponseInstance._truncate_result
    s3_responses.S3ResponseInstance._truncate_result = types.MethodType(
        s3_truncate_result, s3_responses.S3ResponseInstance
    )

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
        elements = minidom.parseString(body).getElementsByTagName("Object")
        if len(elements) == 0:
            raise MalformedXML()

        deleted_names = []
        error_names = []

        keys = []
        for element in elements:
            if len(element.getElementsByTagName("VersionId")) == 0:
                version_id = None
            else:
                version_id = element.getElementsByTagName("VersionId")[0].firstChild.nodeValue

            keys.append(
                {
                    "key_name": element.getElementsByTagName("Key")[0].firstChild.nodeValue,
                    "version_id": version_id,
                }
            )

        for k in keys:
            key_name = k["key_name"]
            version_id = k["version_id"]
            success = self.backend.delete_object(
                bucket_name, undo_clean_key_name(key_name), version_id
            )

            if success:
                deleted_names.append({"key": key_name, "version_id": version_id})
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

    # Patch _handle_range_header(..)
    # https://github.com/localstack/localstack/issues/2146
    s3_response_handle_range_header_orig = s3_responses.S3ResponseInstance._handle_range_header

    def s3_response_handle_range_header(self, request, headers, response_content):
        rs_code, rs_headers, rs_content = s3_response_handle_range_header_orig(
            request, headers, response_content
        )
        if rs_code == 206:
            for k in ["ETag", "last-modified"]:
                v = headers.get(k)
                if v and not rs_headers.get(k):
                    rs_headers[k] = v

        return rs_code, rs_headers, rs_content

    s3_responses.S3ResponseInstance._handle_range_header = types.MethodType(
        s3_response_handle_range_header, s3_responses.S3ResponseInstance
    )

    # Patch utils_is_delete_keys
    # https://github.com/localstack/localstack/issues/2866
    # https://github.com/localstack/localstack/issues/2850
    # https://github.com/localstack/localstack/issues/3931
    # https://github.com/localstack/localstack/issues/4015
    utils_is_delete_keys_orig = s3bucket_path_utils.is_delete_keys

    def utils_is_delete_keys(request, path, bucket_name):
        return "/" + bucket_name + "?delete=" in path or utils_is_delete_keys_orig(
            request, path, bucket_name
        )

    def s3_response_is_delete_keys(self, request, path, bucket_name):
        if self.subdomain_based_buckets(request):
            # Temporary fix until moto supports x-id and DeleteObjects (#3931)
            query = self._get_querystring(request.url)
            is_delete_keys_v3 = (
                query and ("delete" in query) and get_safe(query, "$.x-id.0") == "DeleteObjects"
            )
            return is_delete_keys_v3 or is_delete_keys(request, path, bucket_name)
        else:
            return utils_is_delete_keys(request, path, bucket_name)

    s3_responses.S3ResponseInstance.is_delete_keys = types.MethodType(
        s3_response_is_delete_keys, s3_responses.S3ResponseInstance
    )

    def parse_bucket_name_from_url(self, request, url):
        path = urlparse(url).path
        return s3_utils.extract_bucket_name(request.headers, path)

    s3_responses.S3ResponseInstance.parse_bucket_name_from_url = types.MethodType(
        parse_bucket_name_from_url, s3_responses.S3ResponseInstance
    )

    def subdomain_based_buckets(self, request):
        return s3_utils.uses_host_addressing(request.headers)

    s3_responses.S3ResponseInstance.subdomain_based_buckets = types.MethodType(
        subdomain_based_buckets, s3_responses.S3ResponseInstance
    )

    s3_responses_bucket_response_get_orig = s3_responses.S3ResponseInstance._bucket_response_get

    def s3_bucket_response_get(self, bucket_name, querystring):
        try:
            return s3_responses_bucket_response_get_orig(bucket_name, querystring)
        except NotImplementedError:
            if "uploads" not in querystring:
                raise

            multiparts = list(self.backend.get_all_multiparts(bucket_name).values())
            if "prefix" in querystring:
                prefix = querystring.get("prefix", [None])[0]
                multiparts = [upload for upload in multiparts if upload.key_name.startswith(prefix)]

            upload_ids = [upload_id for upload_id in querystring.get("uploads") if upload_id]
            if upload_ids:
                multiparts = [upload for upload in multiparts if upload.id in upload_ids]

            template = self.response_template(S3_ALL_MULTIPARTS)
            return template.render(bucket_name=bucket_name, uploads=multiparts)

    s3_responses.S3ResponseInstance._bucket_response_get = types.MethodType(
        s3_bucket_response_get, s3_responses.S3ResponseInstance
    )

    copy_object_orig = s3_models.s3_backend.copy_object

    def copy_object(
        self,
        src_bucket_name,
        src_key_name,
        dest_bucket_name,
        dest_key_name,
        storage=None,
        acl=None,
        src_version_id=None,
        *args,
        **kwargs,
    ):
        copy_object_orig(
            src_bucket_name,
            src_key_name,
            dest_bucket_name,
            dest_key_name,
            storage=storage,
            acl=acl,
            src_version_id=src_version_id,
            *args,
            **kwargs,
        )
        key = self.get_object(dest_bucket_name, dest_key_name)
        # reset etag
        key._etag = None

    s3_models.s3_backend.copy_object = types.MethodType(copy_object, s3_models.s3_backend)
