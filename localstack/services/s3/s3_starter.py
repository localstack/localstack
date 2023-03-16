import logging
import os
import urllib
from urllib.parse import urlparse

from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.exceptions import MissingBucket, S3ClientError
from moto.s3.responses import S3_ALL_MULTIPARTS, MalformedXML, minidom
from moto.s3.utils import undo_clean_key_name

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.services.s3 import constants as s3_constants
from localstack.services.s3 import s3_listener, s3_utils
from localstack.utils.aws import aws_stack
from localstack.utils.collections import get_safe
from localstack.utils.common import get_free_tcp_port, wait_for_port_open
from localstack.utils.patch import patch
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


def add_gateway_compatibility_handlers():
    """
    This method adds handlers that ensure compatibility between the legacy s3 provider and ASF.
    """

    def _fix_static_website_request(chain, context, response):
        """
        The ASF parser will recognize a request to a website as a normal 'ListBucket' request, but will be routed
        through ``serve_static_website``, which does not return a `ListObjects` result. This would lead to errors in
        the service response parser. So this handler unsets the AWS operation for this particular request, so it is not
        parsed by the service response parser."""
        if not s3_listener.is_static_website(context.request.headers):
            return
        if context.operation.name == "ListObjects":
            context.operation = None

    from localstack.aws.handlers import modify_service_response

    modify_service_response.append("s3", _fix_static_website_request)


def start_s3(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.service_port("s3")
    if not backend_port:
        if config.FORWARD_EDGE_INMEM:
            backend_port = multiserver.get_moto_server_port()
        else:
            backend_port = get_free_tcp_port()
        s3_listener.PORT_S3_BACKEND = backend_port

    apply_patches()

    add_gateway_compatibility_handlers()

    return start_moto_server(
        key="s3",
        name="S3",
        asynchronous=asynchronous,
        port=port,
        backend_port=backend_port,
        update_listener=update_listener,
    )


def apply_patches():
    from moto.iam.access_control import PermissionResult

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

    # patch S3Bucket.create_bucket(..)
    @patch(s3_models.S3Backend.create_bucket)
    def create_bucket(fn, self, bucket_name, region_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        return fn(self, bucket_name, region_name, *args, **kwargs)

    # patch S3Bucket.get_bucket(..)
    @patch(s3_models.S3Backend.get_bucket)
    def get_bucket(fn, self, bucket_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        if bucket_name == config.BUCKET_MARKER_LOCAL:
            return None
        return fn(self, bucket_name, *args, **kwargs)

    @patch(s3_responses.S3Response._bucket_response_head)
    def _bucket_response_head(fn, self, bucket_name, *args, **kwargs):
        code, headers, body = fn(self, bucket_name, *args, **kwargs)
        bucket = self.backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
        return code, headers, body

    @patch(s3_responses.S3Response._bucket_response_get)
    def _bucket_response_get(fn, self, bucket_name, querystring, *args, **kwargs):
        result = fn(self, bucket_name, querystring, *args, **kwargs)
        # for some reason in the "get-bucket-location" call, moto doesn't return a code/headers/body triple as a result
        if isinstance(result, tuple) and len(result) == 3:
            code, headers, body = result
            bucket = self.backend.get_bucket(bucket_name)
            headers["x-amz-bucket-region"] = bucket.region_name
        return result

    # patch S3Bucket.get_bucket(..)
    @patch(s3_models.S3Backend.delete_bucket)
    def delete_bucket(fn, self, bucket_name, *args, **kwargs):
        bucket_name = s3_listener.normalize_bucket_name(bucket_name)
        try:
            s3_listener.remove_bucket_notification(bucket_name)
        except s3_listener.NoSuchBucket:
            raise MissingBucket()
        return fn(self, bucket_name, *args, **kwargs)

    # patch _key_response_post(..)
    @patch(s3_responses.S3ResponseInstance._key_response_post)
    def s3_key_response_post(
        self, fn, request, body, bucket_name, query, key_name, *args, **kwargs
    ):
        result = fn(request, body, bucket_name, query, key_name, *args, **kwargs)
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

    # patch _key_response_put(..)
    @patch(s3_responses.S3ResponseInstance._key_response_put)
    def s3_key_response_put(self, fn, request, body, bucket_name, query, key_name, *args, **kwargs):
        result = fn(request, body, bucket_name, query, key_name, *args, **kwargs)
        s3_update_acls(self, request, query, bucket_name, key_name)
        return result

    # patch DeleteObjectTagging
    @patch(s3_responses.S3ResponseInstance._key_response_delete)
    def s3_key_response_delete(self, fn, headers, bucket_name, query, key_name, *args, **kwargs):
        # Fixes https://github.com/localstack/localstack/issues/1083
        if query.get("tagging"):
            self._set_action("KEY", "DELETE", query)
            self._authenticate_and_authorize_s3_action()
            key = self.backend.get_object(bucket_name, key_name)
            key.tags = {}
            self.backend.tagger.delete_all_tags_for_resource(key.arn)
            return 204, {}, ""
        result = fn(headers, bucket_name, query, key_name, *args, **kwargs)
        return result

    action_map = s3_responses.ACTION_MAP
    action_map["KEY"]["DELETE"]["tagging"] = (
        action_map["KEY"]["DELETE"].get("tagging") or "DeleteObjectTagging"
    )

    # patch _key_response_get(..)
    # https://github.com/localstack/localstack/issues/2724
    class InvalidObjectState(S3ClientError):
        code = 403

        def __init__(self, *args, **kwargs):
            super(InvalidObjectState, self).__init__(
                "InvalidObjectState",
                "The operation is not valid for the object's storage class.",
                *args,
                **kwargs,
            )

    @patch(s3_responses.S3ResponseInstance._key_response_get)
    def s3_key_response_get(self, fn, bucket_name, query, key_name, headers, *args, **kwargs):
        resp_status, resp_headers, resp_value = fn(
            bucket_name, query, key_name, headers, *args, **kwargs
        )

        if resp_headers.get("x-amz-storage-class") == "DEEP_ARCHIVE" and not resp_headers.get(
            "x-amz-restore"
        ):
            raise InvalidObjectState()

        return resp_status, resp_headers, resp_value

    # patch truncate_result
    @patch(s3_responses.S3ResponseInstance._truncate_result)
    def s3_truncate_result(self, fn, result_keys, max_keys):
        return fn(result_keys, max_keys or 1000)

    # patch _bucket_response_delete_keys(..)
    # https://github.com/localstack/localstack/issues/2077
    # TODO: check if patch still needed!
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

    @patch(s3_responses.S3ResponseInstance._bucket_response_delete_keys, pass_target=False)
    def s3_bucket_response_delete_keys(self, bucket_name, *args, **kwargs):
        template = self.response_template(s3_delete_keys_response_template)
        elements = minidom.parseString(self.body).getElementsByTagName("Object")

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

    # Patch _handle_range_header(..)
    # https://github.com/localstack/localstack/issues/2146

    @patch(s3_responses.S3ResponseInstance._handle_range_header)
    def s3_response_handle_range_header(self, fn, request, headers, response_content):
        rs_code, rs_headers, rs_content = fn(request, headers, response_content)
        if rs_code == 206:
            for k in ["ETag", "last-modified"]:
                v = headers.get(k)
                if v and not rs_headers.get(k):
                    rs_headers[k] = v

        return rs_code, rs_headers, rs_content

    @patch(s3_responses.S3Response.is_delete_keys)
    def s3_response_is_delete_keys(fn, self):
        """
        Temporary fix until moto supports x-id and DeleteObjects (#3931)
        """
        return get_safe(self.querystring, "$.x-id.0") == "DeleteObjects" or fn(self)

    @patch(s3_responses.S3ResponseInstance.parse_bucket_name_from_url, pass_target=False)
    def parse_bucket_name_from_url(self, request, url):
        path = urlparse(url).path
        return s3_utils.extract_bucket_name(request.headers, path)

    @patch(s3_responses.S3ResponseInstance.subdomain_based_buckets, pass_target=False)
    def subdomain_based_buckets(self, request):
        return s3_utils.uses_host_addressing(request.headers)

    @patch(s3_responses.S3ResponseInstance._bucket_response_get)
    def s3_bucket_response_get(self, fn, bucket_name, querystring):
        try:
            return fn(bucket_name, querystring)
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

    @patch(s3_models.S3Backend.copy_object)
    def copy_object(
        fn,
        self,
        src_key,
        dest_bucket_name,
        dest_key_name,
        *args,
        **kwargs,
    ):
        fn(
            self,
            src_key,
            dest_bucket_name,
            dest_key_name,
            *args,
            **kwargs,
        )
        key = self.get_object(dest_bucket_name, dest_key_name)
        # reset etag
        key._etag = None

    @patch(s3_models.FakeKey.safe_name)
    def safe_name(fn, self, encoding_type=None):
        if encoding_type == "url":
            # fixes an issue where upstream also encodes "/", which should not be the case
            return urllib.parse.quote(self.name, safe="/")
        return self.name

    @patch(s3_models.FakeBucket.get_permission)
    def bucket_get_permission(fn, self, *args, **kwargs):
        """
        Apply a patch to disable/enable enforcement of S3 bucket policies
        """
        if not s3_constants.ENABLE_MOTO_BUCKET_POLICY_ENFORCEMENT:
            return PermissionResult.PERMITTED

        return fn(self, *args, **kwargs)
