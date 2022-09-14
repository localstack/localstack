import copy
import logging
import os
from typing import Union
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import moto.s3.models as moto_s3_models
import moto.s3.responses as moto_s3_responses
from moto.s3 import s3_backends as moto_s3_backends
from moto.s3.exceptions import MissingBucket

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    AccessControlPolicy,
    AccountId,
    BucketName,
    CreateBucketOutput,
    CreateBucketRequest,
    GetBucketAclOutput,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLifecycleOutput,
    GetBucketLocationOutput,
    GetBucketRequestPaymentOutput,
    GetBucketRequestPaymentRequest,
    GetObjectOutput,
    GetObjectRequest,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidArgument,
    InvalidBucketName,
    ListObjectsOutput,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    NoSuchBucket,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    ObjectKey,
    PutBucketAclRequest,
    PutBucketLifecycleConfigurationRequest,
    PutBucketLifecycleRequest,
    PutBucketRequestPaymentRequest,
    PutObjectOutput,
    PutObjectRequest,
    S3Api,
)
from localstack.aws.api.s3 import Type as GranteeType
from localstack.config import get_edge_port_http, get_protocol
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.http import Request, Response
from localstack.http.proxy import forward
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.models import S3Store, s3_stores
from localstack.services.s3.utils import (
    VALID_ACL_PREDEFINED_GROUPS,
    VALID_GRANTEE_PERMISSIONS,
    get_header_name,
    is_bucket_name_valid,
    is_canned_acl_valid,
    is_key_expired,
    is_valid_canonical_id,
    verify_checksum,
)
from localstack.utils.aws import aws_stack
from localstack.utils.aws.request_context import AWS_REGION_REGEX
from localstack.utils.objects import singleton_factory
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"

MOTO_CANONICAL_USER_ID = "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"


class MalformedXML(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("MalformedXML", status_code=400, message=message)


class MalformedACLError(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("MalformedACLError", status_code=400, message=message)


def get_moto_s3_backend(context: RequestContext) -> moto_s3_models.S3Backend:
    return moto_s3_backends[context.account_id]["global"]


def get_full_default_bucket_location(bucket_name):
    return f"{get_protocol()}://{bucket_name}.s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()}/"


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store() -> S3Store:
        return s3_stores[get_aws_account_id()][aws_stack.get_region()]

    def on_after_init(self):
        apply_moto_patches()
        self.add_custom_routes()

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self,
        context: RequestContext,
        request: CreateBucketRequest,
    ) -> CreateBucketOutput:
        bucket_name = request["Bucket"]
        validate_bucket_name(bucket=bucket_name)
        response: CreateBucketOutput = call_moto(context)
        # Location is always contained in response -> full url for LocationConstraint outside us-east-1
        if request.get("CreateBucketConfiguration"):
            location = request["CreateBucketConfiguration"].get("LocationConstraint")
            if location and location != "us-east-1":
                response["Location"] = get_full_default_bucket_location(bucket_name)
        if "Location" not in response:
            response["Location"] = f"/{bucket_name}"
        return response

    def delete_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        call_moto(context)
        store = self.get_store()
        # TODO: create a helper method for cleaning up the store, already done in next PR
        store.bucket_lifecycle_configuration.pop(bucket, None)

    def get_bucket_location(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLocationOutput:
        response = call_moto(context)
        return response

    @handler("ListObjects", expand=False)
    def list_objects(
        self,
        context: RequestContext,
        request: ListObjectsRequest,
    ) -> ListObjectsOutput:
        response: ListObjectsOutput = call_moto(context)

        if "Marker" not in response:
            response["Marker"] = request.get("Marker") or ""

        encoding_type = request.get("EncodingType")
        if "EncodingType" not in response and encoding_type:
            response["EncodingType"] = encoding_type

        # fix URL-encoding of Delimiter
        if delimiter := response.get("Delimiter"):
            delimiter = delimiter.strip()
            if delimiter != "/":
                response["Delimiter"] = quote(delimiter)

        if "BucketRegion" not in response:
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
            response["BucketRegion"] = bucket.region_name

        return ListObjectsOutput(**response)

    @handler("ListObjectsV2", expand=False)
    def list_objects_v2(
        self,
        context: RequestContext,
        request: ListObjectsV2Request,
    ) -> ListObjectsV2Output:
        response: ListObjectsV2Output = call_moto(context)

        encoding_type = request.get("EncodingType")
        if "EncodingType" not in response and encoding_type:
            response["EncodingType"] = encoding_type

        # fix URL-encoding of Delimiter
        if delimiter := response.get("Delimiter"):
            delimiter = delimiter.strip()
            if delimiter != "/":
                response["Delimiter"] = quote(delimiter)

        if "BucketRegion" not in response:
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
            response["BucketRegion"] = bucket.region_name

        return response

    @handler("HeadObject", expand=False)
    def head_object(
        self,
        context: RequestContext,
        request: HeadObjectRequest,
    ) -> HeadObjectOutput:
        response: HeadObjectOutput = call_moto(context)
        response["AcceptRanges"] = "bytes"
        return response

    @handler("GetObject", expand=False)
    def get_object(self, context: RequestContext, request: GetObjectRequest) -> GetObjectOutput:
        key = request["Key"]
        if is_object_expired(context, bucket=request["Bucket"], key=key):
            # TODO: old behaviour was deleting key instantly if expired. AWS cleans up only once a day generally
            # see if we need to implement a feature flag
            # but you can still HeadObject on it and you get the expiry time
            ex = NoSuchKey("The specified key does not exist.")
            ex.Key = key
            raise ex
        response: GetObjectOutput = call_moto(context)
        response["AcceptRanges"] = "bytes"
        return response

    @handler("PutObject", expand=False)
    def put_object(
        self,
        context: RequestContext,
        request: PutObjectRequest,
    ) -> PutObjectOutput:
        if checksum_algorithm := request.get("ChecksumAlgorithm"):
            verify_checksum(checksum_algorithm, context.request.data, request)

        response: PutObjectOutput = call_moto(context)

        if expires := request.get("Expires"):
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
            key_object = get_key_from_moto_bucket(bucket, key=request["Key"])
            key_object.set_expiry(expires)

        return response

    @handler("PutBucketRequestPayment", expand=False)
    def put_bucket_request_payment(
        self,
        context: RequestContext,
        request: PutBucketRequestPaymentRequest,
    ) -> None:
        bucket_name = request["Bucket"]
        payer = request.get("RequestPaymentConfiguration", {}).get("Payer")
        if payer not in ["Requester", "BucketOwner"]:
            raise MalformedXML(
                message="The XML you provided was not well-formed or did not validate against our published schema"
            )

        moto_backend = get_moto_s3_backend(context)
        bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
        bucket.payer = payer

    @handler("GetBucketRequestPayment", expand=False)
    def get_bucket_request_payment(
        self,
        context: RequestContext,
        request: GetBucketRequestPaymentRequest,
    ) -> GetBucketRequestPaymentOutput:
        bucket_name = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
        return GetBucketRequestPaymentOutput(Payer=bucket.payer)

    def get_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleOutput:
        # deprecated for older rules created. Not sure what to do with this?
        response = self.get_bucket_lifecycle_configuration(context, bucket, expected_bucket_owner)
        return GetBucketLifecycleOutput(**response)

    def get_bucket_lifecycle_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleConfigurationOutput:
        # test if bucket exists in moto
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket=bucket)

        store = self.get_store()
        bucket_lifecycle = store.bucket_lifecycle_configuration.get(bucket)
        if not bucket_lifecycle:
            ex = NoSuchLifecycleConfiguration("The lifecycle configuration does not exist")
            ex.BucketName = bucket
            raise ex

        return GetBucketLifecycleConfigurationOutput(Rules=bucket_lifecycle["Rules"])

    @handler("PutBucketLifecycle", expand=False)
    def put_bucket_lifecycle(
        self,
        context: RequestContext,
        request: PutBucketLifecycleRequest,
    ) -> None:
        # deprecated for older rules created. Not sure what to do with this?
        # same URI as PutBucketLifecycleConfiguration
        self.put_bucket_lifecycle_configuration(context, request)

    @handler("PutBucketLifecycleConfiguration", expand=False)
    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        request: PutBucketLifecycleConfigurationRequest,
    ) -> None:
        """This is technically supported in moto, however moto does not support multiple transitions action
        It will raise an TypeError trying to get dict attributes on a list. It would need a bigger rework on moto's side
        Moto has quite a good validation for the other Lifecycle fields, so it would be nice to be able to use it
        somehow. For now the behaviour is the same as before, aka no validation
        """
        # test if bucket exists in moto
        bucket = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket=bucket)
        store = self.get_store()
        # TODO: add validation on the BucketLifecycleConfiguration
        store.bucket_lifecycle_configuration[bucket] = request.get("LifecycleConfiguration")

    def delete_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        # test if bucket exists in moto
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket=bucket)

        store = self.get_store()
        store.bucket_lifecycle_configuration.pop(bucket, None)

    def get_bucket_acl(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketAclOutput:
        response: GetBucketAclOutput = call_moto(context)

        for grant in response["Grants"]:
            grantee = grant.get("Grantee", {})
            if grantee.get("ID") == MOTO_CANONICAL_USER_ID:
                # adding the DisplayName used by moto for the owner
                grantee["DisplayName"] = "webfile"

        return response

    @handler("PutBucketAcl", expand=False)
    def put_bucket_acl(
        self,
        context: RequestContext,
        request: PutBucketAclRequest,
    ) -> None:
        if (canned_acl := request.get("ACL")) and not is_canned_acl_valid(canned_acl):
            ex = _create_invalid_argument_exc(None, name="x-amz-acl", value=canned_acl)
            raise ex

        grant_keys = [
            "GrantFullControl",
            "GrantRead",
            "GrantReadACP",
            "GrantWrite",
            "GrantWriteACP",
        ]
        for key in grant_keys:
            if grantees_values := request.get(key, ""):  # noqa
                validate_grantee_in_headers(key, grantees_values)

        if acp := request.get("AccessControlPolicy"):
            validate_acl_acp(acp)

        call_moto(context)

    def add_custom_routes(self):
        # virtual-host style: https://bucket-name.s3.region-code.amazonaws.com/key-name
        # host_pattern_vhost_style = f"{bucket}.s3.<regex('({AWS_REGION_REGEX}\.)?'):region>{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        host_pattern_vhost_style = f"<regex('.*'):bucket>.s3.<regex('({AWS_REGION_REGEX}\\.)?'):region>{LOCALHOST_HOSTNAME}<regex('(?::\\d+)?'):port>"
        ROUTER.add(
            "/<path:path>",
            host=host_pattern_vhost_style,
            endpoint=self.serve_bucket,
        )
        ROUTER.add(
            "/",
            host=host_pattern_vhost_style,
            endpoint=self.serve_bucket,
            defaults={"path": "/"},
        )

        # regions for path-style need to be parsed correctly
        host_pattern_vhost_style = f"s3.<regex('({AWS_REGION_REGEX}\\.)'):region>{LOCALHOST_HOSTNAME}<regex('(?::\\d+)?'):port>"
        ROUTER.add(
            "/<regex('.+'):bucket>/<path:path>",
            host=host_pattern_vhost_style,
            endpoint=self.serve_bucket,
        )
        ROUTER.add(
            "/<regex('.+'):bucket>",
            host=host_pattern_vhost_style,
            endpoint=self.serve_bucket,
            defaults={"path": "/"},
        )

    def serve_bucket(
        self, request: Request, bucket: str, path: str, region: str, port: str
    ) -> Response:
        # TODO region pattern currently not working -> removing it from url
        rewritten_url = self.rewrite_url(request.url, bucket, region)

        LOG.debug(f"Rewritten original host url: {request.url} to path-style url: {rewritten_url}")

        splitted = urlsplit(rewritten_url)
        copied_headers = copy.deepcopy(request.headers)
        copied_headers["Host"] = splitted.netloc
        return forward(
            request, f"{splitted.scheme}://{splitted.netloc}", splitted.path, copied_headers
        )

    def rewrite_url(self, url: str, bucket: str, region: str) -> str:
        """
        Rewrites the url so that it can be forwarded to moto. Used for vhost-style and for any url that contains the region.

        For vhost style: removes the bucket-name from the host-name and adds it as path
        E.g. http://my-bucket.s3.localhost.localstack.cloud:4566 -> http://s3.localhost.localstack.cloud:4566/my-bucket

        If the region is contained in the host-name we remove it (for now) as moto cannot handle the region correctly

        :param url: the original url
        :param bucket: the bucket name
        :param region: the region name
        :return: re-written url as string
        """
        splitted = urlsplit(url)
        if splitted.netloc.startswith(f"{bucket}."):
            netloc = splitted.netloc.replace(f"{bucket}.", "")
            path = f"{bucket}{splitted.path}"
        else:
            # we already have a path-style addressing, only need to remove the region
            netloc = splitted.netloc
            path = splitted.path
        # TODO region currently ignored
        if region:
            netloc = netloc.replace(f"{region}", "")

        return urlunsplit(
            SplitResult(splitted.scheme, netloc, path, splitted.query, splitted.fragment)
        )


def validate_bucket_name(bucket: BucketName) -> None:
    """
    Validate s3 bucket name based on the documentation
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    if not is_bucket_name_valid(bucket_name=bucket):
        ex = InvalidBucketName("The specified bucket is not valid.")
        ex.BucketName = bucket
        raise ex


def _create_invalid_argument_exc(
    message: Union[str, None], name: str, value: str
) -> InvalidArgument:
    ex = InvalidArgument(message)
    ex.ArgumentName = name
    ex.ArgumentValue = value
    return ex


def validate_canned_acl(canned_acl: str) -> None:
    """
    Validate the canned ACL value, or raise an Exception
    """
    if not is_canned_acl_valid(canned_acl):
        ex = _create_invalid_argument_exc(None, "x-amz-acl", canned_acl)
        raise ex


def validate_grantee_in_headers(grant: str, grantees: str) -> None:
    splitted_grantees = [grantee.strip() for grantee in grantees.split(",")]
    for grantee in splitted_grantees:
        grantee_type, grantee_id = grantee.split("=")
        grantee_id = grantee_id.strip('"')
        if grantee_type not in ("uri", "id", "emailAddress"):
            ex = _create_invalid_argument_exc(
                "Argument format not recognized", get_header_name(grant), grantee
            )
            raise ex
        elif grantee_type == "uri" and grantee_id not in VALID_ACL_PREDEFINED_GROUPS:
            ex = _create_invalid_argument_exc("Invalid group uri", "uri", grantee_id)
            raise ex
        elif grantee_type == "id" and not is_valid_canonical_id(grantee_id):
            ex = _create_invalid_argument_exc("Invalid id", "id", grantee_id)
            raise ex
        elif grantee_type == "emailAddress":
            # TODO: check validation here
            continue


def validate_acl_acp(acp: AccessControlPolicy) -> None:
    if "Owner" not in acp or "Grants" not in acp:
        raise MalformedACLError(
            "The XML you provided was not well-formed or did not validate against our published schema"
        )

    if not is_valid_canonical_id(owner_id := acp["Owner"].get("ID", "")):
        ex = _create_invalid_argument_exc("Invalid id", "CanonicalUser/ID", owner_id)
        raise ex

    for grant in acp["Grants"]:
        if grant.get("Permission") not in VALID_GRANTEE_PERMISSIONS:
            raise MalformedACLError(
                "The XML you provided was not well-formed or did not validate against our published schema"
            )

        grantee = grant.get("Grantee", {})
        grant_type = grantee.get("Type")
        if grant_type not in (
            GranteeType.Group,
            GranteeType.CanonicalUser,
            GranteeType.AmazonCustomerByEmail,
        ):
            raise MalformedACLError(
                "The XML you provided was not well-formed or did not validate against our published schema"
            )
        elif (
            grant_type == GranteeType.Group
            and (grant_uri := grantee.get("URI", "")) not in VALID_ACL_PREDEFINED_GROUPS
        ):
            ex = _create_invalid_argument_exc("Invalid group uri", "Group/URI", grant_uri)
            raise ex

        elif grant_type == GranteeType.AmazonCustomerByEmail:
            # TODO: add validation here
            continue

        elif grant_type == GranteeType.CanonicalUser and not is_valid_canonical_id(
            (grantee_id := grantee.get("ID", ""))
        ):
            ex = _create_invalid_argument_exc("Invalid id", "CanonicalUser/ID", grantee_id)
            raise ex


def get_bucket_from_moto(
    moto_backend: moto_s3_models.S3Backend, bucket: BucketName
) -> moto_s3_models.FakeBucket:
    # TODO: check authorization for buckets as well?
    try:
        return moto_backend.get_bucket(bucket_name=bucket)
    except MissingBucket:
        ex = NoSuchBucket("The specified bucket does not exist")
        ex.BucketName = bucket
        raise ex


def get_key_from_moto_bucket(
    moto_bucket: moto_s3_models.FakeBucket, key: ObjectKey
) -> moto_s3_models.FakeKey:
    fake_key = moto_bucket.keys.get(key)
    if not fake_key:
        ex = NoSuchKey("The specified key does not exist.")
        ex.Key = key
        raise ex

    return fake_key


def is_object_expired(context: RequestContext, bucket: BucketName, key: ObjectKey) -> bool:
    moto_backend = get_moto_s3_backend(context)
    moto_bucket = get_bucket_from_moto(moto_backend, bucket)
    key_object = get_key_from_moto_bucket(moto_bucket, key)
    return is_key_expired(key_object=key_object)


@singleton_factory
def apply_moto_patches():
    # importing here in case we need InvalidObjectState from `localstack.aws.api.s3`
    from moto.s3.exceptions import InvalidObjectState

    @patch(moto_s3_responses.S3Response.key_response)
    def _fix_key_response(fn, self, *args, **kwargs):
        """Change casing of Last-Modified headers to be picked by the parser"""
        status_code, resp_headers, key_value = fn(self, *args, **kwargs)
        for low_case_header in [
            "last-modified",
            "content-type",
            "content-length",
            "content-range",
            "content-encoding",
        ]:
            if header_value := resp_headers.pop(low_case_header, None):
                header_name = _capitalize_header_name_from_snake_case(low_case_header)
                resp_headers[header_name] = header_value

        return status_code, resp_headers, key_value

    @patch(moto_s3_responses.S3Response._bucket_response_head)
    def _fix_bucket_response_head(fn, self, bucket_name, *args, **kwargs):
        code, headers, body = fn(self, bucket_name, *args, **kwargs)
        bucket = self.backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
        headers["content-type"] = "application/xml"
        return code, headers, body

    @patch(moto_s3_responses.S3Response._key_response_get)
    def _fix_key_response_get(fn, *args, **kwargs):
        code, headers, body = fn(*args, **kwargs)
        storage_class = headers.get("x-amz-storage-class")

        if storage_class == "DEEP_ARCHIVE" and not headers.get("x-amz-restore"):
            raise InvalidObjectState(storage_class=storage_class)

        return code, headers, body

    @patch(moto_s3_responses.S3Response.all_buckets)
    def _fix_owner_id_list_bucket(fn, *args, **kwargs) -> str:
        """
        Moto does not use the same CanonicalUser ID for the owner between ListBuckets and all ACLs related response
        Patch ListBuckets to return the same ID as the ACL
        """
        res: str = fn(*args, **kwargs)
        res = res.replace(
            "<ID>bcaf1ffd86f41161ca5fb16fd081034f</ID>", f"<ID>{MOTO_CANONICAL_USER_ID}</ID>"
        )
        return res


def _capitalize_header_name_from_snake_case(header_name: str) -> str:
    return "-".join([part.capitalize() for part in header_name.split("-")])
