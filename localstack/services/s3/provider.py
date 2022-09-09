import logging
import os
from urllib.parse import quote

# from moto.s3.models import FakeKey, S3Backend
import moto.s3.models as moto_s3_models
import moto.s3.responses as moto_s3_responses
from moto.s3 import s3_backends as moto_s3_backends

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, ServiceResponse, handler
from localstack.aws.api.s3 import (  # CreateBucketConfiguration,; Delimiter,; EncodingType,; Marker,; MaxKeys,; ObjectKey,; Prefix,; RequestPayer,
    AccountId,
    BucketName,
    ChecksumAlgorithm,
    ContentMD5,
    CreateBucketOutput,
    CreateBucketRequest,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLifecycleOutput,
    GetObjectOutput,
    GetObjectRequest,
    HeadBucketOutput,
    HeadBucketRequest,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidBucketName,
    LifecycleConfiguration,
    ListObjectsOutput,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    NoSuchBucket,
    NoSuchLifecycleConfiguration,
    S3Api,
)
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.models import S3Store, s3_stores
from localstack.utils.aws import aws_stack
from localstack.utils.objects import singleton_factory
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"

PATCHED_EXCEPTIONS = [NoSuchBucket, NoSuchLifecycleConfiguration]


def get_moto_s3_backend(context: RequestContext) -> moto_s3_models.S3Backend:
    return moto_s3_backends[context.account_id]["global"]


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store() -> S3Store:
        return s3_stores[get_aws_account_id()][aws_stack.get_region()]

    def on_after_init(self):
        apply_moto_patches()

    @handler("GetObject", expand=False)
    def get_object(self, context: RequestContext, request: GetObjectRequest) -> GetObjectOutput:
        # TODO: how to manage LastModified on object (store state?)
        response = call_moto_with_exception_patching(context, bucket=request.get("Bucket", ""))

        return GetObjectOutput(**response, AcceptRanges="bytes")

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self,
        context: RequestContext,
        request: CreateBucketRequest,
    ) -> CreateBucketOutput:
        bucket_name = request.get("Bucket", "")
        validate_bucket_name(bucket=bucket_name)

        response = call_moto_with_exception_patching(context, bucket_name)
        return CreateBucketOutput(**response)

    @handler("HeadBucket", expand=False)
    def head_bucket(
        self,
        context: RequestContext,
        request: HeadBucketRequest,
    ) -> HeadBucketOutput:
        bucket_name = request.get("Bucket", "")
        response = call_moto_with_exception_patching(context, bucket_name)
        if "BucketRegion" not in response:
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
            response["BucketRegion"] = bucket.region_name

        return HeadBucketOutput(**response)

    @handler("HeadObject", expand=False)
    def head_object(
        self,
        context: RequestContext,
        request: HeadObjectRequest,
    ) -> HeadObjectOutput:
        bucket_name = request.get("Bucket", "")
        response = call_moto_with_exception_patching(context, bucket_name)

        return HeadObjectOutput(**response, AcceptRanges="bytes")

    @handler("ListObjects", expand=False)
    def list_objects(
        self,
        context: RequestContext,
        request: ListObjectsRequest,
    ) -> ListObjectsOutput:
        bucket_name = request.get("Bucket", "")
        response = call_moto_with_exception_patching(context, bucket_name)

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
            bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
            response["BucketRegion"] = bucket.region_name

        return ListObjectsOutput(**response)

    @handler("ListObjectsV2", expand=False)
    def list_objects_v2(
        self,
        context: RequestContext,
        request: ListObjectsV2Request,
    ) -> ListObjectsV2Output:
        bucket_name = request.get("Bucket", "")
        response = call_moto_with_exception_patching(context, bucket_name)
        # TODO: check those
        # encoding_type = request.get("EncodingType")
        # if "EncodingType" not in response and encoding_type:
        #     response["EncodingType"] = encoding_type
        #
        # # fix URL-encoding of Delimiter
        # if delimiter := response.get("Delimiter"):
        #     delimiter = delimiter.strip()
        #     if delimiter != "/":
        #         response["Delimiter"] = quote(delimiter)

        if "BucketRegion" not in response:
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
            response["BucketRegion"] = bucket.region_name

        return ListObjectsV2Output(**response)

    def get_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleOutput:
        # TODO: see both methods have the same URI, what it returns depends on what was put (filter or not)
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html
        # which is called from ASF?
        response = call_moto_with_exception_patching(context, bucket)
        return GetBucketLifecycleOutput(**response)

    def get_bucket_lifecycle_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleConfigurationOutput:
        # TODO: see both methods have the same URI, what it returns depends on what was put (filter or not)
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html
        # which is called from ASF?
        response = call_moto_with_exception_patching(context, bucket)
        return GetBucketLifecycleConfigurationOutput(**response)

    def put_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        lifecycle_configuration: LifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        response = call_moto_with_exception_patching(context, bucket)
        return response

    def delete_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        response = call_moto_with_exception_patching(context, bucket=bucket)
        return response


def call_moto_with_exception_patching(
    context: RequestContext, bucket: BucketName
) -> ServiceResponse:
    try:
        response = call_moto(context)
    except CommonServiceException as e:
        ex = _patch_moto_exceptions(e, bucket_name=bucket)
        raise ex
    return response


def _patch_moto_exceptions(e: CommonServiceException, bucket_name: BucketName):
    for exception_class in PATCHED_EXCEPTIONS:
        if exception_class.code == e.code:
            ex = exception_class(e.message)
            ex.BucketName = bucket_name
            return ex
    return e


def validate_bucket_name(bucket: BucketName):
    if not bucket.islower():
        ex = InvalidBucketName("The specified bucket is not valid.")
        ex.BucketName = bucket
        raise ex

    # match e.code:
    #     case NoSuchBucket.code:
    #         ex = NoSuchBucket(e.message)
    #         ex.BucketName = bucket_name
    #         raise ex
    #     case NoSuchLifecycleConfiguration.code:
    #         ex = NoSuchLifecycleConfiguration(e.message)
    #         ex.BucketName = bucket_name
    #         raise ex
    #
    #     case _:
    #         raise e


# def get_key_from_moto(moto_backend: S3Backend, bucket: BucketName, key: ObjectKey) -> moto_s3_models.FakeKey:
#     return


def get_bucket_from_moto(
    moto_backend: moto_s3_models.S3Backend, bucket: BucketName
) -> moto_s3_models.FakeBucket:
    return moto_backend.get_bucket(bucket_name=bucket)


@singleton_factory
def apply_moto_patches():
    def _fix_key_response(fn, self, *args, **kwargs):
        """Change casing of Last-Modified headers to be picked by the parser"""
        status_code, resp_headers, key_value = fn(self, *args, **kwargs)
        for low_case_header in ["last-modified", "content-type", "content-length"]:
            if header_value := resp_headers.pop(low_case_header, None):
                header_name = _capitalize_header_name_from_snake_case(low_case_header)
                resp_headers[header_name] = header_value

        return status_code, resp_headers, key_value

    patch(moto_s3_responses.S3Response._key_response_get)(_fix_key_response)
    patch(moto_s3_responses.S3Response._key_response_head)(_fix_key_response)


def _capitalize_header_name_from_snake_case(header_name: str) -> str:
    return "-".join([part.capitalize() for part in header_name.split("-")])
