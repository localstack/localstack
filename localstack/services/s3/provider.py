import logging
import os
from urllib.parse import quote

import moto.s3.models as moto_s3_models
import moto.s3.responses as moto_s3_responses
from moto.s3 import s3_backends as moto_s3_backends
from moto.s3.exceptions import MissingBucket

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    AccountId,
    BucketName,
    CreateBucketOutput,
    CreateBucketRequest,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLifecycleOutput,
    GetBucketRequestPaymentOutput,
    GetBucketRequestPaymentRequest,
    GetObjectOutput,
    GetObjectRequest,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidBucketName,
    ListObjectsOutput,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    NoSuchBucket,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    ObjectKey,
    PutBucketLifecycleConfigurationRequest,
    PutBucketLifecycleRequest,
    PutBucketRequestPaymentRequest,
    PutObjectOutput,
    PutObjectRequest,
    S3Api,
)
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.models import S3Store, s3_stores
from localstack.services.s3.utils import is_bucket_name_valid, is_key_expired, verify_checksum
from localstack.utils.aws import aws_stack
from localstack.utils.objects import singleton_factory
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"


class MalformedXML(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("MalformedXML", status_code=400, message=message)


def get_moto_s3_backend(context: RequestContext) -> moto_s3_models.S3Backend:
    return moto_s3_backends[context.account_id]["global"]


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store() -> S3Store:
        return s3_stores[get_aws_account_id()][aws_stack.get_region()]

    def on_after_init(self):
        apply_moto_patches()

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self,
        context: RequestContext,
        request: CreateBucketRequest,
    ) -> CreateBucketOutput:
        bucket_name = request.get("Bucket", "")
        validate_bucket_name(bucket=bucket_name)

        response: CreateBucketOutput = call_moto(context)
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
            bucket = get_bucket_from_moto(moto_backend, bucket=request.get("Bucket", ""))
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
            bucket = get_bucket_from_moto(moto_backend, bucket=request.get("Bucket", ""))
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
        response: GetObjectOutput = call_moto(context)
        key = request.get("Key", "")
        if is_object_expired(context, bucket=request.get("Bucket", ""), key=key):
            # TODO: old behaviour was deleting key instantly if expired. AWS cleans up only once a day generally
            # see if we need to implement a feature flag
            # but you can still HeadObject on it and you get the expiry time
            ex = NoSuchKey("The specified key does not exist.")
            ex.Key = key
            raise ex

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
            bucket = get_bucket_from_moto(moto_backend, bucket=request.get("Bucket", ""))
            key = request.get("Key", "")
            key_object = get_key_from_moto_bucket(bucket, key=key)
            key_object.set_expiry(expires)

        return response

    @handler("PutBucketRequestPayment", expand=False)
    def put_bucket_request_payment(
        self,
        context: RequestContext,
        request: PutBucketRequestPaymentRequest,
    ) -> None:
        bucket_name = request.get("Bucket", "")
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
        bucket_name = request.get("Bucket", "")
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
        bucket = request.get("Bucket", "")
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


def validate_bucket_name(bucket: BucketName):
    """
    Validate s3 bucket name based on the documentation
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    if not is_bucket_name_valid(bucket_name=bucket):
        ex = InvalidBucketName("The specified bucket is not valid.")
        ex.BucketName = bucket
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
    def _bucket_response_head(fn, self, bucket_name, *args, **kwargs):
        code, headers, body = fn(self, bucket_name, *args, **kwargs)
        bucket = self.backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
        return code, headers, body


def _capitalize_header_name_from_snake_case(header_name: str) -> str:
    return "-".join([part.capitalize() for part in header_name.split("-")])


# TODO: check if filter works with current provider
