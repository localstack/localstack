import copy
import logging
import os
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import moto.s3.models as moto_s3_models
import moto.s3.responses as moto_s3_responses
from moto.s3 import s3_backends as moto_s3_backends

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.s3 import (
    AccountId,
    BucketName,
    CreateBucketOutput,
    CreateBucketRequest,
    GetBucketLocationOutput,
    GetObjectOutput,
    GetObjectRequest,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidBucketName,
    ListObjectsOutput,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    PutObjectOutput,
    PutObjectRequest,
    S3Api,
)
from localstack.config import get_edge_port_http, get_protocol
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.http import Request, Response
from localstack.http.proxy import forward
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.models import S3Store, s3_stores
from localstack.services.s3.utils import verify_checksum
from localstack.utils.aws import aws_stack
from localstack.utils.aws.request_context import AWS_REGION_REGEX
from localstack.utils.objects import singleton_factory
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"


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
        bucket_name = request.get("Bucket", "")
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
        return response

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


def validate_bucket_name(bucket: BucketName):
    # TODO: add rules to validate bucket name
    if not bucket.islower():
        ex = InvalidBucketName("The specified bucket is not valid.")
        ex.BucketName = bucket
        raise ex


def get_bucket_from_moto(
    moto_backend: moto_s3_models.S3Backend, bucket: BucketName
) -> moto_s3_models.FakeBucket:
    return moto_backend.get_bucket(bucket_name=bucket)


@singleton_factory
def apply_moto_patches():
    @patch(moto_s3_responses.S3Response.key_response)
    def _fix_key_response(fn, self, *args, **kwargs):
        """Change casing of Last-Modified headers to be picked by the parser"""
        status_code, resp_headers, key_value = fn(self, *args, **kwargs)
        for low_case_header in ["last-modified", "content-type", "content-length"]:
            if header_value := resp_headers.pop(low_case_header, None):
                header_name = _capitalize_header_name_from_snake_case(low_case_header)
                resp_headers[header_name] = header_value

        return status_code, resp_headers, key_value

    @patch(moto_s3_responses.S3Response._bucket_response_head)
    def _bucket_response_head(fn, self, bucket_name, *args, **kwargs):
        code, headers, body = fn(self, bucket_name, *args, **kwargs)
        bucket = self.backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
        headers["content-type"] = "application/xml"
        return code, headers, body


def _capitalize_header_name_from_snake_case(header_name: str) -> str:
    return "-".join([part.capitalize() for part in header_name.split("-")])
