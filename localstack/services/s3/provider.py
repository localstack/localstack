import copy
import json
import logging
import os
from typing import List, Optional, Union
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import moto.s3.models as moto_s3_models
import moto.s3.responses as moto_s3_responses
from botocore.config import Config as BotoConfig
from moto.s3 import s3_backends as moto_s3_backends
from moto.s3.exceptions import MissingBucket

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    AccessControlPolicy,
    AccountId,
    BucketName,
    CompleteMultipartUploadOutput,
    CompleteMultipartUploadRequest,
    CopyObjectOutput,
    CopyObjectRequest,
    CreateBucketOutput,
    CreateBucketRequest,
    DeleteObjectOutput,
    DeleteObjectRequest,
    DeleteObjectTaggingOutput,
    DeleteObjectTaggingRequest,
    Event,
    EventList,
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
    LambdaFunctionConfiguration,
    ListObjectsOutput,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    NoSuchBucket,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    NotificationConfiguration,
    NotificationConfigurationFilter,
    ObjectKey,
    PutBucketAclRequest,
    PutBucketLifecycleConfigurationRequest,
    PutBucketLifecycleRequest,
    PutBucketRequestPaymentRequest,
    PutBucketVersioningRequest,
    PutObjectOutput,
    PutObjectRequest,
    PutObjectTaggingOutput,
    PutObjectTaggingRequest,
    QueueConfiguration,
    S3Api,
    SkipValidation,
    TopicConfiguration,
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
    ALLOWED_HEADER_OVERRIDES,
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
from localstack.utils.strings import short_uid
from localstack.utils.time import timestamp_millis

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"

MOTO_CANONICAL_USER_ID = "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"

HEADER_AMZN_XRAY = "X-Amzn-Trace-Id"

NOTIFICATION_FIELDS = {"TopicArn": "sns", "QueueArn": "sqs", "LambdaFunctionArn": "lambda"}


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


class InvalidArgumentError(CommonServiceException):
    def __init__(self, message: str, name: str, value: str):
        super().__init__("InvalidArgument", message, 400, False)
        # TODO how to set values?


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store() -> S3Store:
        return s3_stores[get_aws_account_id()][aws_stack.get_region()]

    def _clear_bucket_from_store(self, bucket: BucketName):
        store = self.get_store()
        store.bucket_lifecycle_configuration.pop(bucket, None)
        store.bucket_versioning_status.pop(bucket, None)

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
        self._clear_bucket_from_store(bucket)

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
        bucket = request["Bucket"]
        if is_object_expired(context, bucket=bucket, key=key):
            # TODO: old behaviour was deleting key instantly if expired. AWS cleans up only once a day generally
            # see if we need to implement a feature flag
            # but you can still HeadObject on it and you get the expiry time
            ex = NoSuchKey("The specified key does not exist.")
            ex.Key = key
            raise ex

        response: GetObjectOutput = call_moto(context)
        # check for the presence in the response, might be fixed by moto one day
        if "VersionId" in response and bucket not in self.get_store().bucket_versioning_status:
            response.pop("VersionId")

        for request_param, response_param in ALLOWED_HEADER_OVERRIDES.items():
            if request_param_value := request.get(request_param):  # noqa
                response[response_param] = request_param_value  # noqa

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

        # moto interprets the Expires in query string for presigned URL as an Expires header and use it for the object
        # we set it to the correctly parsed value in Request, else we remove it from moto metadata
        moto_backend = get_moto_s3_backend(context)
        bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
        key_object = get_key_from_moto_bucket(bucket, key=request["Key"])
        if expires := request.get("Expires"):
            key_object.set_expiry(expires)
        elif "expires" in key_object.metadata:  # if it got added from query string parameter
            metadata = {k: v for k, v in key_object.metadata.items() if k != "expires"}
            key_object.set_metadata(metadata, replace=True)

        self.send_bucket_notifications(
            context,
            request.get("Bucket"),
            request.get("Key"),
            event=Event.s3_ObjectCreated_Put,
        )
        return response

    @handler("CopyObject", expand=False)
    def copy_object(
        self,
        context: RequestContext,
        request: CopyObjectRequest,
    ) -> CopyObjectOutput:
        response: CopyObjectOutput = call_moto(context)
        self.send_bucket_notifications(
            context,
            request.get("Bucket"),
            request.get("Key"),
            event=Event.s3_ObjectCreated_Copy,
        )
        return response

    @handler("DeleteObject", expand=False)
    def delete_object(
        self,
        context: RequestContext,
        request: DeleteObjectRequest,
    ) -> DeleteObjectOutput:
        # we need to make copies as the bucket and key will get deleted if the request was successful
        bucket = copy.deepcopy(
            get_bucket_from_moto(get_moto_s3_backend(context), bucket=request.get("Bucket"))
        )
        key = copy.deepcopy(bucket.keys.get(request.get("Key")))

        response: DeleteObjectOutput = call_moto(context)
        bucket_notifications = self.get_store().bucket_notification_configs.get(bucket.name)
        if bucket_notifications:
            _send_event_message(
                event_name=Event.s3_ObjectRemoved_Delete,
                bucket=bucket,
                key=key,
                notifications=bucket_notifications,
                xray=context.request.headers.get(HEADER_AMZN_XRAY),
            )
        return response

    @handler("CompleteMultipartUpload", expand=False)
    def complete_multipart_upload(
        self, context: RequestContext, request: CompleteMultipartUploadRequest
    ) -> CompleteMultipartUploadOutput:
        response: CopyObjectOutput = call_moto(context)
        self.send_bucket_notifications(
            context,
            request.get("Bucket"),
            request.get("Key"),
            event=Event.s3_ObjectCreated_CompleteMultipartUpload,
        )
        return response

    @handler("PutObjectTagging", expand=False)
    def put_object_tagging(
        self, context: RequestContext, request: PutObjectTaggingRequest
    ) -> PutObjectTaggingOutput:
        response: PutObjectTaggingOutput = call_moto(context)
        self.send_bucket_notifications(
            context,
            request.get("Bucket"),
            request.get("Key"),
            event=Event.s3_ObjectTagging_Put,
        )
        return response

    @handler("DeleteObjectTagging", expand=False)
    def delete_object_tagging(
        self, context: RequestContext, request: DeleteObjectTaggingRequest
    ) -> DeleteObjectTaggingOutput:
        response: DeleteObjectTaggingOutput = call_moto(context)
        self.send_bucket_notifications(
            context,
            request.get("Bucket"),
            request.get("Key"),
            event=Event.s3_ObjectTagging_Delete,
        )
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

    @handler("PutBucketVersioning", expand=False)
    def put_bucket_versioning(
        self,
        context: RequestContext,
        request: PutBucketVersioningRequest,
    ) -> None:
        call_moto(context)
        # set it in the store, so we can keep the state if it was ever enabled
        if versioning_status := request.get("VersioningConfiguration", {}).get("Status"):
            bucket_name = request.get("Bucket", "")
            store = self.get_store()
            store.bucket_versioning_status[bucket_name] = versioning_status == "Enabled"

    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId = None,
        skip_destination_validation: SkipValidation = None,
    ) -> None:
        # TODO implement put_bucket_notification as well? ->  no longer used https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html
        # TODO expected_bucket_owner

        # check if the bucket exists
        get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)

        for topic in notification_configuration.get("TopicConfigurations", {}):
            self._verify_notification(topic, skip_destination_validation)

        for queue in notification_configuration.get("QueueConfigurations", {}):
            self._verify_notification(queue, skip_destination_validation)

        for cloudfun in notification_configuration.get("LambdaFunctionConfigurations", {}):
            self._verify_notification(cloudfun, skip_destination_validation)

        self.get_store().bucket_notification_configs[bucket] = notification_configuration

    def get_bucket_notification_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfiguration:
        # TODO how to verify expected_bucket_owner
        # check if the bucket exists
        get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)
        return self.get_store().bucket_notification_configs.get(bucket, NotificationConfiguration())

    def send_bucket_notifications(
        self,
        context: RequestContext,
        bucket_name: str,
        key_name: str,
        event: str,
    ):
        if self.get_store().bucket_notification_configs.get(bucket_name):
            bucket = get_moto_s3_backend(context).get_bucket(bucket_name)
            key = bucket.keys.get(key_name)

            _send_event_message(
                event_name=event,
                bucket=bucket,
                key=key,
                notifications=self.get_store().bucket_notification_configs.get(bucket_name),
                xray=context.request.headers.get(HEADER_AMZN_XRAY),
            )

    def _verify_notification(self, notification, skip_destination_validation=False):
        """Does some verification of notification settings:
        - validating the Rule names (and normalizing to capitalized),
        - setting default ID if not provided,
        - check if the filter value is not empty
        - validate the arn pattern
        """

        # id's can be set the request, but need to be auto-generated if they are not provided
        if not notification.get("Id"):
            notification["Id"] = short_uid()

        # arn pattern is always verified
        # will contain the notification-key (e.g. TopicArn) and the actual arn
        tmp = {k: v for k, v in notification.items() if "arn" in k.lower()}
        (type,) = tmp
        (arn,) = tmp.values()

        if not arn.startswith(f"arn:aws:{NOTIFICATION_FIELDS.get(type)}:"):
            # TODO raise InvalidArgument (patch service)
            raise InvalidArgumentError(
                "The ARN is not well formed", name=type.capitalize(), value=arn
            )
        if not skip_destination_validation:
            self._verify_target_exists(NOTIFICATION_FIELDS.get(type), arn)

        if filter_rules := notification.get("Filter", {}).get("Key", {}).get("FilterRules"):
            for rule in filter_rules:
                rule["Name"] = rule["Name"].capitalize()
                if not rule["Name"] in ["Suffix", "Prefix"]:
                    # TODO replace with patched InvalidArgument exception (patch service)
                    raise InvalidArgumentError(
                        "filter rule name must be either prefix or suffix",
                        rule["Name"],
                        rule["Value"],
                    )
                if not rule["Value"]:
                    raise InvalidArgumentError(
                        "filter value cannot be empty", rule["Name"], rule["Value"]
                    )

    def _verify_target_exists(self, type: str, arn: str):
        """verifies if the notification target exists, by trying to access the resource"""
        region_name = aws_stack.extract_region_from_arn(arn)
        client = aws_stack.connect_to_service(type, region_name=region_name)
        account_id = aws_stack.extract_account_id_from_arn(arn)

        # TODO raise InvalidArgument error here (patch service)
        #      it somehow adds numbers here, e.g. ArgumentValue1, ArgumentName1

        if type == "sqs":
            try:
                queue_name = arn.split(":")[-1]
                client.get_queue_url(QueueName=queue_name, QueueOwnerAWSAccountId=account_id)
            except Exception:  # noqa
                raise InvalidArgumentError(
                    "Unable to validate the following destination configurations",
                    name=arn,
                    value="The destination queue does not exist",
                )
        elif type == "lambda":
            try:
                function_name = aws_stack.lambda_function_name(arn)
                client.get_function(FunctionName=function_name)
            except Exception:  # noqua
                raise InvalidArgumentError(
                    "Unable to validate the following destination configurations",
                    name=arn,
                    value="The destination Lambda does not exist",
                )
        elif type == "sns":
            try:
                client.get_topic_attributes(TopicArn=arn)
            except Exception:  # noqua
                raise InvalidArgumentError(
                    "Unable to validate the following destination configurations",
                    name=arn,
                    value="The destination topic does not exist",
                )

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


def normalize_bucket_name(bucket_name):
    bucket_name = bucket_name or ""
    bucket_name = bucket_name.lower()
    return bucket_name


def _send_event_message_to_topic(
    notification: TopicConfiguration,
    event_name: str,
    bucket: moto_s3_models.FakeBucket,
    key: moto_s3_models.FakeKey,
    xray: str = None,
):
    event_body = _get_event_message(
        event_name=event_name[3:],
        bucket_name=bucket.name,
        config_id=notification.get("Id"),
        key_name=key.name,
        key_etag=key.etag,
        key_size=key.contentsize,
        version_id=key.version_id if bucket.is_versioned else None,
    )
    message = json.dumps(event_body)
    topic_arn = notification["TopicArn"]

    region_name = aws_stack.extract_region_from_arn(topic_arn)
    sns_client = aws_stack.connect_to_service("sns", region_name=region_name)
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject="Amazon S3 Notification",
        )
    except Exception as e:
        LOG.warning(
            f'Unable to send notification for S3 bucket "{bucket.name}" to SNS topic "{topic_arn}": {e}'
        )


def _send_event_message_to_lambda(
    notification: LambdaFunctionConfiguration,
    event_name: str,
    bucket: moto_s3_models.FakeBucket,
    key: moto_s3_models.FakeKey,
    xray: str = None,
):
    event_body = _get_event_message(
        event_name=event_name[3:],
        bucket_name=bucket.name,
        config_id=notification.get("Id"),
        key_name=key.name,
        key_etag=key.etag,
        key_size=key.contentsize,
        version_id=key.version_id if bucket.is_versioned else None,
    )
    message = json.dumps(event_body)
    lambda_arn = notification["LambdaFunctionArn"]

    region_name = aws_stack.extract_region_from_arn(lambda_arn)
    # make sure we don't run into a socket timeout
    connection_config = BotoConfig(read_timeout=300)
    lambda_client = aws_stack.connect_to_service(
        "lambda", config=connection_config, region_name=region_name
    )
    lambda_function_config = aws_stack.lambda_function_name(lambda_arn)
    try:
        lambda_client.invoke(
            FunctionName=lambda_function_config,
            InvocationType="Event",
            Payload=message,
        )
    except Exception:
        LOG.warning(
            f'Unable to send notification for S3 bucket "{bucket.name}" to Lambda function "{lambda_function_config}".'
        )


def _send_event_message_to_queue(
    notification: QueueConfiguration,
    event_name: str,
    bucket: moto_s3_models.FakeBucket,
    key: moto_s3_models.FakeKey,
    xray: str = None,
):
    event_body = _get_event_message(
        event_name=event_name[3:],
        bucket_name=bucket.name,
        config_id=notification.get("Id"),
        key_name=key.name,
        key_etag=key.etag,
        key_size=key.contentsize,
        version_id=key.version_id if bucket.is_versioned else None,
    )
    message = json.dumps(event_body)
    queue_arn = notification["QueueArn"]

    region_name = aws_stack.extract_region_from_arn(queue_arn)
    queue_name = queue_arn.split(":")[-1]
    sqs_client = aws_stack.connect_to_service("sqs", region_name=region_name)
    try:
        queue_url = aws_stack.sqs_queue_url_for_arn(queue_arn)
        system_attributes = {}
        if xray:
            system_attributes["AWSTraceHeader"] = {
                "DataType": "String",
                "StringValue": xray,
            }
        sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=message,
            MessageSystemAttributes=system_attributes,
        )
    except Exception as e:
        LOG.warning(
            f'Unable to send notification for S3 bucket "{bucket.name}" to SQS queue "{queue_name}": {e}',
        )


def _matching_event(events: EventList, event_name: str) -> bool:
    if event_name in events:
        return True
    wildcard_pattern = f"{event_name[0:event_name.rindex(':')]}:*"
    if wildcard_pattern in events:
        return True
    return False


def _matching_filter(filter: Optional[NotificationConfigurationFilter], key_name: str) -> bool:
    if not filter or not filter.get("Key", {}).get("FilterRules"):
        return True
    filter_rules = filter.get("Key").get("FilterRules")
    for rule in filter_rules:
        name = rule.get("Name", "").lower()
        value = rule.get("Value", "")
        if name == "prefix" and not key_name.startswith(value):
            return False
        if name == "suffix" and not key_name.endswith(value):
            return False

    return True


def _send_event_to_event_bridge(
    event_name: str,
    bucket: moto_s3_models.FakeBucket,
    key: moto_s3_models.FakeKey,
    xray: str = None,
):
    s3api_client = aws_stack.connect_to_service("s3")
    region = (
        s3api_client.get_bucket_location(Bucket=bucket.name)["LocationConstraint"]
        or config.DEFAULT_REGION
    )
    events_client = aws_stack.connect_to_service("events", region_name=region)
    # structure defined here: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html
    entry = {
        "Source": "aws.s3",
        "Resources": [f"arn:aws:s3:::{bucket.name}"],
        "Detail": {
            "version": "0",
            "bucket": {"name": bucket.name},
            "object": {
                "key": key.name,
                "size": key.size,
                "etag": key.etag.strip('"'),
                "sequencer": "0062E99A88DC407460",
            },
            "request-id": "RKREYG1RN2X92YX6",
            "requester": "074255357339",
            "source-ip-address": "127.0.0.1",  # TODO previously headers.get("X-Forwarded-For", "127.0.0.1").split(",")[0]
        },
    }
    # messages are bit different for EventBridge, see https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html
    if "ObjectCreated" in event_name:
        entry["DetailType"] = "Object Created"
        event_type = event_name[event_name.rindex(":") + 1 :]
        if event_type in ["Put", "Post", "Copy"]:
            event_type = f"{event_type}Object"
        entry["Detail"]["reason"] = event_type

    if "ObjectRemoved" in event_name:
        entry["DetailType"] = "Object Deleted"
        entry["Detail"]["reason"] = "DeleteObject"
        entry["Detail"]["deletion-type"] = "Permanently Deleted"
        entry["Detail"]["object"].pop("etag")
        entry["Detail"]["object"].pop("size")

    if "ObjectTagging" in event_name:
        entry["DetailType"] = "Object Tags Added" if "Put" in event_name else "Object Tags Deleted"

    entry["Detail"] = json.dumps(entry["Detail"])

    try:
        events_client.put_events(Entries=[entry])
    except Exception as e:
        LOG.exception(f'Unable to send notification for S3 bucket "{bucket}" to EventBridge', e)


def _send_event_message(
    event_name: str,
    bucket: moto_s3_models.FakeBucket,
    key: moto_s3_models.FakeKey,
    notifications: NotificationConfiguration,
    xray: str = None,
):
    for notification in notifications.get("QueueConfigurations", {}):
        if _matching_event(notification["Events"], event_name) and _matching_filter(
            notification.get("Filter"), key.name
        ):
            _send_event_message_to_queue(notification, event_name, bucket, key, xray)

    for notification in notifications.get("TopicConfigurations", {}):
        if _matching_event(notification["Events"], event_name) and _matching_filter(
            notification.get("Filter"), key.name
        ):
            _send_event_message_to_topic(notification, event_name, bucket, key, xray)

    for notification in notifications.get("LambdaFunctionConfigurations", {}):
        if _matching_event(notification["Events"], event_name) and _matching_filter(
            notification.get("Filter"), key.name
        ):
            _send_event_message_to_lambda(notification, event_name, bucket, key, xray)

    if "EventBridgeConfiguration" in notifications:
        _send_event_to_event_bridge(event_name, bucket, key)


def _get_event_message(
    event_name: str,
    bucket_name: str,
    config_id: str,
    key_name: str,
    key_size: int,
    key_etag: str,
    version_id: str = None,
) -> List[dict]:
    # Based on: http://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
    bucket_name = normalize_bucket_name(bucket_name)
    content = {
        "eventVersion": "2.1",
        "eventSource": "aws:s3",
        "awsRegion": aws_stack.get_region(),
        "eventTime": timestamp_millis(),
        "eventName": event_name,
        "userIdentity": {"principalId": "AIDAJDPLRKLG7UEXAMPLE"},
        "requestParameters": {
            "sourceIPAddress": "127.0.0.1"
        },  # TODO sourceIPAddress was previously extracted from headers ("X-Forwarded-For")
        "responseElements": {
            "x-amz-request-id": short_uid(),
            "x-amz-id-2": "eftixk72aD6Ap51TnqcoF8eFidJG9Z/2",  # Amazon S3 host that processed the request
        },
        "s3": {
            "s3SchemaVersion": "1.0",
            "configurationId": config_id,
            "bucket": {
                "name": bucket_name,
                "ownerIdentity": {"principalId": "A3NL1KOZZKExample"},
                "arn": "arn:aws:s3:::%s" % bucket_name,
            },
            "object": {
                "key": quote(key_name),
                "sequencer": "0055AED6DCD90281E5",
            },
        },
    }
    if version_id:
        # object version if bucket is versioning-enabled, otherwise null
        content["s3"]["object"]["versionId"] = version_id
    if "created" in event_name.lower():
        content["s3"]["object"]["size"] = key_size
        content["s3"]["object"]["eTag"] = key_etag.strip('"')
    if "ObjectTagging" in event_name:
        content["eventVersion"] = "2.3"
        content["s3"]["object"]["eTag"] = key_etag.strip('"')
        content["s3"]["object"].pop("sequencer")
    return {"Records": [content]}


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

    @patch(moto_s3_responses.S3Response._key_response_post)
    def _fix_key_response_post(fn, self, request, body, bucket_name, *args, **kwargs):
        code, headers, body = fn(self, request, body, bucket_name, *args, **kwargs)
        bucket = self.backend.get_bucket(bucket_name)
        if not bucket.is_versioned:
            headers.pop("x-amz-version-id", None)

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
