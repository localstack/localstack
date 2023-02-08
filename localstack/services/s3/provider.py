import logging
import os
from typing import IO, Dict, List
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import moto.s3.responses as moto_s3_responses

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, ServiceException, handler
from localstack.aws.api.s3 import (
    MFA,
    AccessControlPolicy,
    AccountId,
    Body,
    BucketName,
    BypassGovernanceRetention,
    ChecksumAlgorithm,
    CompleteMultipartUploadOutput,
    CompleteMultipartUploadRequest,
    ContentMD5,
    CopyObjectOutput,
    CopyObjectRequest,
    CORSConfiguration,
    CreateBucketOutput,
    CreateBucketRequest,
    CreateMultipartUploadOutput,
    CreateMultipartUploadRequest,
    Delete,
    DeleteObjectOutput,
    DeleteObjectRequest,
    DeleteObjectTaggingOutput,
    DeleteObjectTaggingRequest,
    DeleteResult,
    ETag,
    GetBucketAclOutput,
    GetBucketCorsOutput,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLifecycleOutput,
    GetBucketLocationOutput,
    GetBucketReplicationOutput,
    GetBucketRequestPaymentOutput,
    GetBucketRequestPaymentRequest,
    GetBucketWebsiteOutput,
    GetObjectAclOutput,
    GetObjectAttributesOutput,
    GetObjectAttributesParts,
    GetObjectAttributesRequest,
    GetObjectOutput,
    GetObjectRequest,
    GetObjectTaggingOutput,
    GetObjectTaggingRequest,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidBucketName,
    InvalidPartOrder,
    InvalidStorageClass,
    ListBucketResult,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    MissingSecurityHeader,
    NoSuchBucket,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    NoSuchWebsiteConfiguration,
    NotificationConfiguration,
    ObjectIdentifier,
    ObjectKey,
    ObjectLockToken,
    ObjectVersionId,
    PostResponse,
    PutBucketAclRequest,
    PutBucketLifecycleConfigurationRequest,
    PutBucketLifecycleRequest,
    PutBucketRequestPaymentRequest,
    PutBucketVersioningRequest,
    PutObjectAclOutput,
    PutObjectAclRequest,
    PutObjectOutput,
    PutObjectRequest,
    PutObjectTaggingOutput,
    PutObjectTaggingRequest,
    ReplicationConfiguration,
    ReplicationConfigurationNotFoundError,
    RequestPayer,
    S3Api,
    SkipValidation,
)
from localstack.aws.api.s3 import Type as GranteeType
from localstack.aws.api.s3 import WebsiteConfiguration
from localstack.aws.handlers import (
    modify_service_response,
    preprocess_request,
    serve_custom_service_request_handlers,
)
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.cors import S3CorsHandler
from localstack.services.s3.models import S3Store, get_moto_s3_backend, s3_stores
from localstack.services.s3.notifications import NotificationDispatcher, S3EventNotificationContext
from localstack.services.s3.presigned_url import (
    s3_presigned_url_request_handler,
    s3_presigned_url_response_handler,
    validate_post_policy,
)
from localstack.services.s3.utils import (
    ALLOWED_HEADER_OVERRIDES,
    VALID_ACL_PREDEFINED_GROUPS,
    VALID_GRANTEE_PERMISSIONS,
    VALID_STORAGE_CLASSES,
    _create_invalid_argument_exc,
    capitalize_header_name_from_snake_case,
    get_bucket_from_moto,
    get_header_name,
    get_key_from_moto_bucket,
    is_bucket_name_valid,
    is_canned_acl_bucket_valid,
    is_key_expired,
    is_valid_canonical_id,
    validate_kms_key_id,
    verify_checksum,
)
from localstack.services.s3.website_hosting import register_website_hosting_routes
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import s3_bucket_name
from localstack.utils.collections import get_safe
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"

MOTO_CANONICAL_USER_ID = "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
# max file size for S3 objects kept in memory (500 KB by default)
S3_MAX_FILE_SIZE_BYTES = 512 * 1024


class MalformedXML(CommonServiceException):
    def __init__(self, message=None):
        if not message:
            message = "The XML you provided was not well-formed or did not validate against our published schema"
        super().__init__("MalformedXML", status_code=400, message=message)


class MalformedACLError(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("MalformedACLError", status_code=400, message=message)


class InvalidRequest(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InvalidRequest", status_code=400, message=message)


class UnexpectedContent(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("UnexpectedContent", status_code=400, message=message)


def get_full_default_bucket_location(bucket_name):
    if config.HOSTNAME_EXTERNAL != config.LOCALHOST:
        return f"{config.get_protocol()}://{config.HOSTNAME_EXTERNAL}:{config.get_edge_port_http()}/{bucket_name}/"
    return f"{config.get_protocol()}://{bucket_name}.s3.{LOCALHOST_HOSTNAME}:{config.get_edge_port_http()}/"


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store() -> S3Store:
        return s3_stores[get_aws_account_id()][aws_stack.get_region()]

    def _clear_bucket_from_store(self, bucket: BucketName):
        store = self.get_store()
        store.bucket_lifecycle_configuration.pop(bucket, None)
        store.bucket_versioning_status.pop(bucket, None)
        store.bucket_cors.pop(bucket, None)
        store.bucket_notification_configs.pop(bucket, None)
        store.bucket_replication.pop(bucket, None)
        store.bucket_website_configuration.pop(bucket, None)

    def on_after_init(self):
        apply_moto_patches()
        preprocess_request.append(self._cors_handler)
        register_website_hosting_routes(router=ROUTER)
        register_custom_handlers()
        # registering of virtual host routes happens with the hook on_infra_ready in virtual_host.py
        # create a AWS managed KMS key at start and save it in the store for persistence?

    def __init__(self) -> None:
        super().__init__()
        self._notification_dispatcher = NotificationDispatcher()
        self._cors_handler = S3CorsHandler()

    def on_before_stop(self):
        self._notification_dispatcher.shutdown()

    def _notify(
        self,
        context: RequestContext,
        s3_notif_ctx: S3EventNotificationContext = None,
        key_name: ObjectKey = None,
    ):
        # we can provide the s3_event_notification_context, so in case of deletion of keys, we can create it before
        # it happens
        if not s3_notif_ctx:
            s3_notif_ctx = S3EventNotificationContext.from_request_context(
                context, key_name=key_name
            )
        if notification_config := self.get_store().bucket_notification_configs.get(
            s3_notif_ctx.bucket_name
        ):
            self._notification_dispatcher.send_notifications(s3_notif_ctx, notification_config)

    def _verify_notification_configuration(
        self,
        notification_configuration: NotificationConfiguration,
        skip_destination_validation: SkipValidation,
    ):
        self._notification_dispatcher.verify_configuration(
            notification_configuration, skip_destination_validation
        )

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
        self._cors_handler.invalidate_cache()
        return response

    def delete_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        call_moto(context)
        self._clear_bucket_from_store(bucket)
        self._cors_handler.invalidate_cache()

    def get_bucket_location(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLocationOutput:
        """
        When implementing the ASF provider, this operation is implemented because:
        - The spec defines a root element GetBucketLocationOutput containing a LocationConstraint member, where
          S3 actually just returns the LocationConstraint on the root level (only operation so far that we know of).
        - We circumvent the root level element here by patching the spec such that this operation returns a
          single "payload" (the XML body response), which causes the serializer to directly take the payload element.
        - The above "hack" causes the fix in the serializer to not be picked up here as we're passing the XML body as
          the payload, which is why we need to manually do this here by manipulating the string.
        Botocore implements this hack for parsing the response in `botocore.handlers.py#parse_get_bucket_location`
        """
        response = call_moto(context)

        location_constraint_xml = response["LocationConstraint"]
        xml_root_end = location_constraint_xml.find(">") + 1
        location_constraint_xml = (
            f"{location_constraint_xml[:xml_root_end]}\n{location_constraint_xml[xml_root_end:]}"
        )
        response["LocationConstraint"] = location_constraint_xml[:]
        return response

    @handler("ListObjects", expand=False)
    def list_objects(
        self,
        context: RequestContext,
        request: ListObjectsRequest,
    ) -> ListBucketResult:
        response: ListBucketResult = call_moto(context)

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

        return ListBucketResult(**response)

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

        moto_backend = get_moto_s3_backend(context)
        bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, bucket)

        try:
            response: PutObjectOutput = call_moto(context)
        except CommonServiceException as e:
            # missing attributes in exception
            if e.code == "InvalidStorageClass":
                raise InvalidStorageClass(
                    "The storage class you specified is not valid",
                    StorageClassRequested=request.get("StorageClass"),
                )
            raise

        # moto interprets the Expires in query string for presigned URL as an Expires header and use it for the object
        # we set it to the correctly parsed value in Request, else we remove it from moto metadata
        key_object = get_key_from_moto_bucket(bucket, key=request["Key"])
        if expires := request.get("Expires"):
            key_object.set_expiry(expires)
        elif "expires" in key_object.metadata:  # if it got added from query string parameter
            metadata = {k: v for k, v in key_object.metadata.items() if k != "expires"}
            key_object.set_metadata(metadata, replace=True)

        self._notify(context)

        return response

    @handler("CopyObject", expand=False)
    def copy_object(
        self,
        context: RequestContext,
        request: CopyObjectRequest,
    ) -> CopyObjectOutput:
        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
            validate_kms_key_id(sse_kms_key_id, bucket)

        response: CopyObjectOutput = call_moto(context)
        self._notify(context)
        return response

    @handler("DeleteObject", expand=False)
    def delete_object(
        self,
        context: RequestContext,
        request: DeleteObjectRequest,
    ) -> DeleteObjectOutput:

        if request["Bucket"] not in self.get_store().bucket_notification_configs:
            return call_moto(context)

        # create the notification context before deleting the object, to be able to retrieve its properties
        s3_notification_ctx = S3EventNotificationContext.from_request_context(context)

        response: DeleteObjectOutput = call_moto(context)
        self._notify(context, s3_notification_ctx)

        return response

    def delete_objects(
        self,
        context: RequestContext,
        bucket: BucketName,
        delete: Delete,
        mfa: MFA = None,
        request_payer: RequestPayer = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        expected_bucket_owner: AccountId = None,
        checksum_algorithm: ChecksumAlgorithm = None,
    ) -> DeleteResult:
        objects: List[ObjectIdentifier] = delete.get("Objects")
        deleted_objects = {}
        quiet = delete.get("Quiet", False)
        for object in objects:
            key = object["Key"]
            # create the notification context before deleting the object, to be able to retrieve its properties
            s3_notification_ctx = S3EventNotificationContext.from_request_context(
                context, key_name=key, allow_non_existing_key=True
            )

            deleted_objects[key] = s3_notification_ctx
        result: DeleteResult = call_moto(context)
        for deleted in result.get("Deleted"):
            if deleted_objects.get(deleted["Key"]):
                self._notify(context, deleted_objects.get(deleted["Key"]))

        if not quiet:
            return result

        #  In quiet mode the response includes only keys where the delete action encountered an error.
        #  For a successful deletion, the action does not return any information about the delete in the response body.
        result.pop("Deleted", "")
        return result

    @handler("CreateMultipartUpload", expand=False)
    def create_multipart_upload(
        self,
        context: RequestContext,
        request: CreateMultipartUploadRequest,
    ) -> CreateMultipartUploadOutput:
        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            moto_backend = get_moto_s3_backend(context)
            bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
            validate_kms_key_id(sse_kms_key_id, bucket)

        if (
            storage_class := request.get("StorageClass")
        ) and storage_class not in VALID_STORAGE_CLASSES:
            raise InvalidStorageClass(
                "The storage class you specified is not valid",
                StorageClassRequested=storage_class,
            )

        response: CreateMultipartUploadOutput = call_moto(context)
        return response

    @handler("CompleteMultipartUpload", expand=False)
    def complete_multipart_upload(
        self, context: RequestContext, request: CompleteMultipartUploadRequest
    ) -> CompleteMultipartUploadOutput:
        parts = request.get("MultipartUpload", {}).get("Parts", [])
        parts_numbers = [part.get("PartNumber") for part in parts]
        # sorted is very fast (fastest) if the list is already sorted, which should be the case
        if sorted(parts_numbers) != parts_numbers:
            raise InvalidPartOrder(
                "The list of parts was not in ascending order. Parts must be ordered by part number.",
                UploadId=request["UploadId"],
            )

        response: CompleteMultipartUploadOutput = call_moto(context)

        # moto return the Location in AWS `http://{bucket}.s3.amazonaws.com/{key}`
        response[
            "Location"
        ] = f'{get_full_default_bucket_location(request["Bucket"])}{response["Key"]}'
        self._notify(context)
        return response

    @handler("GetObjectTagging", expand=False)
    def get_object_tagging(
        self, context: RequestContext, request: GetObjectTaggingRequest
    ) -> GetObjectTaggingOutput:
        response: GetObjectTaggingOutput = call_moto(context)
        if (
            "VersionId" in response
            and request["Bucket"] not in self.get_store().bucket_versioning_status
        ):
            response.pop("VersionId")
        return response

    @handler("PutObjectTagging", expand=False)
    def put_object_tagging(
        self, context: RequestContext, request: PutObjectTaggingRequest
    ) -> PutObjectTaggingOutput:
        response: PutObjectTaggingOutput = call_moto(context)
        self._notify(context)
        return response

    @handler("DeleteObjectTagging", expand=False)
    def delete_object_tagging(
        self, context: RequestContext, request: DeleteObjectTaggingRequest
    ) -> DeleteObjectTaggingOutput:
        response: DeleteObjectTaggingOutput = call_moto(context)
        self._notify(context)
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
            raise MalformedXML()

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

    def put_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        replication_configuration: ReplicationConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        token: ObjectLockToken = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        if not moto_bucket.is_versioned:
            raise InvalidRequest(
                "Versioning must be 'Enabled' on the bucket to apply a replication configuration"
            )

        for rule in replication_configuration.get("Rules", {}):
            if "ID" not in rule:
                rule["ID"] = short_uid()

        store = self.get_store()
        for rule in replication_configuration.get("Rules", []):
            dst = rule.get("Destination", {}).get("Bucket")
            dst_bucket_name = s3_bucket_name(dst)
            dst_bucket = None
            try:
                dst_bucket = get_bucket_from_moto(moto_backend, bucket=dst_bucket_name)
            except NoSuchBucket:
                # according to AWS testing it returns in this case the same exception as if versioning was disabled
                pass
            if not dst_bucket or not dst_bucket.is_versioned:
                raise InvalidRequest("Destination bucket must have versioning enabled.")

        # TODO more validation on input
        store.bucket_replication[bucket] = replication_configuration

    def get_bucket_replication(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketReplicationOutput:
        # test if bucket exists in moto
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket=bucket)

        store = self.get_store()
        replication = store.bucket_replication.get(bucket, None)
        if not replication:
            ex = ReplicationConfigurationNotFoundError(
                "The replication configuration was not found"
            )
            ex.BucketName = bucket
            raise ex

        return GetBucketReplicationOutput(ReplicationConfiguration=replication)

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

    def put_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        cors_configuration: CORSConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        response = call_moto(context)
        self.get_store().bucket_cors[bucket] = cors_configuration
        self._cors_handler.invalidate_cache()
        return response

    def get_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketCorsOutput:
        call_moto(context)
        cors_rules = self.get_store().bucket_cors.get(bucket)
        return GetBucketCorsOutput(CORSRules=cors_rules["CORSRules"])

    def delete_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        response = call_moto(context)
        if self.get_store().bucket_cors.pop(bucket, None):
            self._cors_handler.invalidate_cache()
        return response

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
        canned_acl = request.get("ACL")

        grant_keys = [
            "GrantFullControl",
            "GrantRead",
            "GrantReadACP",
            "GrantWrite",
            "GrantWriteACP",
        ]
        present_headers = [
            (key, grant_header) for key in grant_keys if (grant_header := request.get(key))
        ]
        # FIXME: this is very dirty, but the parser does not differentiate between an empty body and an empty XML node
        # errors are different depending on that data, so we need to access the context. Modifying the parser for this
        # use case seems dangerous
        is_acp_in_body = context.request.data

        if not (canned_acl or present_headers or is_acp_in_body):
            raise MissingSecurityHeader(
                "Your request was missing a required header", MissingHeaderName="x-amz-acl"
            )

        elif canned_acl and present_headers:
            raise InvalidRequest("Specifying both Canned ACLs and Header Grants is not allowed")

        elif (canned_acl or present_headers) and is_acp_in_body:
            raise UnexpectedContent("This request does not support content")

        if canned_acl:
            validate_canned_acl(canned_acl)

        elif present_headers:
            for key, grantees_values in present_headers:
                validate_grantee_in_headers(key, grantees_values)

        elif acp := request.get("AccessControlPolicy"):
            validate_acl_acp(acp)

        call_moto(context)

    def get_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectAclOutput:
        response: GetObjectAclOutput = call_moto(context)

        for grant in response["Grants"]:
            grantee = grant.get("Grantee", {})
            if grantee.get("ID") == MOTO_CANONICAL_USER_ID:
                # adding the DisplayName used by moto for the owner
                grantee["DisplayName"] = "webfile"

        return response

    @handler("PutObjectAcl", expand=False)
    def put_object_acl(
        self,
        context: RequestContext,
        request: PutObjectAclRequest,
    ) -> PutObjectAclOutput:
        validate_canned_acl(request.get("ACL"))

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

        moto_backend = get_moto_s3_backend(context)
        key = get_key_from_moto_bucket(
            get_bucket_from_moto(moto_backend, bucket=request["Bucket"]), key=request["Key"]
        )
        acl = key.acl

        response: PutObjectOutput = call_moto(context)
        new_acl = key.acl

        if acl != new_acl:
            self._notify(context)

        return response

    @handler("PutBucketVersioning", expand=False)
    def put_bucket_versioning(
        self,
        context: RequestContext,
        request: PutBucketVersioningRequest,
    ) -> None:
        call_moto(context)
        # set it in the store, so we can keep the state if it was ever enabled
        if versioning_status := request.get("VersioningConfiguration", {}).get("Status"):
            bucket_name = request["Bucket"]
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
        self._verify_notification_configuration(
            notification_configuration, skip_destination_validation
        )
        self.get_store().bucket_notification_configs[bucket] = notification_configuration

    def get_bucket_notification_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfiguration:
        # TODO how to verify expected_bucket_owner
        # check if the bucket exists
        get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)
        return self.get_store().bucket_notification_configs.get(bucket, NotificationConfiguration())

    def get_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketWebsiteOutput:
        # to check if the bucket exists
        # TODO: simplify this when we don't use moto
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket)

        if not (website_configuration := self.get_store().bucket_website_configuration.get(bucket)):
            ex = NoSuchWebsiteConfiguration(
                "The specified bucket does not have a website configuration"
            )
            ex.BucketName = bucket
            raise ex

        return website_configuration

    def put_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        website_configuration: WebsiteConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        # to check if the bucket exists
        # TODO: simplify this when we don't use moto
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket)

        validate_website_configuration(website_configuration)
        store = self.get_store()
        store.bucket_website_configuration[bucket] = website_configuration

    def delete_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        # to check if the bucket exists
        # TODO: simplify this when we don't use moto
        moto_backend = get_moto_s3_backend(context)
        get_bucket_from_moto(moto_backend, bucket)
        # does not raise error if the bucket did not have a config, will simply return
        self.get_store().bucket_website_configuration.pop(bucket, None)

    def post_object(
        self, context: RequestContext, bucket: BucketName, body: IO[Body] = None
    ) -> PostResponse:
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html
        # TODO: signature validation is not implemented for pre-signed POST
        # policy validation is not implemented either, except expiration and mandatory fields
        validate_post_policy(context.request.form)

        # Botocore has trouble parsing responses with status code in the 3XX range, it interprets them as exception
        # it then raises a nonsense one with a wrong code
        # We have to create and populate the response manually if that happens
        try:
            response: PostResponse = call_moto(context=context)
        except ServiceException as e:
            if e.status_code == 303:
                # the parser did not succeed in parsing the moto respond, we start constructing the response ourselves
                response = PostResponse(StatusCode=e.status_code)
            else:
                raise e

        key_name = context.request.form.get("key")
        if "${filename}" in key_name:
            key_name = key_name.replace("${filename}", context.request.files["file"].filename)

        moto_backend = get_moto_s3_backend(context)
        key = get_key_from_moto_bucket(
            get_bucket_from_moto(moto_backend, bucket=bucket), key=key_name
        )
        # hacky way to set the etag in the headers as well: two locations for one value
        response["ETagHeader"] = key.etag

        if response["StatusCode"] == 303:
            # we need to create the redirect, as the parser could not return the moto-calculated one
            try:
                redirect = _create_redirect_for_post_request(
                    base_redirect=context.request.form["success_action_redirect"],
                    bucket=bucket,
                    key=key_name,
                    etag=key.etag,
                )
                response["LocationHeader"] = redirect
            except ValueError:
                # If S3 cannot interpret the URL, it acts as if the field is not present.
                response["StatusCode"] = 204

        response["LocationHeader"] = response.get(
            "LocationHeader", f"{get_full_default_bucket_location(bucket)}{key_name}"
        )

        if bucket in self.get_store().bucket_versioning_status:
            response["VersionId"] = key.version_id

        self._notify(context, key_name=key_name)
        if context.request.form.get("success_action_status") != "201":
            return response

        response["ETag"] = key.etag
        response["Bucket"] = bucket
        response["Key"] = key_name
        response["Location"] = response["LocationHeader"]

        return response

    @handler("GetObjectAttributes", expand=False)
    def get_object_attributes(
        self,
        context: RequestContext,
        request: GetObjectAttributesRequest,
    ) -> GetObjectAttributesOutput:
        bucket_name = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        bucket = get_bucket_from_moto(moto_backend, bucket_name)
        key = get_key_from_moto_bucket(moto_bucket=bucket, key=request["Key"])

        object_attrs = request.get("ObjectAttributes", [])
        response = GetObjectAttributesOutput()
        # TODO: see Checksum field
        if "ETag" in object_attrs:
            response["ETag"] = key.etag.strip('"')
        if "StorageClass" in object_attrs:
            response["StorageClass"] = key.storage_class
        if "ObjectSize" in object_attrs:
            response["ObjectSize"] = key.size

        response["LastModified"] = key.last_modified
        if version_id := request.get("VersionId"):
            response["VersionId"] = version_id

        if key.multipart:
            response["ObjectParts"] = GetObjectAttributesParts(
                TotalPartsCount=len(key.multipart.partlist)
            )

        return response


def validate_bucket_name(bucket: BucketName) -> None:
    """
    Validate s3 bucket name based on the documentation
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    if not is_bucket_name_valid(bucket_name=bucket):
        ex = InvalidBucketName("The specified bucket is not valid.")
        ex.BucketName = bucket
        raise ex


def validate_canned_acl(canned_acl: str) -> None:
    """
    Validate the canned ACL value, or raise an Exception
    """
    if canned_acl and not is_canned_acl_bucket_valid(canned_acl):
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
    if acp is None or "Owner" not in acp or "Grants" not in acp:
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


def validate_website_configuration(website_config: WebsiteConfiguration) -> None:
    """
    Validate the website configuration following AWS docs
    See https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html
    :param website_config:
    :raises
    :return: None
    """
    if redirect_all_req := website_config.get("RedirectAllRequestsTo", {}):
        if len(website_config) > 1:
            ex = _create_invalid_argument_exc(
                message="RedirectAllRequestsTo cannot be provided in conjunction with other Routing Rules.",
                name="RedirectAllRequestsTo",
                value="not null",
            )
            raise ex
        if "HostName" not in redirect_all_req:
            raise MalformedXML()

        if (protocol := redirect_all_req.get("Protocol")) and protocol not in ("http", "https"):
            raise InvalidRequest(
                "Invalid protocol, protocol can be http or https. If not defined the protocol will be selected automatically."
            )

        return

    # required
    # https://docs.aws.amazon.com/AmazonS3/latest/API/API_IndexDocument.html
    if not (index_configuration := website_config.get("IndexDocument")):
        ex = _create_invalid_argument_exc(
            message="A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty",
            name="IndexDocument",
            value="null",
        )
        raise ex

    if not (index_suffix := index_configuration.get("Suffix")) or "/" in index_suffix:
        ex = _create_invalid_argument_exc(
            message="The IndexDocument Suffix is not well formed",
            name="IndexDocument",
            value=index_suffix or None,
        )
        raise ex

    if "ErrorDocument" in website_config and not website_config.get("ErrorDocument", {}).get("Key"):
        raise MalformedXML()

    if "RoutingRules" in website_config:
        routing_rules = website_config.get("RoutingRules", [])
        if len(routing_rules) == 0:
            raise MalformedXML()
        if len(routing_rules) > 50:
            raise "Something?"
        for routing_rule in routing_rules:
            redirect = routing_rule.get("Redirect", {})
            # todo: this does not raise an error? check what GetWebsiteConfig returns? empty field?
            # if not (redirect := routing_rule.get("Redirect")):
            #     raise "Something"

            if "ReplaceKeyPrefixWith" in redirect and "ReplaceKeyWith" in redirect:
                raise InvalidRequest(
                    "You can only define ReplaceKeyPrefix or ReplaceKey but not both."
                )

            if "Condition" in routing_rule and not routing_rule.get("Condition", {}):
                raise InvalidRequest(
                    "Condition cannot be empty. To redirect all requests without a condition, the condition element shouldn't be present."
                )

            if (protocol := redirect.get("Protocol")) and protocol not in ("http", "https"):
                raise InvalidRequest(
                    "Invalid protocol, protocol can be http or https. If not defined the protocol will be selected automatically."
                )


def is_object_expired(context: RequestContext, bucket: BucketName, key: ObjectKey) -> bool:
    moto_backend = get_moto_s3_backend(context)
    moto_bucket = get_bucket_from_moto(moto_backend, bucket)
    key_object = get_key_from_moto_bucket(moto_bucket, key)
    return is_key_expired(key_object=key_object)


def _create_redirect_for_post_request(
    base_redirect: str, bucket: BucketName, key: ObjectKey, etag: ETag
):
    """
    POST requests can redirect if successful. It will take the URL provided and append query string parameters
    (key, bucket and ETag). It needs to be a full URL.
    :param base_redirect: the URL provided for redirection
    :param bucket: bucket name
    :param key: key name
    :param etag: key ETag
    :return: the URL provided with the new appended query string parameters
    """
    parts = urlparse(base_redirect)
    if not parts.netloc:
        raise ValueError("The provided URL is not valid")
    queryargs = parse_qs(parts.query)
    queryargs["key"] = [key]
    queryargs["bucket"] = [bucket]
    queryargs["etag"] = [etag]
    redirect_queryargs = urlencode(queryargs, doseq=True)
    newparts = (
        parts.scheme,
        parts.netloc,
        parts.path,
        parts.params,
        redirect_queryargs,
        parts.fragment,
    )
    return urlunparse(newparts)


def apply_moto_patches():
    # importing here in case we need InvalidObjectState from `localstack.aws.api.s3`
    from moto.s3.exceptions import InvalidObjectState
    from moto.s3.models import STORAGE_CLASS

    if not os.environ.get("MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"):
        os.environ["MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"] = str(S3_MAX_FILE_SIZE_BYTES)

    # TODO: fix upstream
    STORAGE_CLASS.clear()
    STORAGE_CLASS.extend(VALID_STORAGE_CLASSES)

    @patch(moto_s3_responses.S3Response.key_response)
    def _fix_key_response(fn, self, *args, **kwargs):
        """Change casing of Last-Modified and other headers to be picked by the parser"""
        status_code, resp_headers, key_value = fn(self, *args, **kwargs)
        for low_case_header in [
            "last-modified",
            "content-type",
            "content-length",
            "content-range",
            "content-encoding",
            "content-language",
            "content-disposition",
            "cache-control",
        ]:
            if header_value := resp_headers.pop(low_case_header, None):
                header_name = capitalize_header_name_from_snake_case(low_case_header)
                resp_headers[header_name] = header_value

        # The header indicating 'bucket-key-enabled' is set as python boolean, resulting in camelcase-value.
        # The parser expects it to be lowercase string, however, to be parsed correctly.
        bucket_key_enabled = "x-amz-server-side-encryption-bucket-key-enabled"
        if val := resp_headers.get(bucket_key_enabled, ""):
            resp_headers[bucket_key_enabled] = str(val).lower()

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

    @patch(moto_s3_responses.S3Response._tagging_from_xml)
    def _fix_tagging_from_xml(fn, *args, **kwargs) -> Dict[str, str]:
        """
        Moto tries to parse the TagSet and then iterate of it, not checking if it returned something
        Potential to be an easy upstream fix
        """
        try:
            tags: Dict[str, str] = fn(*args, **kwargs)
        except TypeError:
            tags = {}
        return tags

    @patch(moto_s3_responses.S3Response._cors_from_body)
    def _fix_parsing_cors_rules(fn, *args, **kwargs) -> List[Dict]:
        """
        Fix parsing of CORS Rules from moto, you can set empty origin in AWS. Replace None by an empty string
        """
        cors_rules = fn(*args, **kwargs)
        for rule in cors_rules:
            if rule["AllowedOrigin"] is None:
                rule["AllowedOrigin"] = ""
        return cors_rules

    @patch(moto_s3_responses.S3Response.is_delete_keys)
    def s3_response_is_delete_keys(fn, self):
        """
        Old provider had a fix for a ticket, concerning 'x-id' - there is no documentation on AWS about this, but it is probably still valid
        original comment: Temporary fix until moto supports x-id and DeleteObjects (#3931)
        """
        return get_safe(self.querystring, "$.x-id.0") == "DeleteObjects" or fn(self)

    @patch(moto_s3_responses.S3ResponseInstance.parse_bucket_name_from_url, pass_target=False)
    def parse_bucket_name_from_url(self, request, url):
        """
        Requests going to moto will never be subdomain based, as they passed through the VirtualHost forwarder.
        We know the bucket is in the path, we can directly return it.
        """
        path = urlparse(url).path
        return path.split("/")[1]

    @patch(moto_s3_responses.S3ResponseInstance.subdomain_based_buckets, pass_target=False)
    def subdomain_based_buckets(self, request):
        """
        Requests going to moto will never be subdomain based, as they passed through the VirtualHost forwarder
        """
        return False


def register_custom_handlers():
    serve_custom_service_request_handlers.append(s3_presigned_url_request_handler)
    modify_service_response.append(S3Provider.service, s3_presigned_url_response_handler)
