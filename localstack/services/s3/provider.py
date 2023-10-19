import copy
import datetime
import logging
import os
from collections import defaultdict
from operator import itemgetter
from typing import IO, Dict, List, Optional
from urllib.parse import quote, urlparse

import moto.s3.responses as moto_s3_responses
from zoneinfo import ZoneInfo

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext, ServiceException, handler
from localstack.aws.api.s3 import (
    MFA,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsConfigurationList,
    AnalyticsId,
    Body,
    BucketLoggingStatus,
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
    CrossLocationLoggingProhibitted,
    Delete,
    DeleteObjectOutput,
    DeleteObjectRequest,
    DeleteObjectsOutput,
    DeleteObjectTaggingOutput,
    DeleteObjectTaggingRequest,
    Expiration,
    Expression,
    ExpressionType,
    GetBucketAclOutput,
    GetBucketAnalyticsConfigurationOutput,
    GetBucketCorsOutput,
    GetBucketIntelligentTieringConfigurationOutput,
    GetBucketInventoryConfigurationOutput,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLifecycleOutput,
    GetBucketLocationOutput,
    GetBucketLoggingOutput,
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
    GetObjectRetentionOutput,
    HeadObjectOutput,
    HeadObjectRequest,
    InputSerialization,
    IntelligentTieringConfiguration,
    IntelligentTieringConfigurationList,
    IntelligentTieringId,
    InvalidArgument,
    InvalidDigest,
    InvalidPartOrder,
    InvalidStorageClass,
    InvalidTargetBucketForLogging,
    InventoryConfiguration,
    InventoryId,
    LifecycleRules,
    ListBucketAnalyticsConfigurationsOutput,
    ListBucketIntelligentTieringConfigurationsOutput,
    ListBucketInventoryConfigurationsOutput,
    ListMultipartUploadsOutput,
    ListMultipartUploadsRequest,
    ListObjectsOutput,
    ListObjectsRequest,
    ListObjectsV2Output,
    ListObjectsV2Request,
    MissingSecurityHeader,
    MultipartUpload,
    NoSuchBucket,
    NoSuchCORSConfiguration,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    NoSuchUpload,
    NoSuchWebsiteConfiguration,
    NotificationConfiguration,
    ObjectIdentifier,
    ObjectKey,
    ObjectLockRetention,
    ObjectLockToken,
    ObjectVersionId,
    OutputSerialization,
    PostResponse,
    PreconditionFailed,
    PutBucketAclRequest,
    PutBucketLifecycleConfigurationRequest,
    PutBucketLifecycleRequest,
    PutBucketRequestPaymentRequest,
    PutBucketVersioningRequest,
    PutObjectAclOutput,
    PutObjectAclRequest,
    PutObjectOutput,
    PutObjectRequest,
    PutObjectRetentionOutput,
    PutObjectTaggingOutput,
    PutObjectTaggingRequest,
    ReplicationConfiguration,
    ReplicationConfigurationNotFoundError,
    RequestPayer,
    RequestProgress,
    RestoreObjectOutput,
    RestoreObjectRequest,
    S3Api,
    ScanRange,
    SelectObjectContentOutput,
    SkipValidation,
    SSECustomerAlgorithm,
    SSECustomerKey,
    SSECustomerKeyMD5,
    StorageClass,
    Token,
    UploadPartOutput,
    UploadPartRequest,
    WebsiteConfiguration,
)
from localstack.aws.forwarder import NotImplementedAvoidFallbackError
from localstack.aws.handlers import preprocess_request, serve_custom_service_request_handlers
from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3 import constants as s3_constants
from localstack.services.s3.codec import AwsChunkedDecoder
from localstack.services.s3.cors import S3CorsHandler, s3_cors_request_handler
from localstack.services.s3.exceptions import (
    InvalidRequest,
    MalformedXML,
    NoSuchConfiguration,
    UnexpectedContent,
)
from localstack.services.s3.models import BucketCorsIndex, S3Store, get_moto_s3_backend, s3_stores
from localstack.services.s3.notifications import NotificationDispatcher, S3EventNotificationContext
from localstack.services.s3.presigned_url import validate_post_policy
from localstack.services.s3.utils import (
    capitalize_header_name_from_snake_case,
    create_redirect_for_post_request,
    etag_to_base_64_content_md5,
    extract_bucket_key_version_id_from_copy_source,
    get_bucket_from_moto,
    get_failed_precondition_copy_source,
    get_key_from_moto_bucket,
    get_lifecycle_rule_from_object,
    get_object_checksum_for_algorithm,
    get_permission_from_header,
    is_key_expired,
    serialize_expiration_header,
    validate_kms_key_id,
    verify_checksum,
)
from localstack.services.s3.validation import (
    parse_grants_in_headers,
    validate_acl_acp,
    validate_bucket_analytics_configuration,
    validate_bucket_intelligent_tiering_configuration,
    validate_bucket_name,
    validate_canned_acl,
    validate_inventory_configuration,
    validate_lifecycle_configuration,
    validate_website_configuration,
)
from localstack.services.s3.website_hosting import register_website_hosting_routes
from localstack.utils.aws import arns
from localstack.utils.aws.arns import s3_bucket_name
from localstack.utils.collections import get_safe
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid
from localstack.utils.time import parse_timestamp
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = "s3.localhost.localstack.cloud:4566,s3.localhost.localstack.cloud"

MOTO_CANONICAL_USER_ID = "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
# max file size for S3 objects kept in memory (500 KB by default)
S3_MAX_FILE_SIZE_BYTES = 512 * 1024


def get_full_default_bucket_location(bucket_name):
    if config.HOSTNAME_EXTERNAL != config.LOCALHOST:
        host_definition = localstack_host(
            use_hostname_external=True, custom_port=config.get_edge_port_http()
        )
        return f"{config.get_protocol()}://{host_definition.host_and_port()}/{bucket_name}/"
    else:
        host_definition = localstack_host(use_localhost_cloud=True)
        return f"{config.get_protocol()}://{bucket_name}.s3.{host_definition.host_and_port()}/"


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store(account_id: Optional[str] = None, region: Optional[str] = None) -> S3Store:
        return s3_stores[account_id or DEFAULT_AWS_ACCOUNT_ID][region or AWS_REGION_US_EAST_1]

    def _clear_bucket_from_store(
        self, bucket_account_id: str, bucket_region: str, bucket: BucketName
    ):
        store = self.get_store(bucket_account_id, bucket_region)
        store.bucket_lifecycle_configuration.pop(bucket, None)
        store.bucket_versioning_status.pop(bucket, None)
        store.bucket_cors.pop(bucket, None)
        store.bucket_notification_configs.pop(bucket, None)
        store.bucket_replication.pop(bucket, None)
        store.bucket_website_configuration.pop(bucket, None)
        store.bucket_analytics_configuration.pop(bucket, None)
        store.bucket_intelligent_tiering_configuration.pop(bucket, None)
        self._expiration_cache.pop(bucket, None)

    def on_after_init(self):
        apply_moto_patches()
        preprocess_request.append(self._cors_handler)
        register_website_hosting_routes(router=ROUTER)
        serve_custom_service_request_handlers.append(s3_cors_request_handler)
        # registering of virtual host routes happens with the hook on_infra_ready in virtual_host.py
        # create a AWS managed KMS key at start and save it in the store for persistence?

    def __init__(self) -> None:
        super().__init__()
        self._notification_dispatcher = NotificationDispatcher()
        self._cors_handler = S3CorsHandler(BucketCorsIndex())
        # runtime cache of Lifecycle Expiration headers, as they need to be calculated everytime we fetch an object
        # in case the rules have changed
        self._expiration_cache: dict[BucketName, dict[ObjectKey, Expiration]] = defaultdict(dict)

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
        store = self.get_store(s3_notif_ctx.bucket_account_id, s3_notif_ctx.bucket_location)
        if notification_config := store.bucket_notification_configs.get(s3_notif_ctx.bucket_name):
            self._notification_dispatcher.send_notifications(s3_notif_ctx, notification_config)

    def _verify_notification_configuration(
        self,
        notification_configuration: NotificationConfiguration,
        skip_destination_validation: SkipValidation,
        context: RequestContext,
        bucket_name: str,
    ):
        self._notification_dispatcher.verify_configuration(
            notification_configuration, skip_destination_validation, context, bucket_name
        )

    def _get_expiration_header(
        self, lifecycle_rules: LifecycleRules, moto_object, object_tags
    ) -> Expiration:
        """
        This method will check if the key matches a Lifecycle filter, and return the serializer header if that's
        the case. We're caching it because it can change depending on the set rules on the bucket.
        We can't use `lru_cache` as the parameters needs to be hashable
        :param lifecycle_rules: the bucket LifecycleRules
        :param moto_object: FakeKey from moto
        :param object_tags: the object tags
        :return: the Expiration header if there's a rule matching
        """
        if cached_exp := self._expiration_cache.get(moto_object.bucket_name, {}).get(
            moto_object.name
        ):
            return cached_exp

        if lifecycle_rule := get_lifecycle_rule_from_object(
            lifecycle_rules, moto_object.name, moto_object.size, object_tags
        ):
            expiration_header = serialize_expiration_header(
                lifecycle_rule["ID"],
                lifecycle_rule["Expiration"],
                moto_object.last_modified,
            )
            self._expiration_cache[moto_object.bucket_name][moto_object.name] = expiration_header
            return expiration_header

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self,
        context: RequestContext,
        request: CreateBucketRequest,
    ) -> CreateBucketOutput:
        bucket_name = request["Bucket"]
        validate_bucket_name(bucket=bucket_name)

        # FIXME: moto will raise an exception if no Content-Length header is set. However, some SDK (Java v1 for ex.)
        # will not provide a content-length if there's no body attached to the PUT request (not mandatory in HTTP specs)
        # We will add it manually, normally to 0, if not present. AWS accepts that.
        if "content-length" not in context.request.headers:
            context.request.headers["Content-Length"] = str(len(context.request.data))

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
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        call_moto(context)
        self._clear_bucket_from_store(
            bucket_account_id=moto_bucket.account_id,
            bucket_region=moto_bucket.region_name,
            bucket=bucket,
        )
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

        return response

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

        key = request["Key"]
        bucket = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        key_object = get_key_from_moto_bucket(moto_bucket, key=key)

        if (checksum_algorithm := key_object.checksum_algorithm) and not response.get(
            "ContentEncoding"
        ):
            # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested) if it's not
            # set to something
            response["ContentEncoding"] = ""

        if (request.get("ChecksumMode") or "").upper() == "ENABLED" and checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = key_object.checksum_value  # noqa

        if not request.get("VersionId"):
            store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
            if (
                bucket_lifecycle_config := store.bucket_lifecycle_configuration.get(
                    request["Bucket"]
                )
            ) and (rules := bucket_lifecycle_config.get("Rules")):
                object_tags = moto_backend.tagger.get_tag_dict_for_resource(key_object.arn)
                if expiration_header := self._get_expiration_header(rules, key_object, object_tags):
                    # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to
                    #  apply them everytime we get/head an object
                    response["Expiration"] = expiration_header

        return response

    @handler("GetObject", expand=False)
    def get_object(self, context: RequestContext, request: GetObjectRequest) -> GetObjectOutput:
        key = request["Key"]
        bucket = request["Bucket"]
        version_id = request.get("VersionId")
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)

        if is_object_expired(moto_bucket=moto_bucket, key=key, version_id=version_id):
            # TODO: old behaviour was deleting key instantly if expired. AWS cleans up only once a day generally
            # see if we need to implement a feature flag
            # but you can still HeadObject on it and you get the expiry time
            raise NoSuchKey("The specified key does not exist.", Key=key)

        response: GetObjectOutput = call_moto(context)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        # check for the presence in the response, was fixed by moto but incompletely
        if bucket in store.bucket_versioning_status and "VersionId" not in response:
            response["VersionId"] = "null"

        for request_param, response_param in s3_constants.ALLOWED_HEADER_OVERRIDES.items():
            if request_param_value := request.get(request_param):  # noqa
                response[response_param] = request_param_value  # noqa

        key_object = get_key_from_moto_bucket(moto_bucket, key=key, version_id=version_id)

        if not config.S3_SKIP_KMS_KEY_VALIDATION and key_object.kms_key_id:
            validate_kms_key_id(kms_key=key_object.kms_key_id, bucket=moto_bucket)

        if (checksum_algorithm := key_object.checksum_algorithm) and not response.get(
            "ContentEncoding"
        ):
            # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested) if it's not
            # set to something
            response["ContentEncoding"] = ""

        if (request.get("ChecksumMode") or "").upper() == "ENABLED" and checksum_algorithm:
            response[f"Checksum{key_object.checksum_algorithm.upper()}"] = key_object.checksum_value

        if not version_id and (
            (bucket_lifecycle_config := store.bucket_lifecycle_configuration.get(request["Bucket"]))
            and (rules := bucket_lifecycle_config.get("Rules"))
        ):
            object_tags = moto_backend.tagger.get_tag_dict_for_resource(key_object.arn)
            if expiration_header := self._get_expiration_header(rules, key_object, object_tags):
                # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to
                #  apply them everytime we get/head an object
                response["Expiration"] = expiration_header

        response["AcceptRanges"] = "bytes"
        return response

    @handler("PutObject", expand=False)
    def put_object(
        self,
        context: RequestContext,
        request: PutObjectRequest,
    ) -> PutObjectOutput:
        # TODO: it seems AWS uses AES256 encryption by default now, starting January 5th 2023
        # note: etag do not change after encryption
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
        if checksum_algorithm := request.get("ChecksumAlgorithm"):
            verify_checksum(checksum_algorithm, context.request.data, request)

        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, moto_bucket)

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

        # TODO: handle ContentMD5 and ChecksumAlgorithm in a handler for all requests except requests with a streaming
        #  body. We can use the specs to verify which operations needs to have the checksum validated
        # verify content_md5
        if content_md5 := request.get("ContentMD5"):
            calculated_md5 = etag_to_base_64_content_md5(response["ETag"].strip('"'))
            if calculated_md5 != content_md5:
                moto_backend.delete_object(
                    bucket_name=request["Bucket"],
                    key_name=request["Key"],
                    version_id=response.get("VersionId"),
                    bypass=True,
                )
                raise InvalidDigest(
                    "The Content-MD5 you specified was invalid.",
                    Content_MD5=content_md5,
                )

        # moto interprets the Expires in query string for presigned URL as an Expires header and use it for the object
        # we set it to the correctly parsed value in Request, else we remove it from moto metadata
        # we are getting the last set key here so no need for versionId when getting the key
        key_object = get_key_from_moto_bucket(moto_bucket, key=request["Key"])
        if expires := request.get("Expires"):
            key_object.set_expiry(expires)
        elif "expires" in key_object.metadata:  # if it got added from query string parameter
            metadata = {k: v for k, v in key_object.metadata.items() if k != "expires"}
            key_object.set_metadata(metadata, replace=True)

        if key_object.kms_key_id:
            # set the proper format of the key to be an ARN
            key_object.kms_key_id = arns.kms_key_arn(
                key_id=key_object.kms_key_id,
                account_id=moto_bucket.account_id,
                region_name=moto_bucket.region_name,
            )
            response["SSEKMSKeyId"] = key_object.kms_key_id

        if key_object.checksum_algorithm == ChecksumAlgorithm.CRC32C:
            # moto does not support CRC32C yet, it uses CRC32 instead
            # recalculate the proper checksum to store in the key
            key_object.checksum_value = get_object_checksum_for_algorithm(
                ChecksumAlgorithm.CRC32C,
                key_object.value,
            )

        bucket_lifecycle_configurations = self.get_store(
            context.account_id, context.region
        ).bucket_lifecycle_configuration
        if (bucket_lifecycle_config := bucket_lifecycle_configurations.get(request["Bucket"])) and (
            rules := bucket_lifecycle_config.get("Rules")
        ):
            object_tags = moto_backend.tagger.get_tag_dict_for_resource(key_object.arn)
            if expiration_header := self._get_expiration_header(rules, key_object, object_tags):
                response["Expiration"] = expiration_header

        self._notify(context)

        return response

    @handler("CopyObject", expand=False)
    def copy_object(
        self,
        context: RequestContext,
        request: CopyObjectRequest,
    ) -> CopyObjectOutput:
        moto_backend = get_moto_s3_backend(context)
        dest_moto_bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, dest_moto_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request["CopySource"]
        )
        src_moto_bucket = get_bucket_from_moto(moto_backend, bucket=src_bucket)
        source_key_object = get_key_from_moto_bucket(
            src_moto_bucket, key=src_key, version_id=src_version_id
        )

        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
        source_object_last_modified = source_key_object.last_modified.replace(
            tzinfo=ZoneInfo("GMT")
        )
        if failed_condition := get_failed_precondition_copy_source(
            request, source_object_last_modified, source_key_object.etag
        ):
            raise PreconditionFailed(
                "At least one of the pre-conditions you specified did not hold",
                Condition=failed_condition,
            )

        response: CopyObjectOutput = call_moto(context)

        # we properly calculate the Checksum for the destination Key
        checksum_algorithm = (
            request.get("ChecksumAlgorithm") or source_key_object.checksum_algorithm
        )
        if checksum_algorithm:
            dest_key_object = get_key_from_moto_bucket(dest_moto_bucket, key=request["Key"])
            dest_key_object.checksum_algorithm = checksum_algorithm

            if (
                not source_key_object.checksum_value
                or checksum_algorithm == ChecksumAlgorithm.CRC32C
            ):
                dest_key_object.checksum_value = get_object_checksum_for_algorithm(
                    checksum_algorithm, dest_key_object.value
                )
            else:
                dest_key_object.checksum_value = source_key_object.checksum_value

            if checksum_algorithm == ChecksumAlgorithm.CRC32C:
                # TODO: the logic for rendering the template in moto is the following:
                # if `CRC32` in `key.checksum_algorithm` which is valid for both CRC32 and CRC32C, and will render both
                # remove the key if it's CRC32C.
                response["CopyObjectResult"].pop("ChecksumCRC32", None)

            dest_key_object.checksum_algorithm = checksum_algorithm

            response["CopyObjectResult"][
                f"Checksum{checksum_algorithm.upper()}"
            ] = dest_key_object.checksum_value  # noqa

        self._notify(context)
        return response

    @handler("DeleteObject", expand=False)
    def delete_object(
        self,
        context: RequestContext,
        request: DeleteObjectRequest,
    ) -> DeleteObjectOutput:
        # TODO: implement DeleteMarker response
        bucket_name = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
        if request.get("BypassGovernanceRetention") is not None:
            if not moto_bucket.object_lock_enabled:
                raise InvalidArgument(
                    "x-amz-bypass-governance-retention is only applicable to Object Lock enabled buckets.",
                    ArgumentName="x-amz-bypass-governance-retention",
                )

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        if request["Bucket"] not in store.bucket_notification_configs:
            return call_moto(context)

        # TODO: we do not differentiate between deleting a key and creating a DeleteMarker in a versioned bucket
        # for the event (s3:ObjectRemoved:Delete / s3:ObjectRemoved:DeleteMarkerCreated)
        # it always s3:ObjectRemoved:Delete for now
        # create the notification context before deleting the object, to be able to retrieve its properties
        s3_notification_ctx = S3EventNotificationContext.from_request_context(
            context, version_id=request.get("VersionId")
        )

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
    ) -> DeleteObjectsOutput:
        # TODO: implement DeleteMarker response
        if bypass_governance_retention is not None:
            moto_backend = get_moto_s3_backend(context)
            moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
            if not moto_bucket.object_lock_enabled:
                raise InvalidArgument(
                    "x-amz-bypass-governance-retention is only applicable to Object Lock enabled buckets.",
                    ArgumentName="x-amz-bypass-governance-retention",
                )

        objects: List[ObjectIdentifier] = delete.get("Objects")
        deleted_objects = {}
        quiet = delete.get("Quiet", False)
        for object_data in objects:
            key = object_data["Key"]
            # create the notification context before deleting the object, to be able to retrieve its properties
            # TODO: test format of notification if the key is a DeleteMarker
            s3_notification_ctx = S3EventNotificationContext.from_request_context(
                context,
                key_name=key,
                version_id=object_data.get("VersionId"),
                allow_non_existing_key=True,
            )

            deleted_objects[key] = s3_notification_ctx
        result: DeleteObjectsOutput = call_moto(context)
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
        ) and storage_class not in s3_constants.VALID_STORAGE_CLASSES:
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

        bucket_name = request["Bucket"]
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket_name)
        if (upload_id := request.get("UploadId")) not in moto_bucket.multiparts:
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        response: CompleteMultipartUploadOutput = call_moto(context)

        # moto return the Location in AWS `http://{bucket}.s3.amazonaws.com/{key}`
        response["Location"] = f'{get_full_default_bucket_location(bucket_name)}{response["Key"]}'
        self._notify(context)
        return response

    @handler("UploadPart", expand=False)
    def upload_part(self, context: RequestContext, request: UploadPartRequest) -> UploadPartOutput:
        bucket_name = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket_name)
        if (upload_id := request.get("UploadId")) not in moto_bucket.multiparts:
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )
        elif (part_number := request.get("PartNumber", 0)) < 1 or part_number > 10000:
            raise InvalidArgument(
                "Part number must be an integer between 1 and 10000, inclusive",
                ArgumentName="partNumber",
                ArgumentValue=part_number,
            )

        body = request.get("Body")
        headers = context.request.headers
        # AWS specifies that the `Content-Encoding` should be `aws-chunked`, but some SDK don't set it.
        # Rely on the `x-amz-content-sha256` which is a more reliable indicator that the request is streamed
        content_sha_256 = (headers.get("x-amz-content-sha256") or "").upper()
        if body and content_sha_256 and content_sha_256.startswith("STREAMING-"):
            # this is a chunked request, we need to properly decode it while setting the key value
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
            body = AwsChunkedDecoder(body, decoded_content_length)

        part = body.read() if body else b""

        # we are directly using moto backend and not calling moto because to get the response, moto calls
        # key.response_dict, which in turns tries to access the tags of part, indirectly creating a BackendDict
        # with an account_id set to None (because moto does not set an account_id to the FakeKey representing a Part)
        key = moto_backend.upload_part(bucket_name, upload_id, part_number, part)
        response = UploadPartOutput(ETag=key.etag)

        if key.encryption is not None:
            response["ServerSideEncryption"] = key.encryption
            if key.encryption == "aws:kms" and key.kms_key_id is not None:
                response["SSEKMSKeyId"] = key.encryption

        if key.encryption == "aws:kms" and key.bucket_key_enabled is not None:
            response["BucketKeyEnabled"] = key.bucket_key_enabled

        return response

    @handler("ListMultipartUploads", expand=False)
    def list_multipart_uploads(
        self,
        context: RequestContext,
        request: ListMultipartUploadsRequest,
    ) -> ListMultipartUploadsOutput:
        # TODO: implement KeyMarker and UploadIdMarker (using sort)
        # implement Delimiter and MaxUploads
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html
        bucket = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        # getting the bucket from moto to raise an error if the bucket does not exist
        get_bucket_from_moto(moto_backend=moto_backend, bucket=bucket)

        multiparts = list(moto_backend.get_all_multiparts(bucket).values())
        if (prefix := request.get("Prefix")) is not None:
            multiparts = [upload for upload in multiparts if upload.key_name.startswith(prefix)]

        # TODO: this is taken from moto template, hardcoded strings.
        uploads = [
            MultipartUpload(
                Key=upload.key_name,
                UploadId=upload.id,
                Initiator={
                    "ID": f"arn:aws:iam::{context.account_id}:user/user1-11111a31-17b5-4fb7-9df5-b111111f13de",
                    "DisplayName": "user1-11111a31-17b5-4fb7-9df5-b111111f13de",
                },
                Owner={
                    "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a",
                    "DisplayName": "webfile",
                },
                StorageClass=StorageClass.STANDARD,  # hardcoded in moto
                Initiated=datetime.datetime.now(),  # hardcoded in moto
            )
            for upload in multiparts
        ]

        response = ListMultipartUploadsOutput(
            Bucket=request["Bucket"],
            MaxUploads=request.get("MaxUploads") or 1000,
            IsTruncated=False,
            Uploads=uploads,
            UploadIdMarker=request.get("UploadIdMarker") or "",
            KeyMarker=request.get("KeyMarker") or "",
        )

        if "Delimiter" in request:
            response["Delimiter"] = request["Delimiter"]

        # TODO: add NextKeyMarker and NextUploadIdMarker to response once implemented

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

        if not (rules := replication_configuration.get("Rules")):
            raise MalformedXML()

        for rule in rules:
            if "ID" not in rule:
                rule["ID"] = short_uid()

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
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        store.bucket_replication[bucket] = replication_configuration

    def get_bucket_replication(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketReplicationOutput:
        # test if bucket exists in moto
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

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
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
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
        lifecycle_conf = request.get("LifecycleConfiguration")
        validate_lifecycle_configuration(lifecycle_conf)
        # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to apply them
        #  everytime we get/head an object
        # for now, we keep a cache and get it everytime we fetch an object, as it's easier to invalidate than
        # iterating over every single key to set the Expiration header to None
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        store.bucket_lifecycle_configuration[bucket] = lifecycle_conf
        self._expiration_cache[bucket].clear()

    def delete_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        # test if bucket exists in moto
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        store.bucket_lifecycle_configuration.pop(bucket, None)
        self._expiration_cache[bucket].clear()

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
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        store.bucket_cors[bucket] = cors_configuration
        self._cors_handler.invalidate_cache()
        return response

    def get_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketCorsOutput:
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        call_moto(context)

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        cors_rules = store.bucket_cors.get(bucket)
        if not cors_rules:
            raise NoSuchCORSConfiguration(
                "The CORS configuration does not exist",
                BucketName=bucket,
            )
        return GetBucketCorsOutput(CORSRules=cors_rules["CORSRules"])

    def delete_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        response = call_moto(context)
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        if store.bucket_cors.pop(bucket, None):
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

    def get_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectRetentionOutput:
        moto_backend = get_moto_s3_backend(context)
        key = get_key_from_moto_bucket(
            get_bucket_from_moto(moto_backend, bucket=bucket), key=key, version_id=version_id
        )
        if not key.lock_mode and not key.lock_until:
            raise InvalidRequest("Bucket is missing Object Lock Configuration")
        return GetObjectRetentionOutput(
            Retention=ObjectLockRetention(
                Mode=key.lock_mode,
                RetainUntilDate=parse_timestamp(key.lock_until),
            )
        )

    @handler("PutObjectRetention")
    def put_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        retention: ObjectLockRetention = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectRetentionOutput:
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)

        try:
            moto_key = get_key_from_moto_bucket(moto_bucket, key=key, version_id=version_id)
        except NoSuchKey:
            moto_key = None

        if not moto_key and version_id:
            raise InvalidArgument("Invalid version id specified")
        if not moto_bucket.object_lock_enabled:
            raise InvalidRequest("Bucket is missing Object Lock Configuration")
        if not moto_key and not version_id:
            raise NoSuchKey("The specified key does not exist.", Key=key)

        moto_key.lock_mode = retention.get("Mode")
        retention_date = retention.get("RetainUntilDate")
        retention_date = retention_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        moto_key.lock_until = retention_date
        return PutObjectRetentionOutput()

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
            for key in grant_keys:
                if grantees_values := request.get(key, ""):  # noqa
                    permission = get_permission_from_header(key)
                    parse_grants_in_headers(permission, grantees_values)

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
                permission = get_permission_from_header(key)
                parse_grants_in_headers(permission, grantees_values)

        if acp := request.get("AccessControlPolicy"):
            validate_acl_acp(acp)

        moto_backend = get_moto_s3_backend(context)
        # TODO: rework the delete marker handling
        key = get_key_from_moto_bucket(
            moto_bucket=get_bucket_from_moto(moto_backend, bucket=request["Bucket"]),
            key=request["Key"],
            version_id=request.get("VersionId"),
            raise_if_delete_marker_method="PUT",
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
            moto_backend = get_moto_s3_backend(context)
            moto_bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
            store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
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
            notification_configuration, skip_destination_validation, context, bucket
        )
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        store.bucket_notification_configs[bucket] = notification_configuration

    def get_bucket_notification_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfiguration:
        # TODO how to verify expected_bucket_owner
        # check if the bucket exists
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        return store.bucket_notification_configs.get(bucket, NotificationConfiguration())

    def get_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketWebsiteOutput:
        # to check if the bucket exists
        # TODO: simplify this when we don't use moto
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        if not (website_configuration := store.bucket_website_configuration.get(bucket)):
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
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)

        validate_website_configuration(website_configuration)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        store.bucket_website_configuration[bucket] = website_configuration

    def delete_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        # to check if the bucket exists
        # TODO: simplify this when we don't use moto
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        # does not raise error if the bucket did not have a config, will simply return
        store.bucket_website_configuration.pop(bucket, None)

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

        # TODO: add concept of VersionId
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket=bucket)
        key = get_key_from_moto_bucket(moto_bucket, key=key_name)
        # hacky way to set the etag in the headers as well: two locations for one value
        response["ETagHeader"] = key.etag

        if response["StatusCode"] == 303:
            # we need to create the redirect, as the parser could not return the moto-calculated one
            try:
                redirect = create_redirect_for_post_request(
                    base_redirect=context.request.form["success_action_redirect"],
                    bucket=bucket,
                    object_key=key_name,
                    etag=key.etag,
                )
                response["LocationHeader"] = redirect
            except ValueError:
                # If S3 cannot interpret the URL, it acts as if the field is not present.
                response["StatusCode"] = 204

        response["LocationHeader"] = response.get(
            "LocationHeader", f"{get_full_default_bucket_location(bucket)}{key_name}"
        )

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        if bucket in store.bucket_versioning_status:
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
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket_name)
        # TODO: rework the delete marker handling
        key = get_key_from_moto_bucket(
            moto_bucket=moto_bucket,
            key=request["Key"],
            version_id=request.get("VersionId"),
            raise_if_delete_marker_method="GET",
        )

        object_attrs = request.get("ObjectAttributes", [])
        response = GetObjectAttributesOutput()
        # TODO: see Checksum field
        if "ETag" in object_attrs:
            response["ETag"] = key.etag.strip('"')
        if "StorageClass" in object_attrs:
            response["StorageClass"] = key.storage_class
        if "ObjectSize" in object_attrs:
            response["ObjectSize"] = key.size
        if "Checksum" in object_attrs and (checksum_algorithm := key.checksum_algorithm):
            response["Checksum"] = {
                f"Checksum{checksum_algorithm.upper()}": key.checksum_value
            }  # noqa

        response["LastModified"] = key.last_modified

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        if bucket_name in store.bucket_versioning_status:
            response["VersionId"] = key.version_id

        if key.multipart:
            response["ObjectParts"] = GetObjectAttributesParts(
                TotalPartsCount=len(key.multipart.partlist)
            )

        return response

    def put_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        analytics_configuration: AnalyticsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        validate_bucket_analytics_configuration(
            id=id, analytics_configuration=analytics_configuration
        )

        bucket_analytics_configurations = store.bucket_analytics_configuration.setdefault(
            bucket, {}
        )
        bucket_analytics_configurations[id] = analytics_configuration

    def get_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketAnalyticsConfigurationOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        analytics_configuration: AnalyticsConfiguration = store.bucket_analytics_configuration.get(
            bucket, {}
        ).get(id)
        if not analytics_configuration:
            raise NoSuchConfiguration("The specified configuration does not exist.")
        return GetBucketAnalyticsConfigurationOutput(AnalyticsConfiguration=analytics_configuration)

    def list_bucket_analytics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketAnalyticsConfigurationsOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        analytics_configurations: Dict[
            AnalyticsId, AnalyticsConfiguration
        ] = store.bucket_analytics_configuration.get(bucket, {})
        analytics_configurations: AnalyticsConfigurationList = sorted(
            analytics_configurations.values(), key=lambda x: x["Id"]
        )
        return ListBucketAnalyticsConfigurationsOutput(
            IsTruncated=False, AnalyticsConfigurationList=analytics_configurations
        )

    def delete_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        analytics_configurations = store.bucket_analytics_configuration.get(bucket, {})
        if not analytics_configurations.pop(id, None):
            raise NoSuchConfiguration("The specified configuration does not exist.")

    def put_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        intelligent_tiering_configuration: IntelligentTieringConfiguration,
    ) -> None:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)

        validate_bucket_intelligent_tiering_configuration(id, intelligent_tiering_configuration)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        bucket_intelligent_tiering_configurations = (
            store.bucket_intelligent_tiering_configuration.setdefault(bucket, {})
        )
        bucket_intelligent_tiering_configurations[id] = intelligent_tiering_configuration

    def get_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> GetBucketIntelligentTieringConfigurationOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        intelligent_tiering_configuration: IntelligentTieringConfiguration = (
            store.bucket_intelligent_tiering_configuration.get(bucket, {}).get(id)
        )
        if not intelligent_tiering_configuration:
            raise NoSuchConfiguration("The specified configuration does not exist.")
        return GetBucketIntelligentTieringConfigurationOutput(
            IntelligentTieringConfiguration=intelligent_tiering_configuration
        )

    def delete_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> None:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        bucket_intelligent_tiering_configurations = (
            store.bucket_intelligent_tiering_configuration.get(bucket, {})
        )
        if not bucket_intelligent_tiering_configurations.pop(id, None):
            raise NoSuchConfiguration("The specified configuration does not exist.")

    def list_bucket_intelligent_tiering_configurations(
        self, context: RequestContext, bucket: BucketName, continuation_token: Token = None
    ) -> ListBucketIntelligentTieringConfigurationsOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        bucket_intelligent_tiering_configurations: Dict[
            IntelligentTieringId, IntelligentTieringConfiguration
        ] = store.bucket_intelligent_tiering_configuration.get(bucket, {})

        bucket_intelligent_tiering_configurations: IntelligentTieringConfigurationList = sorted(
            bucket_intelligent_tiering_configurations.values(), key=lambda x: x["Id"]
        )
        return ListBucketIntelligentTieringConfigurationsOutput(
            IsTruncated=False,
            IntelligentTieringConfigurationList=bucket_intelligent_tiering_configurations,
        )

    def put_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        bucket_logging_status: BucketLoggingStatus,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=bucket)

        if not (logging_config := bucket_logging_status.get("LoggingEnabled")):
            moto_bucket.logging = {}
            return

        # the target bucket must be in the same account
        if not (target_bucket_name := logging_config.get("TargetBucket")):
            raise MalformedXML()

        if not logging_config.get("TargetPrefix"):
            logging_config["TargetPrefix"] = ""

        # TODO: validate Grants

        if not (target_bucket := moto_backend.buckets.get(target_bucket_name)):
            raise InvalidTargetBucketForLogging(
                "The target bucket for logging does not exist",
                TargetBucket=target_bucket_name,
            )

        if target_bucket.region_name != moto_bucket.region_name:
            raise CrossLocationLoggingProhibitted(
                "Cross S3 location logging not allowed. ",
                TargetBucketLocation=target_bucket.region_name,
            )

        moto_bucket.logging = logging_config

    def get_bucket_logging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLoggingOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        if not moto_bucket.logging:
            return GetBucketLoggingOutput()

        return GetBucketLoggingOutput(LoggingEnabled=moto_bucket.logging)

    def select_object_content(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        expression: Expression,
        expression_type: ExpressionType,
        input_serialization: InputSerialization,
        output_serialization: OutputSerialization,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_progress: RequestProgress = None,
        scan_range: ScanRange = None,
        expected_bucket_owner: AccountId = None,
    ) -> SelectObjectContentOutput:
        # this operation is currently implemented by moto, but raises a 500 error because of the format necessary,
        # and streaming capability.
        # avoid a fallback to moto and return the 501 to the client directly instead.
        raise NotImplementedAvoidFallbackError

    @handler("RestoreObject", expand=False)
    def restore_object(
        self,
        context: RequestContext,
        request: RestoreObjectRequest,
    ) -> RestoreObjectOutput:
        response: RestoreObjectOutput = call_moto(context)
        # We first create a context when we initiated the Restore process
        s3_notif_ctx_initiated = S3EventNotificationContext.from_request_context(context)
        self._notify(context, s3_notif_ctx_initiated)
        # But because it's instant in LocalStack, we can directly send the Completed notification as well
        # We just need to copy the context so that we don't mutate the first context while it could be sent
        # And modify its event type from `ObjectRestore:Post` to `ObjectRestore:Completed`
        s3_notif_ctx_completed = copy.copy(s3_notif_ctx_initiated)
        s3_notif_ctx_completed.event_type = s3_notif_ctx_completed.event_type.replace(
            "Post", "Completed"
        )
        self._notify(context, s3_notif_ctx_completed)
        return response

    def put_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        inventory_configuration: InventoryConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)

        validate_inventory_configuration(
            config_id=id, inventory_configuration=inventory_configuration
        )

        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)
        inventory_configurations = store.bucket_inventory_configurations.setdefault(bucket, {})
        inventory_configurations[id] = inventory_configuration

    def get_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketInventoryConfigurationOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        inventory_configuration = store.bucket_inventory_configurations.get(bucket, {}).get(id)
        if not inventory_configuration:
            raise NoSuchConfiguration("The specified configuration does not exist.")
        return GetBucketInventoryConfigurationOutput(InventoryConfiguration=inventory_configuration)

    def list_bucket_inventory_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketInventoryConfigurationsOutput:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        bucket_inventory_configurations = store.bucket_inventory_configurations.get(bucket, {})

        return ListBucketInventoryConfigurationsOutput(
            IsTruncated=False,
            InventoryConfigurationList=sorted(
                bucket_inventory_configurations.values(), key=itemgetter("Id")
            ),
        )

    def delete_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        moto_bucket = get_bucket_from_moto(get_moto_s3_backend(context), bucket)
        store = self.get_store(moto_bucket.account_id, moto_bucket.region_name)

        bucket_inventory_configurations = store.bucket_inventory_configurations.get(bucket, {})
        if not bucket_inventory_configurations.pop(id, None):
            raise NoSuchConfiguration("The specified configuration does not exist.")


def is_object_expired(moto_bucket, key: ObjectKey, version_id: str = None) -> bool:
    key_object = get_key_from_moto_bucket(moto_bucket, key, version_id=version_id)
    return is_key_expired(key_object=key_object)


def apply_moto_patches():
    # importing here in case we need InvalidObjectState from `localstack.aws.api.s3`
    import moto.s3.models as moto_s3_models
    from moto.iam.access_control import PermissionResult
    from moto.s3.exceptions import InvalidObjectState

    if not os.environ.get("MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"):
        os.environ["MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"] = str(S3_MAX_FILE_SIZE_BYTES)

    # TODO: fix upstream
    moto_s3_models.STORAGE_CLASS.clear()
    moto_s3_models.STORAGE_CLASS.extend(s3_constants.VALID_STORAGE_CLASSES)

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
            for key in tags:
                tags[key] = tags[key] if tags[key] else ""
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

    @patch(moto_s3_responses.S3Response.parse_bucket_name_from_url, pass_target=False)
    def parse_bucket_name_from_url(self, request, url):
        """
        Requests going to moto will never be subdomain based, as they passed through the VirtualHost forwarder.
        We know the bucket is in the path, we can directly return it.
        """
        path = urlparse(url).path
        return path.split("/")[1]

    @patch(moto_s3_responses.S3Response.subdomain_based_buckets, pass_target=False)
    def subdomain_based_buckets(self, request):
        """
        Requests going to moto will never be subdomain based, as they passed through the VirtualHost forwarder
        """
        return False

    @patch(moto_s3_models.FakeBucket.get_permission)
    def bucket_get_permission(fn, self, *args, **kwargs):
        """
        Apply a patch to disable/enable enforcement of S3 bucket policies
        """
        if not s3_constants.ENABLE_MOTO_BUCKET_POLICY_ENFORCEMENT:
            return PermissionResult.PERMITTED

        return fn(self, *args, **kwargs)

    def key_is_locked(self):
        """
        Apply a patch to check if a key is locked
        """
        if self.lock_legal_status == "ON":
            return True

        if self.lock_mode in ["GOVERNANCE", "COMPLIANCE"]:
            now = datetime.datetime.utcnow()
            until = parse_timestamp(self.lock_until)
            if until > now:
                return True

        return False

    moto_s3_models.FakeKey.is_locked = property(key_is_locked)
