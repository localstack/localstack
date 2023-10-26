import base64
import copy
import datetime
import json
import logging
from collections import defaultdict
from operator import itemgetter
from secrets import token_urlsafe
from typing import IO, Union
from urllib import parse as urlparse

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    MFA,
    AbortMultipartUploadOutput,
    AccelerateConfiguration,
    AccessControlPolicy,
    AccessDenied,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    Body,
    Bucket,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketCannedACL,
    BucketLifecycleConfiguration,
    BucketLoggingStatus,
    BucketName,
    BucketNotEmpty,
    BucketVersioningStatus,
    BypassGovernanceRetention,
    ChecksumAlgorithm,
    ChecksumCRC32,
    ChecksumCRC32C,
    ChecksumSHA1,
    ChecksumSHA256,
    CommonPrefix,
    CompletedMultipartUpload,
    CompleteMultipartUploadOutput,
    ConfirmRemoveSelfBucketAccess,
    ContentMD5,
    CopyObjectOutput,
    CopyObjectRequest,
    CopyObjectResult,
    CopyPartResult,
    CORSConfiguration,
    CreateBucketOutput,
    CreateBucketRequest,
    CreateMultipartUploadOutput,
    CreateMultipartUploadRequest,
    CrossLocationLoggingProhibitted,
    Delete,
    DeletedObject,
    DeleteMarkerEntry,
    DeleteObjectOutput,
    DeleteObjectsOutput,
    DeleteObjectTaggingOutput,
    Delimiter,
    EncodingType,
    Error,
    Expiration,
    FetchOwner,
    GetBucketAccelerateConfigurationOutput,
    GetBucketAclOutput,
    GetBucketAnalyticsConfigurationOutput,
    GetBucketCorsOutput,
    GetBucketEncryptionOutput,
    GetBucketIntelligentTieringConfigurationOutput,
    GetBucketInventoryConfigurationOutput,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLocationOutput,
    GetBucketLoggingOutput,
    GetBucketOwnershipControlsOutput,
    GetBucketPolicyOutput,
    GetBucketPolicyStatusOutput,
    GetBucketReplicationOutput,
    GetBucketRequestPaymentOutput,
    GetBucketTaggingOutput,
    GetBucketVersioningOutput,
    GetBucketWebsiteOutput,
    GetObjectAclOutput,
    GetObjectAttributesOutput,
    GetObjectAttributesParts,
    GetObjectAttributesRequest,
    GetObjectLegalHoldOutput,
    GetObjectLockConfigurationOutput,
    GetObjectOutput,
    GetObjectRequest,
    GetObjectRetentionOutput,
    GetObjectTaggingOutput,
    GetObjectTorrentOutput,
    GetPublicAccessBlockOutput,
    HeadBucketOutput,
    HeadObjectOutput,
    HeadObjectRequest,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InvalidArgument,
    InvalidBucketName,
    InvalidDigest,
    InvalidObjectState,
    InvalidPartNumber,
    InvalidPartOrder,
    InvalidStorageClass,
    InvalidTargetBucketForLogging,
    InventoryConfiguration,
    InventoryId,
    KeyMarker,
    LifecycleRules,
    ListBucketAnalyticsConfigurationsOutput,
    ListBucketIntelligentTieringConfigurationsOutput,
    ListBucketInventoryConfigurationsOutput,
    ListBucketsOutput,
    ListMultipartUploadsOutput,
    ListObjectsOutput,
    ListObjectsV2Output,
    ListObjectVersionsOutput,
    ListPartsOutput,
    Marker,
    MaxKeys,
    MaxParts,
    MaxUploads,
    MethodNotAllowed,
    MissingSecurityHeader,
    MultipartUpload,
    MultipartUploadId,
    NoSuchBucket,
    NoSuchBucketPolicy,
    NoSuchCORSConfiguration,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    NoSuchPublicAccessBlockConfiguration,
    NoSuchTagSet,
    NoSuchUpload,
    NoSuchWebsiteConfiguration,
    NotificationConfiguration,
    Object,
    ObjectIdentifier,
    ObjectKey,
    ObjectLockConfiguration,
    ObjectLockConfigurationNotFoundError,
    ObjectLockEnabled,
    ObjectLockLegalHold,
    ObjectLockMode,
    ObjectLockRetention,
    ObjectLockToken,
    ObjectOwnership,
    ObjectVersion,
    ObjectVersionId,
    ObjectVersionStorageClass,
    OptionalObjectAttributesList,
    Owner,
    OwnershipControls,
    OwnershipControlsNotFoundError,
    Part,
    PartNumber,
    PartNumberMarker,
    Policy,
    PostResponse,
    PreconditionFailed,
    Prefix,
    PublicAccessBlockConfiguration,
    PutBucketAclRequest,
    PutObjectAclOutput,
    PutObjectAclRequest,
    PutObjectLegalHoldOutput,
    PutObjectLockConfigurationOutput,
    PutObjectOutput,
    PutObjectRequest,
    PutObjectRetentionOutput,
    PutObjectTaggingOutput,
    ReplicationConfiguration,
    ReplicationConfigurationNotFoundError,
    RequestPayer,
    RequestPaymentConfiguration,
    RestoreObjectOutput,
    RestoreRequest,
    S3Api,
    ServerSideEncryption,
    ServerSideEncryptionConfiguration,
    SkipValidation,
    SSECustomerAlgorithm,
    SSECustomerKey,
    SSECustomerKeyMD5,
    StartAfter,
    StorageClass,
    Tagging,
    Token,
    UploadIdMarker,
    UploadPartCopyOutput,
    UploadPartCopyRequest,
    UploadPartOutput,
    UploadPartRequest,
    VersionIdMarker,
    VersioningConfiguration,
    WebsiteConfiguration,
)
from localstack.aws.handlers import preprocess_request, serve_custom_service_request_handlers
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.codec import AwsChunkedDecoder
from localstack.services.s3.constants import (
    ALLOWED_HEADER_OVERRIDES,
    ARCHIVES_STORAGE_CLASSES,
    DEFAULT_BUCKET_ENCRYPTION,
)
from localstack.services.s3.cors import S3CorsHandler, s3_cors_request_handler
from localstack.services.s3.exceptions import (
    InvalidBucketState,
    InvalidLocationConstraint,
    InvalidRequest,
    MalformedPolicy,
    MalformedXML,
    NoSuchConfiguration,
    NoSuchObjectLockConfiguration,
    UnexpectedContent,
)
from localstack.services.s3.notifications import NotificationDispatcher, S3EventNotificationContext
from localstack.services.s3.presigned_url import validate_post_policy
from localstack.services.s3.utils import (
    ObjectRange,
    add_expiration_days_to_datetime,
    create_redirect_for_post_request,
    create_s3_kms_managed_key_for_region,
    etag_to_base_64_content_md5,
    extract_bucket_key_version_id_from_copy_source,
    get_canned_acl,
    get_class_attrs_from_spec_class,
    get_failed_precondition_copy_source,
    get_full_default_bucket_location,
    get_kms_key_arn,
    get_lifecycle_rule_from_object,
    get_owner_for_account_id,
    get_permission_from_header,
    get_retention_from_now,
    get_system_metadata_from_request,
    get_unique_key_id,
    is_bucket_name_valid,
    parse_copy_source_range_header,
    parse_post_object_tagging_xml,
    parse_range_header,
    parse_tagging_header,
    serialize_expiration_header,
    str_to_rfc_1123_datetime,
    validate_dict_fields,
    validate_failed_precondition,
    validate_kms_key_id,
    validate_tag_set,
)
from localstack.services.s3.v3.models import (
    BucketCorsIndex,
    EncryptionParameters,
    ObjectLockParameters,
    S3Bucket,
    S3DeleteMarker,
    S3Multipart,
    S3Object,
    S3Part,
    S3Store,
    VersionedKeyStore,
    s3_stores,
)
from localstack.services.s3.v3.storage.core import LimitedIterableStream, S3ObjectStore
from localstack.services.s3.v3.storage.ephemeral import EphemeralS3ObjectStore
from localstack.services.s3.validation import (
    parse_grants_in_headers,
    validate_acl_acp,
    validate_bucket_analytics_configuration,
    validate_bucket_intelligent_tiering_configuration,
    validate_canned_acl,
    validate_cors_configuration,
    validate_inventory_configuration,
    validate_lifecycle_configuration,
    validate_website_configuration,
)
from localstack.services.s3.website_hosting import register_website_hosting_routes
from localstack.state import AssetDirectory, StateVisitor
from localstack.utils.aws.arns import s3_bucket_name
from localstack.utils.strings import short_uid, to_str

LOG = logging.getLogger(__name__)

STORAGE_CLASSES = get_class_attrs_from_spec_class(StorageClass)
SSE_ALGORITHMS = get_class_attrs_from_spec_class(ServerSideEncryption)
OBJECT_OWNERSHIPS = get_class_attrs_from_spec_class(ObjectOwnership)

DEFAULT_S3_TMP_DIR = "/tmp/localstack-s3-storage"


class S3Provider(S3Api, ServiceLifecycleHook):
    def __init__(self, storage_backend: S3ObjectStore = None) -> None:
        super().__init__()
        self._storage_backend = storage_backend or EphemeralS3ObjectStore(DEFAULT_S3_TMP_DIR)
        self._notification_dispatcher = NotificationDispatcher()
        self._cors_handler = S3CorsHandler(BucketCorsIndex())

        # runtime cache of Lifecycle Expiration headers, as they need to be calculated everytime we fetch an object
        # in case the rules have changed
        self._expiration_cache: dict[BucketName, dict[ObjectKey, Expiration]] = defaultdict(dict)

    def on_after_init(self):
        preprocess_request.append(self._cors_handler)
        serve_custom_service_request_handlers.append(s3_cors_request_handler)
        register_website_hosting_routes(router=ROUTER)

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(s3_stores)
        visitor.visit(AssetDirectory(self.service, self._storage_backend.root_directory))

    def on_before_state_save(self):
        self._storage_backend.flush()

    def on_before_stop(self):
        self._notification_dispatcher.shutdown()
        self._storage_backend.close()

    def _notify(
        self,
        context: RequestContext,
        s3_bucket: S3Bucket,
        s3_object: S3Object | S3DeleteMarker = None,
        s3_notif_ctx: S3EventNotificationContext = None,
    ):
        """
        :param context: the RequestContext, to retrieve more information about the incoming notification
        :param s3_bucket: the S3Bucket object
        :param s3_object: the S3Object object if S3EventNotificationContext is not given
        :param s3_notif_ctx: S3EventNotificationContext, in case we need specific data only available in the API call
        :return:
        """
        if s3_bucket.notification_configuration:
            if not s3_notif_ctx:
                s3_notif_ctx = S3EventNotificationContext.from_request_context_native(
                    context,
                    s3_bucket=s3_bucket,
                    s3_object=s3_object,
                )

            self._notification_dispatcher.send_notifications(
                s3_notif_ctx, s3_bucket.notification_configuration
            )

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
        self,
        lifecycle_rules: LifecycleRules,
        bucket: BucketName,
        s3_object: S3Object,
        object_tags: dict[str, str],
    ) -> Expiration:
        """
        This method will check if the key matches a Lifecycle filter, and return the serializer header if that's
        the case. We're caching it because it can change depending on the set rules on the bucket.
        We can't use `lru_cache` as the parameters needs to be hashable
        :param lifecycle_rules: the bucket LifecycleRules
        :param s3_object: S3Object
        :param object_tags: the object tags
        :return: the Expiration header if there's a rule matching
        """
        if cached_exp := self._expiration_cache.get(bucket, {}).get(s3_object.key):
            return cached_exp

        if lifecycle_rule := get_lifecycle_rule_from_object(
            lifecycle_rules, s3_object.key, s3_object.size, object_tags
        ):
            expiration_header = serialize_expiration_header(
                lifecycle_rule["ID"],
                lifecycle_rule["Expiration"],
                s3_object.last_modified,
            )
            self._expiration_cache[bucket][s3_object.key] = expiration_header
            return expiration_header

    def _get_cross_account_bucket(
        self, context: RequestContext, bucket_name: BucketName
    ) -> tuple[S3Store, S3Bucket]:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket_name)):
            if not (account_id := store.global_bucket_map.get(bucket_name)):
                raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

            store = self.get_store(account_id, context.region)
            if not (s3_bucket := store.buckets.get(bucket_name)):
                raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        return store, s3_bucket

    @staticmethod
    def get_store(account_id: str, region_name: str) -> S3Store:
        # Use default account id for external access? would need an anonymous one
        return s3_stores[account_id][region_name]

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self,
        context: RequestContext,
        request: CreateBucketRequest,
    ) -> CreateBucketOutput:
        bucket_name = request["Bucket"]

        if not is_bucket_name_valid(bucket_name):
            raise InvalidBucketName("The specified bucket is not valid.", BucketName=bucket_name)
        if create_bucket_configuration := request.get("CreateBucketConfiguration"):
            if not (bucket_region := create_bucket_configuration.get("LocationConstraint")):
                raise MalformedXML()

            if bucket_region == "us-east-1":
                raise InvalidLocationConstraint("The specified location-constraint is not valid")
        else:
            bucket_region = "us-east-1"
            if context.region != bucket_region:
                raise CommonServiceException(
                    code="IllegalLocationConstraintException",
                    message="The unspecified location constraint is incompatible for the region specific endpoint this request was sent to.",
                )

        store = self.get_store(context.account_id, bucket_region)

        if bucket_name in store.global_bucket_map:
            existing_bucket_owner = store.global_bucket_map[bucket_name]
            if existing_bucket_owner != context.account_id:
                raise BucketAlreadyExists()

            # if the existing bucket has the same owner, the behaviour will depend on the region
            if bucket_region != "us-east-1":
                raise BucketAlreadyOwnedByYou(
                    "Your previous request to create the named bucket succeeded and you already own it.",
                    BucketName=bucket_name,
                )
            else:
                # CreateBucket is idempotent in us-east-1
                return CreateBucketOutput(Location=f"/{bucket_name}")

        if (
            object_ownership := request.get("ObjectOwnership")
        ) is not None and object_ownership not in OBJECT_OWNERSHIPS:
            raise InvalidArgument(
                f"Invalid x-amz-object-ownership header: {object_ownership}",
                ArgumentName="x-amz-object-ownership",
            )
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html
        owner = get_owner_for_account_id(context.account_id)
        acl = get_access_control_policy_for_new_resource_request(request, owner=owner)
        s3_bucket = S3Bucket(
            name=bucket_name,
            account_id=context.account_id,
            bucket_region=bucket_region,
            owner=owner,
            acl=acl,
            object_ownership=request.get("ObjectOwnership"),
            object_lock_enabled_for_bucket=request.get("ObjectLockEnabledForBucket"),
        )

        store.buckets[bucket_name] = s3_bucket
        store.global_bucket_map[bucket_name] = s3_bucket.bucket_account_id
        self._cors_handler.invalidate_cache()
        self._storage_backend.create_bucket(bucket_name)

        # Location is always contained in response -> full url for LocationConstraint outside us-east-1
        location = (
            f"/{bucket_name}"
            if bucket_region == "us-east-1"
            else get_full_default_bucket_location(bucket_name)
        )
        response = CreateBucketOutput(Location=location)
        return response

    def delete_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        # the bucket still contains objects
        if not s3_bucket.objects.is_empty():
            message = "The bucket you tried to delete is not empty"
            if s3_bucket.versioning_status:
                message += ". You must delete all versions in the bucket."
            raise BucketNotEmpty(
                message,
                BucketName=bucket,
            )

        store.buckets.pop(bucket)
        store.global_bucket_map.pop(bucket)
        self._cors_handler.invalidate_cache()
        self._expiration_cache.pop(bucket, None)
        # clean up the storage backend
        self._storage_backend.delete_bucket(bucket)

    def list_buckets(
        self,
        context: RequestContext,
    ) -> ListBucketsOutput:
        owner = get_owner_for_account_id(context.account_id)
        store = self.get_store(context.account_id, context.region)
        buckets = [
            Bucket(Name=bucket.name, CreationDate=bucket.creation_date)
            for bucket in store.buckets.values()
        ]
        return ListBucketsOutput(Owner=owner, Buckets=buckets)

    def head_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> HeadBucketOutput:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            if not (account_id := store.global_bucket_map.get(bucket)):
                # just to return the 404 error message
                raise NoSuchBucket()

            store = self.get_store(account_id, context.region)
            if not (s3_bucket := store.buckets.get(bucket)):
                # just to return the 404 error message
                raise NoSuchBucket()

        # TODO: this call is also used to check if the user has access/authorization for the bucket
        #  it can return 403
        return HeadBucketOutput(BucketRegion=s3_bucket.bucket_region)

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
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        location_constraint = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{{location}}</LocationConstraint>'
        )

        location = s3_bucket.bucket_region if s3_bucket.bucket_region != "us-east-1" else ""
        location_constraint = location_constraint.replace("{{location}}", location)

        response = GetBucketLocationOutput(LocationConstraint=location_constraint)
        return response

    @handler("PutObject", expand=False)
    def put_object(
        self,
        context: RequestContext,
        request: PutObjectRequest,
    ) -> PutObjectOutput:
        # TODO: validate order of validation
        # TODO: still need to handle following parameters
        #  request_payer: RequestPayer = None,
        bucket_name = request["Bucket"]
        store, s3_bucket = self._get_cross_account_bucket(context, bucket_name)

        if (storage_class := request.get("StorageClass")) is not None and (
            storage_class not in STORAGE_CLASSES or storage_class == StorageClass.OUTPOSTS
        ):
            raise InvalidStorageClass(
                "The storage class you specified is not valid", StorageClassRequested=storage_class
            )

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, s3_bucket)

        key = request["Key"]

        system_metadata = get_system_metadata_from_request(request)
        if not system_metadata.get("ContentType"):
            system_metadata["ContentType"] = "binary/octet-stream"

        version_id = generate_version_id(s3_bucket.versioning_status)

        checksum_algorithm = request.get("ChecksumAlgorithm")
        checksum_value = (
            request.get(f"Checksum{checksum_algorithm.upper()}") if checksum_algorithm else None
        )

        encryption_parameters = get_encryption_parameters_from_request_and_bucket(
            request,
            s3_bucket,
            store,
        )

        lock_parameters = get_object_lock_parameters_from_bucket_and_request(request, s3_bucket)

        acl = get_access_control_policy_for_new_resource_request(request, owner=s3_bucket.owner)

        if tagging := request.get("Tagging"):
            tagging = parse_tagging_header(tagging)

        s3_object = S3Object(
            key=key,
            version_id=version_id,
            storage_class=storage_class,
            expires=request.get("Expires"),
            user_metadata=request.get("Metadata"),
            system_metadata=system_metadata,
            checksum_algorithm=checksum_algorithm,
            checksum_value=checksum_value,
            encryption=encryption_parameters.encryption,
            kms_key_id=encryption_parameters.kms_key_id,
            bucket_key_enabled=encryption_parameters.bucket_key_enabled,
            lock_mode=lock_parameters.lock_mode,
            lock_legal_status=lock_parameters.lock_legal_status,
            lock_until=lock_parameters.lock_until,
            website_redirect_location=request.get("WebsiteRedirectLocation"),
            acl=acl,
            owner=s3_bucket.owner,  # TODO: for now we only have one owner, but it can depends on Bucket settings
        )

        body = request.get("Body")
        # check if chunked request
        headers = context.request.headers
        is_aws_chunked = headers.get("x-amz-content-sha256", "").startswith("STREAMING-")
        if is_aws_chunked:
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
            body = AwsChunkedDecoder(body, decoded_content_length, s3_object=s3_object)

        s3_stored_object = self._storage_backend.open(bucket_name, s3_object)
        s3_stored_object.write(body)

        if checksum_algorithm and s3_object.checksum_value != s3_stored_object.checksum:
            self._storage_backend.remove(bucket_name, s3_object)
            raise InvalidRequest(
                f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
            )

        # TODO: handle ContentMD5 and ChecksumAlgorithm in a handler for all requests except requests with a streaming
        #  body. We can use the specs to verify which operations needs to have the checksum validated
        if content_md5 := request.get("ContentMD5"):
            calculated_md5 = etag_to_base_64_content_md5(s3_stored_object.etag)
            if calculated_md5 != content_md5:
                self._storage_backend.remove(bucket_name, s3_object)
                raise InvalidDigest(
                    "The Content-MD5 you specified was invalid.",
                    Content_MD5=content_md5,
                )

        s3_bucket.objects.set(key, s3_object)

        # in case we are overriding an object, delete the tags entry
        key_id = get_unique_key_id(bucket_name, key, version_id)
        store.TAGS.tags.pop(key_id, None)
        if tagging:
            store.TAGS.tags[key_id] = tagging

        # RequestCharged: Optional[RequestCharged]  # TODO
        response = PutObjectOutput(
            ETag=s3_object.quoted_etag,
        )
        if s3_bucket.versioning_status == "Enabled":
            response["VersionId"] = s3_object.version_id

        if s3_object.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_object.checksum_value

        if s3_bucket.lifecycle_rules:
            if expiration_header := self._get_expiration_header(
                s3_bucket.lifecycle_rules,
                bucket_name,
                s3_object,
                store.TAGS.tags.get(key_id, {}),
            ):
                # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to
                #  apply them everytime we get/head an object
                response["Expiration"] = expiration_header

        add_encryption_to_response(response, s3_object=s3_object)
        self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)

        return response

    @handler("GetObject", expand=False)
    def get_object(
        self,
        context: RequestContext,
        request: GetObjectRequest,
    ) -> GetObjectOutput:
        # TODO: missing handling parameters:
        #  request_payer: RequestPayer = None,
        #  expected_bucket_owner: AccountId = None,

        bucket_name = request["Bucket"]
        object_key = request["Key"]
        version_id = request.get("VersionId")
        store, s3_bucket = self._get_cross_account_bucket(context, bucket_name)

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=version_id,
            http_method="GET",
        )
        if s3_object.expires and s3_object.expires < datetime.datetime.now(
            tz=s3_object.expires.tzinfo
        ):
            # TODO: old behaviour was deleting key instantly if expired. AWS cleans up only once a day generally
            #  you can still HeadObject on it and you get the expiry time until scheduled deletion
            kwargs = {"Key": object_key}
            if version_id:
                kwargs["VersionId"] = version_id
            raise NoSuchKey("The specified key does not exist.", **kwargs)

        if s3_object.storage_class in ARCHIVES_STORAGE_CLASSES and not s3_object.restore:
            raise InvalidObjectState(
                "The operation is not valid for the object's storage class",
                StorageClass=s3_object.storage_class,
            )

        if not config.S3_SKIP_KMS_KEY_VALIDATION and s3_object.kms_key_id:
            validate_kms_key_id(kms_key=s3_object.kms_key_id, bucket=s3_bucket)

        validate_failed_precondition(request, s3_object.last_modified, s3_object.etag)

        response = GetObjectOutput(
            AcceptRanges="bytes",
            **s3_object.get_system_metadata_fields(),
        )
        if s3_object.user_metadata:
            response["Metadata"] = s3_object.user_metadata

        if s3_object.parts and request.get("PartNumber"):
            response["PartsCount"] = len(s3_object.parts)

        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        if s3_object.website_redirect_location:
            response["WebsiteRedirectLocation"] = s3_object.website_redirect_location

        if s3_object.restore:
            response["Restore"] = s3_object.restore

        if checksum_algorithm := s3_object.checksum_algorithm:
            if (request.get("ChecksumMode") or "").upper() == "ENABLED":
                response[f"Checksum{checksum_algorithm.upper()}"] = s3_object.checksum_value

        s3_stored_object = self._storage_backend.open(bucket_name, s3_object)

        range_header = request.get("Range")
        part_number = request.get("PartNumber")
        if range_header and part_number:
            raise InvalidRequest("Cannot specify both Range header and partNumber query parameter")
        range_data = None
        if range_header:
            range_data = parse_range_header(range_header, s3_object.size)
        elif part_number:
            range_data = get_part_range(s3_object, part_number)

        if range_data:
            s3_stored_object.seek(range_data.begin)
            response["Body"] = LimitedIterableStream(
                s3_stored_object, max_length=range_data.content_length
            )
            response["ContentRange"] = range_data.content_range
            response["ContentLength"] = range_data.content_length
            response["StatusCode"] = 206
        else:
            response["Body"] = s3_stored_object

        add_encryption_to_response(response, s3_object=s3_object)

        if object_tags := store.TAGS.tags.get(
            get_unique_key_id(bucket_name, object_key, version_id)
        ):
            response["TagCount"] = len(object_tags)

        if s3_object.is_current and s3_bucket.lifecycle_rules:
            if expiration_header := self._get_expiration_header(
                s3_bucket.lifecycle_rules,
                bucket_name,
                s3_object,
                object_tags,
            ):
                # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to
                #  apply them everytime we get/head an object
                response["Expiration"] = expiration_header

        # TODO: missing returned fields
        #     RequestCharged: Optional[RequestCharged]
        #     ReplicationStatus: Optional[ReplicationStatus]

        if s3_object.lock_mode:
            response["ObjectLockMode"] = s3_object.lock_mode
            if s3_object.lock_until:
                response["ObjectLockRetainUntilDate"] = s3_object.lock_until
        if s3_object.lock_legal_status:
            response["ObjectLockLegalHoldStatus"] = s3_object.lock_legal_status

        for request_param, response_param in ALLOWED_HEADER_OVERRIDES.items():
            if request_param_value := request.get(request_param):
                response[response_param] = request_param_value

        return response

    @handler("HeadObject", expand=False)
    def head_object(
        self,
        context: RequestContext,
        request: HeadObjectRequest,
    ) -> HeadObjectOutput:
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        version_id = request.get("VersionId")
        store, s3_bucket = self._get_cross_account_bucket(context, bucket_name)

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=version_id,
            http_method="HEAD",
        )

        validate_failed_precondition(request, s3_object.last_modified, s3_object.etag)

        response = HeadObjectOutput(
            AcceptRanges="bytes",
            **s3_object.get_system_metadata_fields(),
        )
        if s3_object.user_metadata:
            response["Metadata"] = s3_object.user_metadata

        if checksum_algorithm := s3_object.checksum_algorithm:
            if (request.get("ChecksumMode") or "").upper() == "ENABLED":
                response[f"Checksum{checksum_algorithm.upper()}"] = s3_object.checksum_value

        if s3_object.parts:
            response["PartsCount"] = len(s3_object.parts)

        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        if s3_object.website_redirect_location:
            response["WebsiteRedirectLocation"] = s3_object.website_redirect_location

        if s3_object.restore:
            response["Restore"] = s3_object.restore

        range_header = request.get("Range")
        part_number = request.get("PartNumber")
        if range_header and part_number:
            raise InvalidRequest("Cannot specify both Range header and partNumber query parameter")
        range_data = None
        if range_header:
            range_data = parse_range_header(range_header, s3_object.size)
        elif part_number:
            range_data = get_part_range(s3_object, part_number)

        if range_data:
            response["ContentLength"] = range_data.content_length
            response["StatusCode"] = 206

        add_encryption_to_response(response, s3_object=s3_object)

        # if you specify the VersionId, AWS won't return the Expiration header, even if that's the current version
        if not version_id and s3_bucket.lifecycle_rules:
            object_tags = store.TAGS.tags.get(
                get_unique_key_id(bucket_name, object_key, s3_object.version_id)
            )
            if expiration_header := self._get_expiration_header(
                s3_bucket.lifecycle_rules,
                bucket_name,
                s3_object,
                object_tags,
            ):
                # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to
                #  apply them everytime we get/head an object
                response["Expiration"] = expiration_header

        if s3_object.lock_mode:
            response["ObjectLockMode"] = s3_object.lock_mode
            if s3_object.lock_until:
                response["ObjectLockRetainUntilDate"] = s3_object.lock_until
        if s3_object.lock_legal_status:
            response["ObjectLockLegalHoldStatus"] = s3_object.lock_legal_status

        # TODO: missing return fields:
        #  ArchiveStatus: Optional[ArchiveStatus]
        #  RequestCharged: Optional[RequestCharged]
        #  ReplicationStatus: Optional[ReplicationStatus]

        return response

    def delete_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        mfa: MFA = None,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if bypass_governance_retention is not None and not s3_bucket.object_lock_enabled:
            raise InvalidArgument(
                "x-amz-bypass-governance-retention is only applicable to Object Lock enabled buckets.",
                ArgumentName="x-amz-bypass-governance-retention",
            )

        if s3_bucket.versioning_status is None:
            if version_id and version_id != "null":
                raise InvalidArgument(
                    "Invalid version id specified",
                    ArgumentName="versionId",
                    ArgumentValue=version_id,
                )

            found_object = s3_bucket.objects.pop(key, None)
            # TODO: RequestCharged
            if found_object:
                self._storage_backend.remove(bucket, found_object)
                self._notify(context, s3_bucket=s3_bucket, s3_object=found_object)
                store.TAGS.tags.pop(get_unique_key_id(bucket, key, version_id), None)

            return DeleteObjectOutput()

        if not version_id:
            delete_marker_id = generate_version_id(s3_bucket.versioning_status)
            delete_marker = S3DeleteMarker(key=key, version_id=delete_marker_id)
            s3_bucket.objects.set(key, delete_marker)
            # TODO: make a proper difference between DeleteMarker and S3Object, not done yet
            #  s3:ObjectRemoved:DeleteMarkerCreated
            self._notify(context, s3_bucket=s3_bucket, s3_object=delete_marker)

            return DeleteObjectOutput(VersionId=delete_marker.version_id, DeleteMarker=True)

        if key not in s3_bucket.objects:
            return DeleteObjectOutput()

        if not (s3_object := s3_bucket.objects.get(key, version_id)):
            raise InvalidArgument(
                "Invalid version id specified",
                ArgumentName="versionId",
                ArgumentValue=version_id,
            )

        if s3_object.is_locked(bypass_governance_retention):
            raise AccessDenied("Access Denied")

        s3_bucket.objects.pop(object_key=key, version_id=version_id)
        response = DeleteObjectOutput(VersionId=s3_object.version_id)

        if isinstance(s3_object, S3DeleteMarker):
            response["DeleteMarker"] = True
        else:
            self._storage_backend.remove(bucket, s3_object)
            self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)
            store.TAGS.tags.pop(get_unique_key_id(bucket, key, version_id), None)

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
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if bypass_governance_retention is not None and not s3_bucket.object_lock_enabled:
            raise InvalidArgument(
                "x-amz-bypass-governance-retention is only applicable to Object Lock enabled buckets.",
                ArgumentName="x-amz-bypass-governance-retention",
            )

        objects: list[ObjectIdentifier] = delete.get("Objects")
        if not objects:
            raise MalformedXML()

        # TODO: max 1000 delete at once? test against AWS?

        quiet = delete.get("Quiet", False)
        deleted = []
        errors = []

        to_remove = []
        for to_delete_object in objects:
            object_key = to_delete_object.get("Key")
            version_id = to_delete_object.get("VersionId")
            if s3_bucket.versioning_status is None:
                if version_id and version_id != "null":
                    errors.append(
                        Error(
                            Code="NoSuchVersion",
                            Key=object_key,
                            Message="The specified version does not exist.",
                            VersionId=version_id,
                        )
                    )
                    continue

                found_object = s3_bucket.objects.pop(object_key, None)
                if found_object:
                    to_remove.append(found_object)
                    self._notify(context, s3_bucket=s3_bucket, s3_object=found_object)
                    store.TAGS.tags.pop(get_unique_key_id(bucket, object_key, version_id), None)
                # small hack to not create a fake object for nothing
                elif s3_bucket.notification_configuration:
                    # DeleteObjects is a bit weird, even if the object didn't exist, S3 will trigger a notification
                    # for a non-existing object being deleted
                    self._notify(
                        context, s3_bucket=s3_bucket, s3_object=S3Object(key=object_key, etag="")
                    )

                if not quiet:
                    deleted.append(DeletedObject(Key=object_key))

                continue

            if not version_id:
                delete_marker_id = generate_version_id(s3_bucket.versioning_status)
                delete_marker = S3DeleteMarker(key=object_key, version_id=delete_marker_id)
                s3_bucket.objects.set(object_key, delete_marker)
                # TODO: make a difference between DeleteMarker and S3Object
                self._notify(context, s3_bucket=s3_bucket, s3_object=delete_marker)
                if not quiet:
                    deleted.append(
                        DeletedObject(
                            DeleteMarker=True,
                            DeleteMarkerVersionId=delete_marker_id,
                            Key=object_key,
                        )
                    )
                continue

            if not (
                found_object := s3_bucket.objects.get(object_key=object_key, version_id=version_id)
            ):
                errors.append(
                    Error(
                        Code="NoSuchVersion",
                        Key=object_key,
                        Message="The specified version does not exist.",
                        VersionId=version_id,
                    )
                )
                continue

            if found_object.is_locked(bypass_governance_retention):
                errors.append(
                    Error(
                        Code="AccessDenied",
                        Key=object_key,
                        Message="Access Denied",
                        VersionId=version_id,
                    )
                )
                continue

            s3_bucket.objects.pop(object_key=object_key, version_id=version_id)
            if not quiet:
                deleted_object = DeletedObject(
                    Key=object_key,
                    VersionId=version_id,
                )
                if isinstance(found_object, S3DeleteMarker):
                    deleted_object["DeleteMarker"] = True
                    deleted_object["DeleteMarkerVersionId"] = found_object.version_id

                deleted.append(deleted_object)

            if isinstance(found_object, S3Object):
                to_remove.append(found_object)

            self._notify(context, s3_bucket=s3_bucket, s3_object=found_object)
            store.TAGS.tags.pop(get_unique_key_id(bucket, object_key, version_id), None)

        # TODO: request charged
        self._storage_backend.remove(bucket, to_remove)
        response: DeleteObjectsOutput = {}
        # AWS validated: the list of Deleted objects is unordered, multiple identical calls can return different results
        if errors:
            response["Errors"] = errors
        if not quiet:
            response["Deleted"] = deleted

        return response

    @handler("CopyObject", expand=False)
    def copy_object(
        self,
        context: RequestContext,
        request: CopyObjectRequest,
    ) -> CopyObjectOutput:
        # request_payer: RequestPayer = None,  # TODO:
        dest_bucket = request["Bucket"]
        dest_key = request["Key"]
        store = self.get_store(context.account_id, context.region)
        # TODO: verify cross account CopyObject
        if not (dest_s3_bucket := store.buckets.get(dest_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=dest_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request.get("CopySource")
        )

        if not (src_s3_bucket := store.buckets.get(src_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=src_bucket)

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, dest_s3_bucket)

        # if the object is a delete marker, get_object will raise NotFound if no versionId, like AWS
        try:
            src_s3_object = src_s3_bucket.get_object(key=src_key, version_id=src_version_id)
        except MethodNotAllowed:
            raise InvalidRequest(
                "The source of a copy request may not specifically refer to a delete marker by version id."
            )

        if src_s3_object.storage_class in ARCHIVES_STORAGE_CLASSES and not src_s3_object.restore:
            raise InvalidObjectState(
                "Operation is not valid for the source object's storage class",
                StorageClass=src_s3_object.storage_class,
            )

        if failed_condition := get_failed_precondition_copy_source(
            request, src_s3_object.last_modified, src_s3_object.etag
        ):
            raise PreconditionFailed(
                "At least one of the pre-conditions you specified did not hold",
                Condition=failed_condition,
            )

        # TODO validate order of validation
        storage_class = request.get("StorageClass")
        server_side_encryption = request.get("ServerSideEncryption")
        metadata_directive = request.get("MetadataDirective")
        website_redirect_location = request.get("WebsiteRedirectLocation")
        # we need to check for identity of the object, to see if the default one has been changed
        is_default_encryption = (
            dest_s3_bucket.encryption_rule is DEFAULT_BUCKET_ENCRYPTION
            and src_s3_object.encryption == "AES256"
        )
        if (
            src_bucket == dest_bucket
            and src_key == dest_key
            and not any(
                (
                    storage_class,
                    server_side_encryption,
                    metadata_directive == "REPLACE",
                    website_redirect_location,
                    dest_s3_bucket.encryption_rule
                    and not is_default_encryption,  # S3 will allow copy in place if the bucket has encryption configured
                    src_s3_object.restore,
                )
            )
        ):
            raise InvalidRequest(
                "This copy request is illegal because it is trying to copy an object to itself without changing the "
                "object's metadata, storage class, website redirect location or encryption attributes."
            )

        if tagging := request.get("Tagging"):
            tagging = parse_tagging_header(tagging)

        if metadata_directive == "REPLACE":
            user_metadata = request.get("Metadata")
            system_metadata = get_system_metadata_from_request(request)
            if not system_metadata.get("ContentType"):
                system_metadata["ContentType"] = "binary/octet-stream"
        else:
            user_metadata = src_s3_object.user_metadata
            system_metadata = src_s3_object.system_metadata

        dest_version_id = generate_version_id(dest_s3_bucket.versioning_status)

        encryption_parameters = get_encryption_parameters_from_request_and_bucket(
            request,
            dest_s3_bucket,
            store,
        )
        lock_parameters = get_object_lock_parameters_from_bucket_and_request(
            request, dest_s3_bucket
        )

        acl = get_access_control_policy_for_new_resource_request(
            request, owner=dest_s3_bucket.owner
        )

        s3_object = S3Object(
            key=dest_key,
            size=src_s3_object.size,
            version_id=dest_version_id,
            storage_class=storage_class,
            expires=request.get("Expires"),
            user_metadata=user_metadata,
            system_metadata=system_metadata,
            checksum_algorithm=request.get("ChecksumAlgorithm") or src_s3_object.checksum_algorithm,
            encryption=encryption_parameters.encryption,
            kms_key_id=encryption_parameters.kms_key_id,
            bucket_key_enabled=request.get(
                "BucketKeyEnabled"
            ),  # CopyObject does not inherit from the bucket here
            lock_mode=lock_parameters.lock_mode,
            lock_legal_status=lock_parameters.lock_legal_status,
            lock_until=lock_parameters.lock_until,
            website_redirect_location=website_redirect_location,
            expiration=None,  # TODO, from lifecycle
            acl=acl,
            owner=dest_s3_bucket.owner,
        )

        s3_stored_object = self._storage_backend.copy(
            src_bucket=src_bucket,
            src_object=src_s3_object,
            dest_bucket=dest_bucket,
            dest_object=s3_object,
        )
        s3_object.checksum_value = s3_stored_object.checksum or src_s3_object.checksum_value
        s3_object.etag = s3_stored_object.etag or src_s3_object.etag

        # Object copied from Glacier object should not have expiry
        # TODO: verify this assumption from moto?
        dest_s3_bucket.objects.set(dest_key, s3_object)

        dest_key_id = get_unique_key_id(dest_bucket, dest_key, dest_version_id)
        if (request.get("TaggingDirective")) == "REPLACE":
            store.TAGS.tags[dest_key_id] = tagging
        else:
            src_key_id = get_unique_key_id(src_bucket, src_key, src_version_id)
            store.TAGS.tags[dest_key_id] = copy.copy(store.TAGS.tags.get(src_key_id, {}))

        copy_object_result = CopyObjectResult(
            ETag=s3_object.quoted_etag,
            LastModified=s3_object.last_modified,
        )
        if s3_object.checksum_algorithm:
            copy_object_result[
                f"Checksum{s3_object.checksum_algorithm.upper()}"
            ] = s3_object.checksum_value

        response = CopyObjectOutput(
            CopyObjectResult=copy_object_result,
        )

        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        if s3_object.expiration:
            response["Expiration"] = s3_object.expiration  # TODO: properly parse the datetime

        add_encryption_to_response(response, s3_object=s3_object)

        if src_s3_bucket.versioning_status and src_s3_object.version_id:
            response["CopySourceVersionId"] = src_s3_object.version_id

        # RequestCharged: Optional[RequestCharged] # TODO
        self._notify(context, s3_bucket=dest_s3_bucket, s3_object=s3_object)

        return response

    def list_objects(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter = None,
        encoding_type: EncodingType = None,
        marker: Marker = None,
        max_keys: MaxKeys = None,
        prefix: Prefix = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
        optional_object_attributes: OptionalObjectAttributesList = None,
    ) -> ListObjectsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        common_prefixes = set()
        count = 0
        is_truncated = False
        next_key_marker = None
        max_keys = max_keys or 1000
        prefix = prefix or ""
        delimiter = delimiter or ""
        if encoding_type:
            prefix = urlparse.quote(prefix)
            delimiter = urlparse.quote(delimiter)

        s3_objects: list[Object] = []

        # sort by key
        all_objects = sorted(s3_bucket.objects.values(), key=lambda r: r.key)
        for s3_object in all_objects:
            if count >= max_keys:
                is_truncated = True
                if s3_objects:
                    next_key_marker = s3_objects[-1]["Key"]
                break

            key = urlparse.quote(s3_object.key) if encoding_type else s3_object.key
            # skip all keys that alphabetically come before key_marker
            if marker:
                if key <= marker:
                    continue

            # Filter for keys that start with prefix
            if prefix and not key.startswith(prefix):
                continue

            # separate keys that contain the same string between the prefix and the first occurrence of the delimiter
            if delimiter and delimiter in (key_no_prefix := key.removeprefix(prefix)):
                pre_delimiter, _, _ = key_no_prefix.partition(delimiter)
                prefix_including_delimiter = f"{prefix}{pre_delimiter}{delimiter}"

                if prefix_including_delimiter not in common_prefixes:
                    count += 1
                    common_prefixes.add(prefix_including_delimiter)
                continue

            # TODO: add RestoreStatus if present
            object_data = Object(
                Key=key,
                ETag=s3_object.quoted_etag,
                Owner=s3_bucket.owner,  # TODO: verify reality
                Size=s3_object.size,
                LastModified=s3_object.last_modified,
                StorageClass=s3_object.storage_class,
            )

            if s3_object.checksum_algorithm:
                object_data["ChecksumAlgorithm"] = [s3_object.checksum_algorithm]

            s3_objects.append(object_data)

            count += 1

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListObjectsOutput(
            IsTruncated=is_truncated,
            Name=bucket,
            MaxKeys=max_keys,
            Prefix=prefix or "",
            Marker=marker or "",
        )
        if s3_objects:
            response["Contents"] = s3_objects
        if encoding_type:
            response["EncodingType"] = EncodingType.url
        if delimiter:
            response["Delimiter"] = delimiter
        if common_prefixes:
            response["CommonPrefixes"] = common_prefixes
        if delimiter and next_key_marker:
            response["NextMarker"] = next_key_marker
        if s3_bucket.bucket_region != "us-east-1":
            response["BucketRegion"] = s3_bucket.bucket_region

        # RequestCharged: Optional[RequestCharged]  # TODO
        return response

    def list_objects_v2(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter = None,
        encoding_type: EncodingType = None,
        max_keys: MaxKeys = None,
        prefix: Prefix = None,
        continuation_token: Token = None,
        fetch_owner: FetchOwner = None,
        start_after: StartAfter = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
        optional_object_attributes: OptionalObjectAttributesList = None,
    ) -> ListObjectsV2Output:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if continuation_token == "":
            raise InvalidArgument(
                "The continuation token provided is incorrect",
                ArgumentName="continuation-token",
            )

        common_prefixes = set()
        count = 0
        is_truncated = False
        next_continuation_token = None
        max_keys = max_keys or 1000
        prefix = prefix or ""
        delimiter = delimiter or ""
        if encoding_type:
            prefix = urlparse.quote(prefix)
            delimiter = urlparse.quote(delimiter)
        decoded_continuation_token = (
            to_str(base64.urlsafe_b64decode(continuation_token.encode()))
            if continuation_token
            else None
        )

        s3_objects: list[Object] = []

        # sort by key
        for s3_object in sorted(s3_bucket.objects.values(), key=lambda r: r.key):
            if count >= max_keys:
                is_truncated = True
                next_continuation_token = to_str(base64.urlsafe_b64encode(s3_object.key.encode()))
                break

            key = urlparse.quote(s3_object.key) if encoding_type else s3_object.key
            # skip all keys that alphabetically come before key_marker
            if continuation_token:
                if key < decoded_continuation_token:
                    continue

            elif start_after:
                if key <= start_after:
                    continue

            # Filter for keys that start with prefix
            if prefix and not key.startswith(prefix):
                continue

            # separate keys that contain the same string between the prefix and the first occurrence of the delimiter
            if delimiter and delimiter in (key_no_prefix := key.removeprefix(prefix)):
                pre_delimiter, _, _ = key_no_prefix.partition(delimiter)
                prefix_including_delimiter = f"{prefix}{pre_delimiter}{delimiter}"

                if prefix_including_delimiter not in common_prefixes:
                    # TODO: check going over MaxKeys from CommonPrefix
                    count += 1
                    common_prefixes.add(prefix_including_delimiter)
                continue

            # TODO: add RestoreStatus if present
            object_data = Object(
                Key=key,
                ETag=s3_object.quoted_etag,
                Size=s3_object.size,
                LastModified=s3_object.last_modified,
                StorageClass=s3_object.storage_class,
            )

            if fetch_owner:
                object_data["Owner"] = s3_bucket.owner

            if s3_object.checksum_algorithm:
                object_data["ChecksumAlgorithm"] = [s3_object.checksum_algorithm]

            s3_objects.append(object_data)
            count += 1

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListObjectsV2Output(
            IsTruncated=is_truncated,
            Name=bucket,
            MaxKeys=max_keys,
            Prefix=prefix or "",
            KeyCount=count,
        )
        if s3_objects:
            response["Contents"] = s3_objects
        if encoding_type:
            response["EncodingType"] = EncodingType.url
        if delimiter:
            response["Delimiter"] = delimiter
        if common_prefixes:
            response["CommonPrefixes"] = common_prefixes
        if next_continuation_token:
            response["NextContinuationToken"] = next_continuation_token

        if continuation_token:
            response["ContinuationToken"] = continuation_token
        elif start_after:
            response["StartAfter"] = start_after

        if s3_bucket.bucket_region != "us-east-1":
            response["BucketRegion"] = s3_bucket.bucket_region

        # RequestCharged: Optional[RequestCharged]  # TODO
        return response

    def list_object_versions(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter = None,
        encoding_type: EncodingType = None,
        key_marker: KeyMarker = None,
        max_keys: MaxKeys = None,
        prefix: Prefix = None,
        version_id_marker: VersionIdMarker = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
        optional_object_attributes: OptionalObjectAttributesList = None,
    ) -> ListObjectVersionsOutput:
        if version_id_marker and not key_marker:
            raise InvalidArgument(
                "A version-id marker cannot be specified without a key marker.",
                ArgumentName="version-id-marker",
                ArgumentValue=version_id_marker,
            )

        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        common_prefixes = set()
        count = 0
        is_truncated = False
        next_key_marker = None
        next_version_id_marker = None
        max_keys = max_keys or 1000
        prefix = prefix or ""
        delimiter = delimiter or ""
        if encoding_type:
            prefix = urlparse.quote(prefix)
            delimiter = urlparse.quote(delimiter)
        version_key_marker_found = False

        object_versions: list[ObjectVersion] = []
        delete_markers: list[DeleteMarkerEntry] = []

        all_versions = s3_bucket.objects.values(with_versions=True)
        # sort by key, and last-modified-date, to get the last version first
        all_versions.sort(key=lambda r: (r.key, -r.last_modified.timestamp()))
        last_version = all_versions[-1] if all_versions else None

        for version in all_versions:
            key = urlparse.quote(version.key) if encoding_type else version.key
            # skip all keys that alphabetically come before key_marker
            if key_marker:
                if key < key_marker:
                    continue
                elif key == key_marker:
                    if not version_id_marker:
                        continue
                    # as the keys are ordered by time, once we found the key marker, we can return the next one
                    if version.version_id == version_id_marker:
                        version_key_marker_found = True
                        continue
                    elif not version_key_marker_found:
                        # as long as we have not passed the version_key_marker, skip the versions
                        continue

            # Filter for keys that start with prefix
            if prefix and not key.startswith(prefix):
                continue

            # separate keys that contain the same string between the prefix and the first occurrence of the delimiter
            if delimiter and delimiter in (key_no_prefix := key.removeprefix(prefix)):
                pre_delimiter, _, _ = key_no_prefix.partition(delimiter)
                prefix_including_delimiter = f"{prefix}{pre_delimiter}{delimiter}"

                if prefix_including_delimiter not in common_prefixes:
                    count += 1
                    common_prefixes.add(prefix_including_delimiter)
                continue

            if isinstance(version, S3DeleteMarker):
                delete_marker = DeleteMarkerEntry(
                    Key=key,
                    Owner=s3_bucket.owner,
                    VersionId=version.version_id,
                    IsLatest=version.is_current,
                    LastModified=version.last_modified,
                )
                delete_markers.append(delete_marker)
            else:
                # TODO: add RestoreStatus if present
                object_version = ObjectVersion(
                    Key=key,
                    ETag=version.quoted_etag,
                    Owner=s3_bucket.owner,  # TODO: verify reality
                    Size=version.size,
                    VersionId=version.version_id or "null",
                    LastModified=version.last_modified,
                    IsLatest=version.is_current,
                    # TODO: verify this, are other class possible?
                    # StorageClass=version.storage_class,
                    StorageClass=ObjectVersionStorageClass.STANDARD,
                )

                if version.checksum_algorithm:
                    object_version["ChecksumAlgorithm"] = [version.checksum_algorithm]

                object_versions.append(object_version)

            count += 1
            if count >= max_keys and last_version.version_id != version.version_id:
                is_truncated = True
                next_key_marker = version.key
                next_version_id_marker = version.version_id
                break

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListObjectVersionsOutput(
            IsTruncated=is_truncated,
            Name=bucket,
            MaxKeys=max_keys,
            Prefix=prefix,
            KeyMarker=key_marker or "",
            VersionIdMarker=version_id_marker or "",
        )
        if object_versions:
            response["Versions"] = object_versions
        if encoding_type:
            response["EncodingType"] = EncodingType.url
        if delete_markers:
            response["DeleteMarkers"] = delete_markers
        if delimiter:
            response["Delimiter"] = delimiter
        if common_prefixes:
            response["CommonPrefixes"] = common_prefixes
        if next_key_marker:
            response["NextKeyMarker"] = next_key_marker
        if next_version_id_marker:
            response["NextVersionIdMarker"] = next_version_id_marker

        # RequestCharged: Optional[RequestCharged]  # TODO
        return response

    @handler("GetObjectAttributes", expand=False)
    def get_object_attributes(
        self,
        context: RequestContext,
        request: GetObjectAttributesRequest,
    ) -> GetObjectAttributesOutput:
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        store, s3_bucket = self._get_cross_account_bucket(context, bucket_name)

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=request.get("VersionId"),
            http_method="GET",
        )

        object_attrs = request.get("ObjectAttributes", [])
        response = GetObjectAttributesOutput()
        if "ETag" in object_attrs:
            response["ETag"] = s3_object.etag
        if "StorageClass" in object_attrs:
            response["StorageClass"] = s3_object.storage_class
        if "ObjectSize" in object_attrs:
            response["ObjectSize"] = s3_object.size
        if "Checksum" in object_attrs and (checksum_algorithm := s3_object.checksum_algorithm):
            response["Checksum"] = {
                f"Checksum{checksum_algorithm.upper()}": s3_object.checksum_value
            }

        response["LastModified"] = s3_object.last_modified

        if s3_bucket.versioning_status:
            response["VersionId"] = s3_object.version_id

        if s3_object.parts:
            response["ObjectParts"] = GetObjectAttributesParts(TotalPartsCount=len(s3_object.parts))

        return response

    def restore_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        restore_request: RestoreRequest = None,
        request_payer: RequestPayer = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> RestoreObjectOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            http_method="GET",  # TODO: verify http method
        )
        if s3_object.storage_class not in ARCHIVES_STORAGE_CLASSES:
            raise InvalidObjectState(StorageClass=s3_object.storage_class)

        # TODO: moto was only supported "Days" parameters from RestoreRequest, and was ignoring the others
        # will only implement only the same functionality for now

        # if a request was already done and the object was available, and we're updating it, set the status code to 200
        status_code = 200 if s3_object.restore else 202
        restore_days = restore_request.get("Days")
        if not restore_days:
            LOG.debug("LocalStack does not support restore SELECT requests yet.")
            return RestoreObjectOutput()

        restore_expiration_date = add_expiration_days_to_datetime(
            datetime.datetime.utcnow(), restore_days
        )
        # TODO: add a way to transition from ongoing-request=true to false? for now it is instant
        s3_object.restore = f'ongoing-request="false", expiry-date="{restore_expiration_date}"'

        s3_notif_ctx_initiated = S3EventNotificationContext.from_request_context_native(
            context,
            s3_bucket=s3_bucket,
            s3_object=s3_object,
        )
        self._notify(context, s3_bucket=s3_bucket, s3_notif_ctx=s3_notif_ctx_initiated)
        # But because it's instant in LocalStack, we can directly send the Completed notification as well
        # We just need to copy the context so that we don't mutate the first context while it could be sent
        # And modify its event type from `ObjectRestore:Post` to `ObjectRestore:Completed`
        s3_notif_ctx_completed = copy.copy(s3_notif_ctx_initiated)
        s3_notif_ctx_completed.event_type = s3_notif_ctx_completed.event_type.replace(
            "Post", "Completed"
        )
        self._notify(context, s3_bucket=s3_bucket, s3_notif_ctx=s3_notif_ctx_completed)

        # TODO: request charged
        return RestoreObjectOutput(StatusCode=status_code)

    @handler("CreateMultipartUpload", expand=False)
    def create_multipart_upload(
        self,
        context: RequestContext,
        request: CreateMultipartUploadRequest,
    ) -> CreateMultipartUploadOutput:
        # TODO: handle missing parameters:
        #  request_payer: RequestPayer = None,
        bucket_name = request["Bucket"]
        store, s3_bucket = self._get_cross_account_bucket(context, bucket_name)

        if (storage_class := request.get("StorageClass")) is not None and (
            storage_class not in STORAGE_CLASSES or storage_class == StorageClass.OUTPOSTS
        ):
            raise InvalidStorageClass(
                "The storage class you specified is not valid", StorageClassRequested=storage_class
            )

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, s3_bucket)

        if tagging := request.get("Tagging"):
            tagging = parse_tagging_header(tagging_header=tagging)

        key = request["Key"]

        system_metadata = get_system_metadata_from_request(request)
        if not system_metadata.get("ContentType"):
            system_metadata["ContentType"] = "binary/octet-stream"

        # TODO: validate the algorithm?
        checksum_algorithm = request.get("ChecksumAlgorithm")

        encryption_parameters = get_encryption_parameters_from_request_and_bucket(
            request,
            s3_bucket,
            store,
        )
        lock_parameters = get_object_lock_parameters_from_bucket_and_request(request, s3_bucket)

        acl = get_access_control_policy_for_new_resource_request(request, owner=s3_bucket.owner)

        # validate encryption values
        s3_multipart = S3Multipart(
            key=key,
            storage_class=storage_class,
            expires=request.get("Expires"),
            user_metadata=request.get("Metadata"),
            system_metadata=system_metadata,
            checksum_algorithm=checksum_algorithm,
            encryption=encryption_parameters.encryption,
            kms_key_id=encryption_parameters.kms_key_id,
            bucket_key_enabled=encryption_parameters.bucket_key_enabled,
            lock_mode=lock_parameters.lock_mode,
            lock_legal_status=lock_parameters.lock_legal_status,
            lock_until=lock_parameters.lock_until,
            website_redirect_location=request.get("WebsiteRedirectLocation"),
            expiration=None,  # TODO, from lifecycle, or should it be updated with config?
            acl=acl,
            initiator=get_owner_for_account_id(context.account_id),
            tagging=tagging,
            owner=s3_bucket.owner,
        )

        s3_bucket.multiparts[s3_multipart.id] = s3_multipart

        response = CreateMultipartUploadOutput(
            Bucket=bucket_name, Key=key, UploadId=s3_multipart.id
        )

        if checksum_algorithm:
            response["ChecksumAlgorithm"] = checksum_algorithm

        add_encryption_to_response(response, s3_object=s3_multipart.object)

        # TODO: missing response fields we're not currently supporting
        # - AbortDate: lifecycle related,not currently supported, todo
        # - AbortRuleId: lifecycle related, not currently supported, todo
        # - RequestCharged: todo

        return response

    @handler("UploadPart", expand=False)
    def upload_part(
        self,
        context: RequestContext,
        request: UploadPartRequest,
    ) -> UploadPartOutput:
        # TODO: missing following parameters:
        #  content_length: ContentLength = None, ->validate?
        #  content_md5: ContentMD5 = None, -> validate?
        #  request_payer: RequestPayer = None,
        bucket_name = request["Bucket"]
        store, s3_bucket = self._get_cross_account_bucket(context, bucket_name)

        upload_id = request.get("UploadId")
        if not (
            s3_multipart := s3_bucket.multiparts.get(upload_id)
        ) or s3_multipart.object.key != request.get("Key"):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )
        elif (part_number := request.get("PartNumber", 0)) < 1 or part_number > 10000:
            raise InvalidArgument(
                "Part number must be an integer between 1 and 10000, inclusive",
                ArgumentName="partNumber",
                ArgumentValue=part_number,
            )

        checksum_algorithm = request.get("ChecksumAlgorithm")
        checksum_value = (
            request.get(f"Checksum{checksum_algorithm.upper()}") if checksum_algorithm else None
        )

        s3_part = S3Part(
            part_number=part_number,
            checksum_algorithm=checksum_algorithm,
            checksum_value=checksum_value,
        )
        body = request.get("Body")
        headers = context.request.headers
        is_aws_chunked = headers.get("x-amz-content-sha256", "").startswith("STREAMING-")
        # check if chunked request
        if is_aws_chunked:
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
            body = AwsChunkedDecoder(body, decoded_content_length, s3_part)

        stored_multipart = self._storage_backend.get_multipart(bucket_name, s3_multipart)
        stored_s3_part = stored_multipart.open(s3_part)
        stored_s3_part.write(body)

        if checksum_algorithm and s3_part.checksum_value != stored_s3_part.checksum:
            stored_multipart.remove_part(s3_part)
            raise InvalidRequest(
                f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
            )

        s3_multipart.parts[part_number] = s3_part

        response = UploadPartOutput(
            ETag=s3_part.quoted_etag,
        )

        add_encryption_to_response(response, s3_object=s3_multipart.object)

        if s3_part.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_part.checksum_value

        # TODO: RequestCharged: Optional[RequestCharged]
        return response

    @handler("UploadPartCopy", expand=False)
    def upload_part_copy(
        self,
        context: RequestContext,
        request: UploadPartCopyRequest,
    ) -> UploadPartCopyOutput:
        # TODO: handle following parameters:
        #  copy_source_if_match: CopySourceIfMatch = None,
        #  copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        #  copy_source_if_none_match: CopySourceIfNoneMatch = None,
        #  copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        #  request_payer: RequestPayer = None,
        dest_bucket = request["Bucket"]
        dest_key = request["Key"]
        store = self.get_store(context.account_id, context.region)
        # TODO: validate cross-account UploadPartCopy
        if not (dest_s3_bucket := store.buckets.get(dest_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=dest_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request.get("CopySource")
        )

        if not (src_s3_bucket := store.buckets.get(src_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=src_bucket)

        # if the object is a delete marker, get_object will raise NotFound if no versionId, like AWS
        try:
            src_s3_object = src_s3_bucket.get_object(key=src_key, version_id=src_version_id)
        except MethodNotAllowed:
            raise InvalidRequest(
                "The source of a copy request may not specifically refer to a delete marker by version id."
            )

        if src_s3_object.storage_class in ARCHIVES_STORAGE_CLASSES and not src_s3_object.restore:
            raise InvalidObjectState(
                "Operation is not valid for the source object's storage class",
                StorageClass=src_s3_object.storage_class,
            )

        upload_id = request.get("UploadId")
        if (
            not (s3_multipart := dest_s3_bucket.multiparts.get(upload_id))
            or s3_multipart.object.key != dest_key
        ):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        elif (part_number := request.get("PartNumber", 0)) < 1 or part_number > 10000:
            raise InvalidArgument(
                "Part number must be an integer between 1 and 10000, inclusive",
                ArgumentName="partNumber",
                ArgumentValue=part_number,
            )

        source_range = request.get("CopySourceRange")
        # TODO implement copy source IF (done in ASF provider)
        range_data = parse_copy_source_range_header(source_range, src_s3_object.size)

        s3_part = S3Part(part_number=part_number)

        stored_multipart = self._storage_backend.get_multipart(dest_bucket, s3_multipart)
        stored_multipart.copy_from_object(s3_part, src_bucket, src_s3_object, range_data)

        s3_multipart.parts[part_number] = s3_part

        # TODO: return those fields (checksum not handled currently in moto for parts)
        # ChecksumCRC32: Optional[ChecksumCRC32]
        # ChecksumCRC32C: Optional[ChecksumCRC32C]
        # ChecksumSHA1: Optional[ChecksumSHA1]
        # ChecksumSHA256: Optional[ChecksumSHA256]
        #     RequestCharged: Optional[RequestCharged]

        result = CopyPartResult(
            ETag=s3_part.quoted_etag,
            LastModified=s3_part.last_modified,
        )

        response = UploadPartCopyOutput(
            CopyPartResult=result,
        )

        if src_s3_bucket.versioning_status and src_s3_object.version_id:
            response["CopySourceVersionId"] = src_s3_object.version_id

        add_encryption_to_response(response, s3_object=s3_multipart.object)

        return response

    def complete_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        multipart_upload: CompletedMultipartUpload = None,
        checksum_crc32: ChecksumCRC32 = None,
        checksum_crc32_c: ChecksumCRC32C = None,
        checksum_sha1: ChecksumSHA1 = None,
        checksum_sha256: ChecksumSHA256 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
    ) -> CompleteMultipartUploadOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if (
            not (s3_multipart := s3_bucket.multiparts.get(upload_id))
            or s3_multipart.object.key != key
        ):
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        parts = multipart_upload.get("Parts", [])
        if not parts:
            raise InvalidRequest("You must specify at least one part")

        parts_numbers = [part.get("PartNumber") for part in parts]
        # sorted is very fast (fastest) if the list is already sorted, which should be the case
        if sorted(parts_numbers) != parts_numbers:
            raise InvalidPartOrder(
                "The list of parts was not in ascending order. Parts must be ordered by part number.",
                UploadId=upload_id,
            )

        # generate the versionId before completing, in case the bucket versioning status has changed between
        # creation and completion? AWS validate this
        version_id = generate_version_id(s3_bucket.versioning_status)
        s3_multipart.object.version_id = version_id
        s3_multipart.complete_multipart(parts)

        stored_multipart = self._storage_backend.get_multipart(bucket, s3_multipart)
        stored_multipart.complete_multipart(
            [s3_multipart.parts.get(part_number) for part_number in parts_numbers]
        )

        s3_object = s3_multipart.object

        s3_bucket.objects.set(key, s3_object)

        # remove the multipart now that it's complete
        self._storage_backend.remove_multipart(bucket, s3_multipart)
        s3_bucket.multiparts.pop(s3_multipart.id, None)

        key_id = get_unique_key_id(bucket, key, version_id)
        store.TAGS.tags.pop(key_id, None)
        if s3_multipart.tagging:
            store.TAGS.tags[key_id] = s3_multipart.tagging

        # TODO: validate if you provide wrong checksum compared to the given algorithm? should you calculate it anyway
        #  when you complete? sounds weird, not sure how that works?

        #     ChecksumCRC32: Optional[ChecksumCRC32] ??
        #     ChecksumCRC32C: Optional[ChecksumCRC32C] ??
        #     ChecksumSHA1: Optional[ChecksumSHA1] ??
        #     ChecksumSHA256: Optional[ChecksumSHA256] ??
        #     RequestCharged: Optional[RequestCharged] TODO

        response = CompleteMultipartUploadOutput(
            Bucket=bucket,
            Key=key,
            ETag=s3_object.quoted_etag,
            Location=f"{get_full_default_bucket_location(bucket)}{key}",
        )

        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        # TODO: check this?
        if s3_object.checksum_algorithm:
            response[f"Checksum{s3_object.checksum_algorithm.upper()}"] = s3_object.checksum_value

        if s3_object.expiration:
            response["Expiration"] = s3_object.expiration  # TODO: properly parse the datetime

        add_encryption_to_response(response, s3_object=s3_object)

        self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)

        return response

    def abort_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> AbortMultipartUploadOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if (
            not (s3_multipart := s3_bucket.multiparts.get(upload_id))
            or s3_multipart.object.key != key
        ):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )
        s3_bucket.multiparts.pop(upload_id, None)

        self._storage_backend.remove_multipart(bucket, s3_multipart)
        response = AbortMultipartUploadOutput()
        # TODO: requestCharged
        return response

    def list_parts(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        max_parts: MaxParts = None,
        part_number_marker: PartNumberMarker = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
    ) -> ListPartsOutput:
        # TODO: implement MaxParts
        # TODO: implements PartNumberMarker
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if (
            not (s3_multipart := s3_bucket.multiparts.get(upload_id))
            or s3_multipart.object.key != key
        ):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        #     AbortDate: Optional[AbortDate] TODO: lifecycle
        #     AbortRuleId: Optional[AbortRuleId] TODO: lifecycle
        #     RequestCharged: Optional[RequestCharged]

        count = 0
        is_truncated = False
        part_number_marker = part_number_marker or 0
        max_parts = max_parts or 1000

        parts = []
        all_parts = sorted(s3_multipart.parts.items())
        last_part_number = all_parts[-1][0] if all_parts else None
        for part_number, part in all_parts:
            if part_number <= part_number_marker:
                continue
            part_item = Part(
                ETag=part.quoted_etag,
                LastModified=part.last_modified,
                PartNumber=part_number,
                Size=part.size,
            )
            parts.append(part_item)
            count += 1

            if count >= max_parts and part.part_number != last_part_number:
                is_truncated = True
                break

        response = ListPartsOutput(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            Initiator=s3_multipart.initiator,
            Owner=s3_multipart.initiator,
            StorageClass=s3_multipart.object.storage_class,
            IsTruncated=is_truncated,
            MaxParts=max_parts,
            PartNumberMarker=0,
            NextPartNumberMarker=0,
        )
        if parts:
            response["Parts"] = parts
            last_part = parts[-1]["PartNumber"]
            response["NextPartNumberMarker"] = last_part

        if part_number_marker:
            response["PartNumberMarker"] = part_number_marker
        if s3_multipart.object.checksum_algorithm:
            response["ChecksumAlgorithm"] = s3_multipart.object.checksum_algorithm

        return response

    def list_multipart_uploads(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter = None,
        encoding_type: EncodingType = None,
        key_marker: KeyMarker = None,
        max_uploads: MaxUploads = None,
        prefix: Prefix = None,
        upload_id_marker: UploadIdMarker = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> ListMultipartUploadsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        common_prefixes = set()
        count = 0
        is_truncated = False
        max_uploads = max_uploads or 1000
        prefix = prefix or ""
        delimiter = delimiter or ""
        if encoding_type:
            prefix = urlparse.quote(prefix)
            delimiter = urlparse.quote(delimiter)
        upload_id_marker_found = False

        if key_marker and upload_id_marker:
            multipart = s3_bucket.multiparts.get(upload_id_marker)
            if multipart:
                key = (
                    urlparse.quote(multipart.object.key) if encoding_type else multipart.object.key
                )
            else:
                # set key to None so it fails if the multipart is not Found
                key = None

            if key_marker != key:
                raise InvalidArgument(
                    "Invalid uploadId marker",
                    ArgumentName="upload-id-marker",
                    ArgumentValue=upload_id_marker,
                )

        uploads = []
        # sort by key and initiated
        for multipart in sorted(
            s3_bucket.multiparts.values(), key=lambda r: (r.object.key, r.initiated.timestamp())
        ):
            if count >= max_uploads:
                is_truncated = True
                break

            key = urlparse.quote(multipart.object.key) if encoding_type else multipart.object.key
            # skip all keys that are different than key_marker
            if key_marker:
                if key < key_marker:
                    continue
                elif key == key_marker:
                    if not upload_id_marker:
                        continue
                    # as the keys are ordered by time, once we found the key marker, we can return the next one
                    if multipart.id == upload_id_marker:
                        upload_id_marker_found = True
                        continue
                    elif not upload_id_marker_found:
                        # as long as we have not passed the version_key_marker, skip the versions
                        continue

            # Filter for keys that start with prefix
            if prefix and not key.startswith(prefix):
                continue

            # separate keys that contain the same string between the prefix and the first occurrence of the delimiter
            if delimiter and delimiter in (key_no_prefix := key.removeprefix(prefix)):
                pre_delimiter, _, _ = key_no_prefix.partition(delimiter)
                prefix_including_delimiter = f"{prefix}{pre_delimiter}{delimiter}"

                if prefix_including_delimiter not in common_prefixes:
                    count += 1
                    common_prefixes.add(prefix_including_delimiter)
                continue

            multipart_upload = MultipartUpload(
                UploadId=multipart.id,
                Key=multipart.object.key,
                Initiated=multipart.initiated,
                StorageClass=multipart.object.storage_class,
                Owner=multipart.initiator,  # TODO: check the difference
                Initiator=multipart.initiator,
            )
            uploads.append(multipart_upload)

            count += 1

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListMultipartUploadsOutput(
            Bucket=bucket,
            IsTruncated=is_truncated,
            MaxUploads=max_uploads or 1000,
            KeyMarker=key_marker or "",
            UploadIdMarker=upload_id_marker or "" if key_marker else "",
            NextKeyMarker="",
            NextUploadIdMarker="",
        )
        if uploads:
            response["Uploads"] = uploads
            last_upload = uploads[-1]
            response["NextKeyMarker"] = last_upload["Key"]
            response["NextUploadIdMarker"] = last_upload["UploadId"]
        if delimiter:
            response["Delimiter"] = delimiter
        if prefix:
            response["Prefix"] = prefix
        if encoding_type:
            response["EncodingType"] = EncodingType.url
        if common_prefixes:
            response["CommonPrefixes"] = common_prefixes

        return response

    def put_bucket_versioning(
        self,
        context: RequestContext,
        bucket: BucketName,
        versioning_configuration: VersioningConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        mfa: MFA = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not (versioning_status := versioning_configuration.get("Status")):
            raise CommonServiceException(
                code="IllegalVersioningConfigurationException",
                message="The Versioning element must be specified",
            )

        if s3_bucket.object_lock_enabled:
            raise InvalidBucketState(
                "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed."
            )

        if versioning_status not in ("Enabled", "Suspended"):
            raise MalformedXML()

        if not s3_bucket.versioning_status:
            s3_bucket.objects = VersionedKeyStore.from_key_store(s3_bucket.objects)

        s3_bucket.versioning_status = versioning_status

    def get_bucket_versioning(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketVersioningOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.versioning_status:
            return GetBucketVersioningOutput()

        return GetBucketVersioningOutput(Status=s3_bucket.versioning_status)

    def get_bucket_encryption(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketEncryptionOutput:
        # AWS now encrypts bucket by default with AES256, see:
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.encryption_rule:
            return GetBucketEncryptionOutput()

        return GetBucketEncryptionOutput(
            ServerSideEncryptionConfiguration={"Rules": [s3_bucket.encryption_rule]}
        )

    def put_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        server_side_encryption_configuration: ServerSideEncryptionConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not (rules := server_side_encryption_configuration.get("Rules")):
            raise MalformedXML()

        if len(rules) != 1 or not (
            encryption := rules[0].get("ApplyServerSideEncryptionByDefault")
        ):
            raise MalformedXML()

        if not (sse_algorithm := encryption.get("SSEAlgorithm")):
            raise MalformedXML()

        if sse_algorithm not in SSE_ALGORITHMS:
            raise MalformedXML()

        if sse_algorithm != ServerSideEncryption.aws_kms and "KMSMasterKeyID" in encryption:
            raise InvalidArgument(
                "a KMSMasterKeyID is not applicable if the default sse algorithm is not aws:kms",
                ArgumentName="ApplyServerSideEncryptionByDefault",
            )
        # elif master_kms_key := encryption.get("KMSMasterKeyID"):
        # TODO: validate KMS key? not currently done in moto
        # You can pass either the KeyId or the KeyArn. If cross-account, it has to be the ARN.
        # It's always saved as the ARN in the bucket configuration.
        # kms_key_arn = get_kms_key_arn(master_kms_key, s3_bucket.bucket_account_id)
        # encryption["KMSMasterKeyID"] = master_kms_key

        s3_bucket.encryption_rule = rules[0]

    def delete_bucket_encryption(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_bucket.encryption_rule = None

    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId = None,
        skip_destination_validation: SkipValidation = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        self._verify_notification_configuration(
            notification_configuration, skip_destination_validation, context, bucket
        )
        s3_bucket.notification_configuration = notification_configuration

    def get_bucket_notification_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfiguration:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        return s3_bucket.notification_configuration or NotificationConfiguration()

    def put_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        tagging: Tagging,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if "TagSet" not in tagging:
            raise MalformedXML()

        validate_tag_set(tagging["TagSet"], type_set="bucket")

        # remove the previous tags before setting the new ones, it overwrites the whole TagSet
        store.TAGS.tags.pop(s3_bucket.bucket_arn, None)
        store.TAGS.tag_resource(s3_bucket.bucket_arn, tags=tagging["TagSet"])

    def get_bucket_tagging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketTaggingOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        tag_set = store.TAGS.list_tags_for_resource(s3_bucket.bucket_arn, root_name="Tags")["Tags"]
        if not tag_set:
            raise NoSuchTagSet(
                "The TagSet does not exist",
                BucketName=bucket,
            )

        return GetBucketTaggingOutput(TagSet=tag_set)

    def delete_bucket_tagging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        store.TAGS.tags.pop(s3_bucket.bucket_arn, None)

    def put_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        tagging: Tagging,
        version_id: ObjectVersionId = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> PutObjectTaggingOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            raise_for_delete_marker=False,  # We can tag DeleteMarker
        )

        if "TagSet" not in tagging:
            raise MalformedXML()

        validate_tag_set(tagging["TagSet"], type_set="object")

        key_id = get_unique_key_id(bucket, key, version_id)
        # remove the previous tags before setting the new ones, it overwrites the whole TagSet
        store.TAGS.tags.pop(key_id, None)
        store.TAGS.tag_resource(key_id, tags=tagging["TagSet"])
        response = PutObjectTaggingOutput()
        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)

        return response

    def get_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> GetObjectTaggingOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        try:
            s3_object = s3_bucket.get_object(
                key=key,
                version_id=version_id,
                raise_for_delete_marker=False,  # We can tag DeleteMarker
            )
        except NoSuchKey as e:
            # There a weird AWS validated bug in S3: the returned key contains the bucket name as well
            # follow AWS on this one
            e.Key = f"{bucket}/{key}"
            raise e

        tag_set = store.TAGS.list_tags_for_resource(get_unique_key_id(bucket, key, version_id))[
            "Tags"
        ]
        response = GetObjectTaggingOutput(TagSet=tag_set)
        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        return response

    def delete_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectTaggingOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            raise_for_delete_marker=False,
        )

        store.TAGS.tags.pop(get_unique_key_id(bucket, key, version_id), None)
        response = DeleteObjectTaggingOutput()
        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)

        return response

    def put_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        cors_configuration: CORSConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        validate_cors_configuration(cors_configuration)
        s3_bucket.cors_rules = cors_configuration
        self._cors_handler.invalidate_cache()

    def get_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketCorsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.cors_rules:
            raise NoSuchCORSConfiguration(
                "The CORS configuration does not exist",
                BucketName=bucket,
            )
        return GetBucketCorsOutput(CORSRules=s3_bucket.cors_rules["CORSRules"])

    def delete_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if s3_bucket.cors_rules:
            self._cors_handler.invalidate_cache()
            s3_bucket.cors_rules = None

    def get_bucket_lifecycle_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.lifecycle_rules:
            raise NoSuchLifecycleConfiguration(
                "The lifecycle configuration does not exist",
                BucketName=bucket,
            )

        return GetBucketLifecycleConfigurationOutput(Rules=s3_bucket.lifecycle_rules)

    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        checksum_algorithm: ChecksumAlgorithm = None,
        lifecycle_configuration: BucketLifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        validate_lifecycle_configuration(lifecycle_configuration)
        # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to apply them
        #  everytime we get/head an object
        # for now, we keep a cache and get it everytime we fetch an object
        s3_bucket.lifecycle_rules = lifecycle_configuration["Rules"]
        self._expiration_cache[bucket].clear()

    def delete_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_bucket.lifecycle_rules = None
        self._expiration_cache[bucket].clear()

    def put_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        analytics_configuration: AnalyticsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        validate_bucket_analytics_configuration(
            id=id, analytics_configuration=analytics_configuration
        )

        s3_bucket.analytics_configurations[id] = analytics_configuration

    def get_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketAnalyticsConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not (analytic_config := s3_bucket.analytics_configurations.get(id)):
            raise NoSuchConfiguration("The specified configuration does not exist.")

        return GetBucketAnalyticsConfigurationOutput(AnalyticsConfiguration=analytic_config)

    def list_bucket_analytics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketAnalyticsConfigurationsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        return ListBucketAnalyticsConfigurationsOutput(
            IsTruncated=False,
            AnalyticsConfigurationList=sorted(
                s3_bucket.analytics_configurations.values(),
                key=itemgetter("Id"),
            ),
        )

    def delete_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.analytics_configurations.pop(id, None):
            raise NoSuchConfiguration("The specified configuration does not exist.")

    def put_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        intelligent_tiering_configuration: IntelligentTieringConfiguration,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        validate_bucket_intelligent_tiering_configuration(id, intelligent_tiering_configuration)

        s3_bucket.intelligent_tiering_configurations[id] = intelligent_tiering_configuration

    def get_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> GetBucketIntelligentTieringConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not (itier_config := s3_bucket.intelligent_tiering_configurations.get(id)):
            raise NoSuchConfiguration("The specified configuration does not exist.")

        return GetBucketIntelligentTieringConfigurationOutput(
            IntelligentTieringConfiguration=itier_config
        )

    def delete_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.intelligent_tiering_configurations.pop(id, None):
            raise NoSuchConfiguration("The specified configuration does not exist.")

    def list_bucket_intelligent_tiering_configurations(
        self, context: RequestContext, bucket: BucketName, continuation_token: Token = None
    ) -> ListBucketIntelligentTieringConfigurationsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        return ListBucketIntelligentTieringConfigurationsOutput(
            IsTruncated=False,
            IntelligentTieringConfigurationList=sorted(
                s3_bucket.intelligent_tiering_configurations.values(),
                key=itemgetter("Id"),
            ),
        )

    def put_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        inventory_configuration: InventoryConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        validate_inventory_configuration(
            config_id=id, inventory_configuration=inventory_configuration
        )
        s3_bucket.inventory_configurations[id] = inventory_configuration

    def get_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketInventoryConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not (inv_config := s3_bucket.inventory_configurations.get(id)):
            raise NoSuchConfiguration("The specified configuration does not exist.")
        return GetBucketInventoryConfigurationOutput(InventoryConfiguration=inv_config)

    def list_bucket_inventory_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketInventoryConfigurationsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        return ListBucketInventoryConfigurationsOutput(
            IsTruncated=False,
            InventoryConfigurationList=sorted(
                s3_bucket.inventory_configurations.values(), key=itemgetter("Id")
            ),
        )

    def delete_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.inventory_configurations.pop(id, None):
            raise NoSuchConfiguration("The specified configuration does not exist.")

    def get_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketWebsiteOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.website_configuration:
            raise NoSuchWebsiteConfiguration(
                "The specified bucket does not have a website configuration",
                BucketName=bucket,
            )
        return s3_bucket.website_configuration

    def put_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        website_configuration: WebsiteConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        validate_website_configuration(website_configuration)
        s3_bucket.website_configuration = website_configuration

    def delete_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        # does not raise error if the bucket did not have a config, will simply return
        s3_bucket.website_configuration = None

    def get_object_lock_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetObjectLockConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.object_lock_enabled:
            raise ObjectLockConfigurationNotFoundError(
                "Object Lock configuration does not exist for this bucket",
                BucketName=bucket,
            )

        response = GetObjectLockConfigurationOutput(
            ObjectLockConfiguration=ObjectLockConfiguration(
                ObjectLockEnabled=ObjectLockEnabled.Enabled
            )
        )
        if s3_bucket.object_lock_default_retention:
            response["ObjectLockConfiguration"]["Rule"] = {
                "DefaultRetention": s3_bucket.object_lock_default_retention
            }

        return response

    def put_object_lock_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        object_lock_configuration: ObjectLockConfiguration = None,
        request_payer: RequestPayer = None,
        token: ObjectLockToken = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectLockConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.object_lock_enabled:
            raise InvalidBucketState(
                "Object Lock configuration cannot be enabled on existing buckets"
            )

        if (
            not object_lock_configuration
            or object_lock_configuration.get("ObjectLockEnabled") != "Enabled"
        ):
            raise MalformedXML()

        if "Rule" not in object_lock_configuration:
            s3_bucket.object_lock_default_retention = None
            return PutObjectLockConfigurationOutput()
        elif not (rule := object_lock_configuration["Rule"]) or not (
            default_retention := rule.get("DefaultRetention")
        ):
            raise MalformedXML()

        if "Mode" not in default_retention or (
            ("Days" in default_retention and "Years" in default_retention)
            or ("Days" not in default_retention and "Years" not in default_retention)
        ):
            raise MalformedXML()

        s3_bucket.object_lock_default_retention = default_retention

        return PutObjectLockConfigurationOutput()

    def get_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectLegalHoldOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.object_lock_enabled:
            raise InvalidRequest("Bucket is missing Object Lock Configuration")

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            http_method="GET",
        )
        if not s3_object.lock_legal_status:
            raise NoSuchObjectLockConfiguration(
                "The specified object does not have a ObjectLock configuration"
            )

        return GetObjectLegalHoldOutput(
            LegalHold=ObjectLockLegalHold(Status=s3_object.lock_legal_status)
        )

    def put_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        legal_hold: ObjectLockLegalHold = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectLegalHoldOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not legal_hold:
            raise MalformedXML()

        if not s3_bucket.object_lock_enabled:
            raise InvalidRequest("Bucket is missing Object Lock Configuration")

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            http_method="PUT",
        )
        # TODO: check casing
        if not (status := legal_hold.get("Status")) or status not in ("ON", "OFF"):
            raise MalformedXML()

        s3_object.lock_legal_status = status

        # TODO: return RequestCharged
        return PutObjectRetentionOutput()

    def get_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectRetentionOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.object_lock_enabled:
            raise InvalidRequest("Bucket is missing Object Lock Configuration")

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            http_method="GET",
        )
        if not s3_object.lock_mode:
            raise NoSuchObjectLockConfiguration(
                "The specified object does not have a ObjectLock configuration"
            )

        return GetObjectRetentionOutput(
            Retention=ObjectLockRetention(
                Mode=s3_object.lock_mode,
                RetainUntilDate=s3_object.lock_until,
            )
        )

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
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.object_lock_enabled:
            raise InvalidRequest("Bucket is missing Object Lock Configuration")

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
            http_method="PUT",
        )

        if retention and not validate_dict_fields(
            retention, required_fields={"Mode", "RetainUntilDate"}
        ):
            raise MalformedXML()

        if (
            not retention
            or (s3_object.lock_until and s3_object.lock_until > retention["RetainUntilDate"])
        ) and not (
            bypass_governance_retention and s3_object.lock_mode == ObjectLockMode.GOVERNANCE
        ):
            raise AccessDenied("Access Denied")

        s3_object.lock_mode = retention["Mode"] if retention else None
        s3_object.lock_until = retention["RetainUntilDate"] if retention else None

        # TODO: return RequestCharged
        return PutObjectRetentionOutput()

    def put_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        request_payment_configuration: RequestPaymentConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        # TODO: this currently only mock the operation, but its actual effect is not emulated
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        payer = request_payment_configuration.get("Payer")
        if payer not in ["Requester", "BucketOwner"]:
            raise MalformedXML()

        s3_bucket.payer = payer

    def get_bucket_request_payment(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketRequestPaymentOutput:
        # TODO: this currently only mock the operation, but its actual effect is not emulated
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        return GetBucketRequestPaymentOutput(Payer=s3_bucket.payer)

    def get_bucket_ownership_controls(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketOwnershipControlsOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.object_ownership:
            raise OwnershipControlsNotFoundError(
                "The bucket ownership controls were not found",
                BucketName=bucket,
            )

        return GetBucketOwnershipControlsOutput(
            OwnershipControls={"Rules": [{"ObjectOwnership": s3_bucket.object_ownership}]}
        )

    def put_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        ownership_controls: OwnershipControls,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        # TODO: this currently only mock the operation, but its actual effect is not emulated
        #  it for example almost forbid ACL usage when set to BucketOwnerEnforced
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not (rules := ownership_controls.get("Rules")) or len(rules) > 1:
            raise MalformedXML()

        rule = rules[0]
        if (object_ownership := rule.get("ObjectOwnership")) not in OBJECT_OWNERSHIPS:
            raise MalformedXML()

        s3_bucket.object_ownership = object_ownership

    def delete_bucket_ownership_controls(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_bucket.object_ownership = None

    def get_public_access_block(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetPublicAccessBlockOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.public_access_block:
            raise NoSuchPublicAccessBlockConfiguration(
                "The public access block configuration was not found", BucketName=bucket
            )

        return GetPublicAccessBlockOutput(
            PublicAccessBlockConfiguration=s3_bucket.public_access_block
        )

    def put_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        # TODO: this currently only mock the operation, but its actual effect is not emulated
        #  as we do not enforce ACL directly. Also, this should take the most restrictive between S3Control and the
        #  bucket configuration. See s3control
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        public_access_block_fields = {
            "BlockPublicAcls",
            "BlockPublicPolicy",
            "IgnorePublicAcls",
            "RestrictPublicBuckets",
        }
        if not validate_dict_fields(
            public_access_block_configuration,
            required_fields=set(),
            optional_fields=public_access_block_fields,
        ):
            raise MalformedXML()

        for field in public_access_block_fields:
            if public_access_block_configuration.get(field) is None:
                public_access_block_configuration[field] = False

        s3_bucket.public_access_block = public_access_block_configuration

    def delete_public_access_block(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_bucket.public_access_block = None

    def get_bucket_policy(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketPolicyOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.policy:
            raise NoSuchBucketPolicy(
                "The bucket policy does not exist",
                BucketName=bucket,
            )
        return GetBucketPolicyOutput(Policy=s3_bucket.policy)

    def put_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        policy: Policy,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not policy or policy[0] != "{":
            raise MalformedPolicy("Policies must be valid JSON and the first byte must be '{'")
        try:
            json_policy = json.loads(policy)
            if not json_policy:
                # TODO: add more validation around the policy?
                raise MalformedPolicy("Missing required field Statement")
        except ValueError:
            raise MalformedPolicy("Policies must be valid JSON and the first byte must be '{'")

        s3_bucket.policy = policy

    def delete_bucket_policy(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_bucket.policy = None

    def get_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> GetBucketAccelerateConfigurationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        response = GetBucketAccelerateConfigurationOutput()
        if s3_bucket.accelerate_status:
            response["Status"] = s3_bucket.accelerate_status

        return response

    def put_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        accelerate_configuration: AccelerateConfiguration,
        expected_bucket_owner: AccountId = None,
        checksum_algorithm: ChecksumAlgorithm = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if "." in bucket:
            raise InvalidRequest(
                "S3 Transfer Acceleration is not supported for buckets with periods (.) in their names"
            )

        if not (status := accelerate_configuration.get("Status")) or status not in (
            "Enabled",
            "Suspended",
        ):
            raise MalformedXML()

        s3_bucket.accelerate_status = status

    def put_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        bucket_logging_status: BucketLoggingStatus,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not (logging_config := bucket_logging_status.get("LoggingEnabled")):
            s3_bucket.logging = {}
            return

        # the target bucket must be in the same account
        if not (target_bucket_name := logging_config.get("TargetBucket")):
            raise MalformedXML()

        if not logging_config.get("TargetPrefix"):
            logging_config["TargetPrefix"] = ""

        # TODO: validate Grants

        if not (target_s3_bucket := store.buckets.get(target_bucket_name)):
            raise InvalidTargetBucketForLogging(
                "The target bucket for logging does not exist",
                TargetBucket=target_bucket_name,
            )

        if target_s3_bucket.bucket_region != s3_bucket.bucket_region:
            raise CrossLocationLoggingProhibitted(
                "Cross S3 location logging not allowed. ",
                TargetBucketLocation=target_s3_bucket.bucket_region,
            )

        s3_bucket.logging = logging_config

    def get_bucket_logging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLoggingOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.logging:
            return GetBucketLoggingOutput()

        return GetBucketLoggingOutput(LoggingEnabled=s3_bucket.logging)

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
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        if not s3_bucket.versioning_status == BucketVersioningStatus.Enabled:
            raise InvalidRequest(
                "Versioning must be 'Enabled' on the bucket to apply a replication configuration"
            )

        if not (rules := replication_configuration.get("Rules")):
            raise MalformedXML()

        for rule in rules:
            if "ID" not in rule:
                rule["ID"] = short_uid()

            dest_bucket_arn = rule.get("Destination", {}).get("Bucket")
            dest_bucket_name = s3_bucket_name(dest_bucket_arn)
            if (
                not (dest_s3_bucket := store.buckets.get(dest_bucket_name))
                or not dest_s3_bucket.versioning_status == BucketVersioningStatus.Enabled
            ):
                # according to AWS testing the same exception is raised if the bucket does not exist
                # or if versioning was disabled
                raise InvalidRequest("Destination bucket must have versioning enabled.")

        # TODO more validation on input
        s3_bucket.replication = replication_configuration

    def get_bucket_replication(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketReplicationOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        if not s3_bucket.replication:
            raise ReplicationConfigurationNotFoundError(
                "The replication configuration was not found",
                BucketName=bucket,
            )

        return GetBucketReplicationOutput(ReplicationConfiguration=s3_bucket.replication)

    def delete_bucket_replication(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_bucket.replication = None

    @handler("PutBucketAcl", expand=False)
    def put_bucket_acl(
        self,
        context: RequestContext,
        request: PutBucketAclRequest,
    ) -> None:
        bucket = request["Bucket"]
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)
        acp = get_access_control_policy_from_acl_request(
            request=request, owner=s3_bucket.owner, request_body=context.request.data
        )
        s3_bucket.acl = acp

    def get_bucket_acl(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketAclOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        return GetBucketAclOutput(Owner=s3_bucket.acl["Owner"], Grants=s3_bucket.acl["Grants"])

    @handler("PutObjectAcl", expand=False)
    def put_object_acl(
        self,
        context: RequestContext,
        request: PutObjectAclRequest,
    ) -> PutObjectAclOutput:
        bucket = request["Bucket"]
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_object = s3_bucket.get_object(
            key=request["Key"],
            version_id=request.get("VersionId"),
            http_method="PUT",
        )
        acp = get_access_control_policy_from_acl_request(
            request=request, owner=s3_object.owner, request_body=context.request.data
        )
        previous_acl = s3_object.acl
        s3_object.acl = acp

        if previous_acl != acp:
            self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)

        # TODO: RequestCharged
        return PutObjectAclOutput()

    def get_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectAclOutput:
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        s3_object = s3_bucket.get_object(
            key=key,
            version_id=version_id,
        )
        # TODO: RequestCharged
        return GetObjectAclOutput(Owner=s3_object.acl["Owner"], Grants=s3_object.acl["Grants"])

    def get_bucket_policy_status(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketPolicyStatusOutput:
        raise NotImplementedError

    def get_object_torrent(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectTorrentOutput:
        raise NotImplementedError

    def post_object(
        self, context: RequestContext, bucket: BucketName, body: IO[Body] = None
    ) -> PostResponse:
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html
        # TODO: signature validation is not implemented for pre-signed POST
        # policy validation is not implemented either, except expiration and mandatory fields
        # This operation is the only one using form for storing the request data. We will have to do some manual
        # parsing here, as no specs are present for this, as no client directly implements this operation.
        store, s3_bucket = self._get_cross_account_bucket(context, bucket)

        form = context.request.form
        validate_post_policy(form)

        fileobj = context.request.files["file"]
        object_key = context.request.form.get("key")
        if "${filename}" in object_key:
            object_key = object_key.replace("${filename}", fileobj.filename)

        if canned_acl := form.get("acl"):
            validate_canned_acl(canned_acl)
            acp = get_canned_acl(canned_acl, owner=s3_bucket.owner)
        else:
            acp = get_canned_acl(BucketCannedACL.private, owner=s3_bucket.owner)

        post_system_settable_headers = [
            "Cache-Control",
            "Content-Type",
            "Content-Disposition",
            "Content-Encoding",
        ]
        system_metadata = {}
        for system_metadata_field in post_system_settable_headers:
            if field_value := form.get(system_metadata_field):
                system_metadata[system_metadata_field.replace("-", "")] = field_value

        if not system_metadata.get("ContentType"):
            system_metadata["ContentType"] = "binary/octet-stream"

        user_metadata = {
            field.removeprefix("x-amz-meta-").lower(): form.get(field)
            for field in form
            if field.startswith("x-amz-meta-")
        }

        if tagging := form.get("tagging"):
            # this is weird, as it's direct XML in the form, we need to parse it direcly
            tagging = parse_post_object_tagging_xml(tagging)

        if (storage_class := form.get("x-amz-storage-class")) is not None and (
            storage_class not in STORAGE_CLASSES or storage_class == StorageClass.OUTPOSTS
        ):
            raise InvalidStorageClass(
                "The storage class you specified is not valid", StorageClassRequested=storage_class
            )

        encryption_request = {
            "ServerSideEncryption": form.get("x-amz-server-side-encryption"),
            "SSEKMSKeyId": form.get("x-amz-server-side-encryption-aws-kms-key-id"),
            "BucketKeyEnabled": form.get("x-amz-server-side-encryption-bucket-key-enabled"),
        }

        encryption_parameters = get_encryption_parameters_from_request_and_bucket(
            encryption_request,
            s3_bucket,
            store,
        )

        checksum_algorithm = form.get("x-amz-checksum-algorithm")
        checksum_value = (
            form.get(f"x-amz-checksum-{checksum_algorithm.lower()}") if checksum_algorithm else None
        )
        expires = (
            str_to_rfc_1123_datetime(expires_str) if (expires_str := form.get("Expires")) else None
        )

        version_id = generate_version_id(s3_bucket.versioning_status)

        s3_object = S3Object(
            key=object_key,
            version_id=version_id,
            storage_class=storage_class,
            expires=expires,
            user_metadata=user_metadata,
            system_metadata=system_metadata,
            checksum_algorithm=checksum_algorithm,
            checksum_value=checksum_value,
            encryption=encryption_parameters.encryption,
            kms_key_id=encryption_parameters.kms_key_id,
            bucket_key_enabled=encryption_parameters.bucket_key_enabled,
            website_redirect_location=form.get("x-amz-website-redirect-location"),
            acl=acp,
            owner=s3_bucket.owner,  # TODO: for now we only have one owner, but it can depends on Bucket settings
        )

        s3_stored_object = self._storage_backend.open(bucket, s3_object)
        s3_stored_object.write(fileobj.stream)

        if checksum_algorithm and s3_object.checksum_value != s3_stored_object.checksum:
            self._storage_backend.remove(bucket, s3_object)
            raise InvalidRequest(
                f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
            )

        s3_bucket.objects.set(object_key, s3_object)

        # in case we are overriding an object, delete the tags entry
        key_id = get_unique_key_id(bucket, object_key, version_id)
        store.TAGS.tags.pop(key_id, None)
        if tagging:
            store.TAGS.tags[key_id] = tagging

        response = PostResponse()
        # hacky way to set the etag in the headers as well: two locations for one value
        response["ETagHeader"] = s3_object.quoted_etag

        if redirect := form.get("success_action_redirect"):
            # we need to create the redirect, as the parser could not return the moto-calculated one
            try:
                redirect = create_redirect_for_post_request(
                    base_redirect=redirect,
                    bucket=bucket,
                    object_key=object_key,
                    etag=s3_object.quoted_etag,
                )
                response["LocationHeader"] = redirect
                response["StatusCode"] = 303
            except ValueError:
                # If S3 cannot interpret the URL, it acts as if the field is not present.
                response["StatusCode"] = form.get("success_action_status", 204)

        elif status_code := form.get("success_action_status"):
            response["StatusCode"] = status_code
        else:
            response["StatusCode"] = 204

        response["LocationHeader"] = response.get(
            "LocationHeader", f"{get_full_default_bucket_location(bucket)}{object_key}"
        )

        if s3_bucket.versioning_status == "Enabled":
            response["VersionId"] = s3_object.version_id

        if s3_object.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_object.checksum_value

        if s3_bucket.lifecycle_rules:
            if expiration_header := self._get_expiration_header(
                s3_bucket.lifecycle_rules,
                bucket,
                s3_object,
                store.TAGS.tags.get(key_id, {}),
            ):
                # TODO: we either apply the lifecycle to existing objects when we set the new rules, or we need to
                #  apply them everytime we get/head an object
                response["Expiration"] = expiration_header

        add_encryption_to_response(response, s3_object=s3_object)

        self._notify(context, s3_bucket=s3_bucket, s3_object=s3_object)

        if response["StatusCode"] == "201":
            # if the StatusCode is 201, S3 returns an XML body with additional information
            response["ETag"] = s3_object.quoted_etag
            response["Bucket"] = bucket
            response["Key"] = object_key
            response["Location"] = response["LocationHeader"]

        return response


def generate_version_id(bucket_versioning_status: str) -> str | None:
    if not bucket_versioning_status:
        return None
    # TODO: check VersionID format, could it be base64 urlsafe encoded?
    return token_urlsafe(16) if bucket_versioning_status.lower() == "enabled" else "null"


def add_encryption_to_response(response: dict, s3_object: S3Object):
    if encryption := s3_object.encryption:
        response["ServerSideEncryption"] = encryption
        if encryption == ServerSideEncryption.aws_kms:
            response["SSEKMSKeyId"] = s3_object.kms_key_id
            if s3_object.bucket_key_enabled:
                response["BucketKeyEnabled"] = s3_object.bucket_key_enabled


def get_encryption_parameters_from_request_and_bucket(
    request: PutObjectRequest | CopyObjectRequest | CreateMultipartUploadRequest,
    s3_bucket: S3Bucket,
    store: S3Store,
) -> EncryptionParameters:
    encryption = request.get("ServerSideEncryption")
    kms_key_id = request.get("SSEKMSKeyId")
    bucket_key_enabled = request.get("BucketKeyEnabled")
    if s3_bucket.encryption_rule:
        bucket_key_enabled = bucket_key_enabled or s3_bucket.encryption_rule.get("BucketKeyEnabled")
        encryption = (
            encryption
            or s3_bucket.encryption_rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        )
        if encryption == ServerSideEncryption.aws_kms:
            key_id = kms_key_id or s3_bucket.encryption_rule[
                "ApplyServerSideEncryptionByDefault"
            ].get("KMSMasterKeyID")
            kms_key_id = get_kms_key_arn(key_id, s3_bucket.bucket_account_id)
            if not kms_key_id:
                # if not key is provided, AWS will use an AWS managed KMS key
                # create it if it doesn't already exist, and save it in the store per region
                if not store.aws_managed_kms_key_id:
                    managed_kms_key_id = create_s3_kms_managed_key_for_region(
                        s3_bucket.bucket_region
                    )
                    store.aws_managed_kms_key_id = managed_kms_key_id

                kms_key_id = store.aws_managed_kms_key_id

    return EncryptionParameters(encryption, kms_key_id, bucket_key_enabled)


def get_object_lock_parameters_from_bucket_and_request(
    request: PutObjectRequest | CopyObjectRequest | CreateMultipartUploadRequest,
    s3_bucket: S3Bucket,
):
    # TODO: also validate here?
    lock_mode = request.get("ObjectLockMode")
    lock_legal_status = request.get("ObjectLockLegalHoldStatus")
    lock_until = request.get("ObjectLockRetainUntilDate")

    if default_retention := s3_bucket.object_lock_default_retention:
        lock_mode = lock_mode or default_retention.get("Mode")
        if lock_mode and not lock_until:
            lock_until = get_retention_from_now(
                days=default_retention.get("Days"),
                years=default_retention.get("Years"),
            )

    return ObjectLockParameters(lock_until, lock_legal_status, lock_mode)


def get_part_range(s3_object: S3Object, part_number: PartNumber) -> ObjectRange:
    """
    Calculate the range value from a part Number for an S3 Object
    :param s3_object: S3Object
    :param part_number: the wanted part from the S3Object
    :return: an ObjectRange used to return only a slice of an Object
    """
    if not s3_object.parts:
        if part_number > 1:
            raise InvalidPartNumber(
                "The requested partnumber is not satisfiable",
                PartNumberRequested=part_number,
                ActualPartCount=1,
            )
        return ObjectRange(
            begin=0,
            end=s3_object.size - 1,
            content_length=s3_object.size,
            content_range=f"bytes 0-{s3_object.size - 1}/{s3_object.size}",
        )
    elif not (part_data := s3_object.parts.get(part_number)):
        raise InvalidPartNumber(
            "The requested partnumber is not satisfiable",
            PartNumberRequested=part_number,
            ActualPartCount=len(s3_object.parts),
        )

    begin, part_length = part_data
    end = begin + part_length - 1
    return ObjectRange(
        begin=begin,
        end=end,
        content_length=part_length,
        content_range=f"bytes {begin}-{end}/{s3_object.size}",
    )


def get_acl_headers_from_request(
    request: Union[
        PutObjectRequest,
        CreateMultipartUploadRequest,
        CopyObjectRequest,
        CreateBucketRequest,
        PutBucketAclRequest,
        PutObjectAclRequest,
    ]
) -> list[tuple[str, str]]:
    permission_keys = [
        "GrantFullControl",
        "GrantRead",
        "GrantReadACP",
        "GrantWrite",
        "GrantWriteACP",
    ]
    acl_headers = [
        (permission, grant_header)
        for permission in permission_keys
        if (grant_header := request.get(permission))
    ]
    return acl_headers


def get_access_control_policy_from_acl_request(
    request: Union[PutBucketAclRequest, PutObjectAclRequest],
    owner: Owner,
    request_body: bytes,
) -> AccessControlPolicy:
    canned_acl = request.get("ACL")
    acl_headers = get_acl_headers_from_request(request)

    # FIXME: this is very dirty, but the parser does not differentiate between an empty body and an empty XML node
    # errors are different depending on that data, so we need to access the context. Modifying the parser for this
    # use case seems dangerous
    is_acp_in_body = request_body

    if not (canned_acl or acl_headers or is_acp_in_body):
        raise MissingSecurityHeader(
            "Your request was missing a required header", MissingHeaderName="x-amz-acl"
        )

    elif canned_acl and acl_headers:
        raise InvalidRequest("Specifying both Canned ACLs and Header Grants is not allowed")

    elif (canned_acl or acl_headers) and is_acp_in_body:
        raise UnexpectedContent("This request does not support content")

    if canned_acl:
        validate_canned_acl(canned_acl)
        acp = get_canned_acl(canned_acl, owner=owner)

    elif acl_headers:
        grants = []
        for permission, grantees_values in acl_headers:
            permission = get_permission_from_header(permission)
            partial_grants = parse_grants_in_headers(permission, grantees_values)
            grants.extend(partial_grants)

        acp = AccessControlPolicy(Owner=owner, Grants=grants)
    else:
        acp = request.get("AccessControlPolicy")
        validate_acl_acp(acp)
        if (
            owner.get("DisplayName")
            and acp["Grants"]
            and "DisplayName" not in acp["Grants"][0]["Grantee"]
        ):
            acp["Grants"][0]["Grantee"]["DisplayName"] = owner["DisplayName"]

    return acp


def get_access_control_policy_for_new_resource_request(
    request: Union[
        PutObjectRequest, CreateMultipartUploadRequest, CopyObjectRequest, CreateBucketRequest
    ],
    owner: Owner,
) -> AccessControlPolicy:
    # TODO: this is basic ACL, not taking into account Bucket settings. Revisit once we really implement ACLs.
    canned_acl = request.get("ACL")
    acl_headers = get_acl_headers_from_request(request)

    if not (canned_acl or acl_headers):
        return get_canned_acl(BucketCannedACL.private, owner=owner)

    elif canned_acl and acl_headers:
        raise InvalidRequest("Specifying both Canned ACLs and Header Grants is not allowed")

    if canned_acl:
        validate_canned_acl(canned_acl)
        return get_canned_acl(canned_acl, owner=owner)

    grants = []
    for permission, grantees_values in acl_headers:
        permission = get_permission_from_header(permission)
        partial_grants = parse_grants_in_headers(permission, grantees_values)
        grants.extend(partial_grants)

    return AccessControlPolicy(Owner=owner, Grants=grants)
