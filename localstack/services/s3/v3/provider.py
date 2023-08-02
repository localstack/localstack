import base64
import copy
import datetime
import logging
from secrets import token_urlsafe

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    MFA,
    AbortMultipartUploadOutput,
    AccountId,
    Bucket,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketName,
    BucketNotEmpty,
    BypassGovernanceRetention,
    ChecksumAlgorithm,
    ChecksumCRC32,
    ChecksumCRC32C,
    ChecksumSHA1,
    ChecksumSHA256,
    CommonPrefix,
    CompletedMultipartUpload,
    CompleteMultipartUploadOutput,
    ContentMD5,
    CopyObjectOutput,
    CopyObjectRequest,
    CopyObjectResult,
    CopyPartResult,
    CreateBucketOutput,
    CreateBucketRequest,
    CreateMultipartUploadOutput,
    CreateMultipartUploadRequest,
    Delete,
    DeletedObject,
    DeleteMarkerEntry,
    DeleteObjectOutput,
    DeleteObjectsOutput,
    DeleteObjectTaggingOutput,
    Delimiter,
    EncodingType,
    Error,
    FetchOwner,
    GetBucketEncryptionOutput,
    GetBucketLocationOutput,
    GetBucketTaggingOutput,
    GetBucketVersioningOutput,
    GetObjectAttributesOutput,
    GetObjectAttributesParts,
    GetObjectAttributesRequest,
    GetObjectOutput,
    GetObjectRequest,
    GetObjectTaggingOutput,
    HeadBucketOutput,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidArgument,
    InvalidBucketName,
    InvalidObjectState,
    InvalidPartOrder,
    InvalidStorageClass,
    KeyMarker,
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
    MultipartUpload,
    MultipartUploadId,
    NoSuchBucket,
    NoSuchKey,
    NoSuchTagSet,
    NoSuchUpload,
    NotificationConfiguration,
    Object,
    ObjectIdentifier,
    ObjectKey,
    ObjectVersion,
    ObjectVersionId,
    ObjectVersionStorageClass,
    OptionalObjectAttributesList,
    Part,
    PartNumberMarker,
    Prefix,
    PutObjectOutput,
    PutObjectRequest,
    PutObjectTaggingOutput,
    RequestPayer,
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
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.codec import AwsChunkedDecoder
from localstack.services.s3.constants import ARCHIVES_STORAGE_CLASSES, DEFAULT_BUCKET_ENCRYPTION
from localstack.services.s3.exceptions import (
    InvalidLocationConstraint,
    InvalidRequest,
    MalformedXML,
)
from localstack.services.s3.notifications import NotificationDispatcher, S3EventNotificationContext
from localstack.services.s3.utils import (
    add_expiration_days_to_datetime,
    create_s3_kms_managed_key_for_region,
    extract_bucket_key_version_id_from_copy_source,
    get_class_attrs_from_spec_class,
    get_full_default_bucket_location,
    get_kms_key_arn,
    get_owner_for_account_id,
    get_system_metadata_from_request,
    get_unique_key_id,
    is_bucket_name_valid,
    parse_range_header,
    parse_tagging_header,
    validate_kms_key_id,
    validate_tag_set,
)
from localstack.services.s3.v3.models import (
    EncryptionParameters,
    S3Bucket,
    S3DeleteMarker,
    S3Multipart,
    S3Object,
    S3Part,
    S3Store,
    VersionedKeyStore,
    s3_stores,
)
from localstack.services.s3.v3.storage.core import LimitedIterableStream
from localstack.services.s3.v3.storage.ephemeral import EphemeralS3ObjectStore
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)

STORAGE_CLASSES = get_class_attrs_from_spec_class(StorageClass)
SSE_ALGORITHMS = get_class_attrs_from_spec_class(ServerSideEncryption)

# TODO: pre-signed URLS -> REMAP parameters from querystring to headers???
#  create a handler which handle pre-signed and remap before parsing the request!


class S3Provider(S3Api, ServiceLifecycleHook):
    def __init__(self) -> None:
        super().__init__()
        self._storage_backend = EphemeralS3ObjectStore()
        self._notification_dispatcher = NotificationDispatcher()

    def on_before_stop(self):
        self._notification_dispatcher.shutdown()

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

        s3_bucket = S3Bucket(
            name=bucket_name,
            account_id=context.account_id,
            bucket_region=bucket_region,
            acl=None,  # TODO: validate ACL first, create utils for validating and consolidating
            object_ownership=request.get("ObjectOwnership"),
            object_lock_enabled_for_bucket=request.get("ObjectLockEnabledForBucket"),
        )
        store.buckets[bucket_name] = s3_bucket
        store.global_bucket_map[bucket_name] = s3_bucket.bucket_account_id

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        # TODO: still need to handle following parameters:
        #  acl: ObjectCannedACL = None,
        #  grant_full_control: GrantFullControl = None,
        #  grant_read: GrantRead = None,
        #  grant_read_acp: GrantReadACP = None,
        #  grant_write_acp: GrantWriteACP = None,
        #  -
        #  request_payer: RequestPayer = None,
        #  object_lock_mode: ObjectLockMode = None,
        #  object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        #  object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        if (
            storage_class := request.get("StorageClass")
        ) is not None and storage_class not in STORAGE_CLASSES:
            raise InvalidStorageClass(
                "The storage class you specified is not valid", StorageClassRequested=storage_class
            )

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, s3_bucket)

        key = request["Key"]

        system_metadata = get_system_metadata_from_request(request)
        if not system_metadata.get("ContentType"):
            system_metadata["ContentType"] = "binary/octet-stream"

        # TODO: get all default from bucket once it is implemented
        # validate encryption values

        body = request.get("Body")
        # check if chunked request
        headers = context.request.headers
        is_aws_chunked = headers.get("x-amz-content-sha256", "").startswith("STREAMING-")
        if is_aws_chunked:
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
            body = AwsChunkedDecoder(body, decoded_content_length)

        # TODO check if key already exist, and if it is locked with LegalHold? so we don't override it if protected

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
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            website_redirect_location=request.get("WebsiteRedirectLocation"),
            expiration=None,  # TODO, from lifecycle, or should it be updated with config?
            acl=None,
        )

        s3_stored_object = self._storage_backend.open(bucket_name, s3_object)
        s3_stored_object.write(body)

        if checksum_algorithm and s3_object.checksum_value != s3_stored_object.checksum():
            self._storage_backend.remove(bucket_name, s3_object)
            raise InvalidRequest(
                f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
            )

        s3_bucket.objects.set(key, s3_object)

        # in case we are overriding an object, delete the tags entry
        key_id = get_unique_key_id(bucket_name, key, version_id)
        store.TAGS.tags.pop(key_id, None)
        if tagging_header := request.get("Tagging"):
            tagging = parse_tagging_header(tagging_header)
            store.TAGS.tags[key_id] = tagging

        # TODO: returned fields
        # RequestCharged: Optional[RequestCharged]  # TODO
        response = PutObjectOutput(
            ETag=s3_object.quoted_etag,
        )
        if s3_bucket.versioning_status == "Enabled":
            response["VersionId"] = s3_object.version_id

        if s3_object.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_object.checksum_value

        if s3_object.expiration:
            response["Expiration"] = s3_object.expiration  # TODO: properly parse the datetime

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
        #  if_match: IfMatch = None,
        #  if_modified_since: IfModifiedSince = None,
        #  if_none_match: IfNoneMatch = None,
        #  if_unmodified_since: IfUnmodifiedSince = None,
        #  response_cache_control: ResponseCacheControl = None,
        #  response_content_disposition: ResponseContentDisposition = None,
        #  response_content_encoding: ResponseContentEncoding = None,
        #  response_content_language: ResponseContentLanguage = None,
        #  response_content_type: ResponseContentType = None,
        #  response_expires: ResponseExpires = None,
        #  request_payer: RequestPayer = None,
        #  part_number: PartNumber = None,
        #  expected_bucket_owner: AccountId = None,

        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        version_id = request.get("VersionId")
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        # TODO implement PartNumber once multipart is done (being able to select only a Part)

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=version_id,
            http_method="GET",
        )

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

        if range_header := request.get("Range"):
            range_data = parse_range_header(range_header, s3_object.size)
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

        # TODO: missing returned fields
        #     Expiration: Optional[Expiration]
        #     RequestCharged: Optional[RequestCharged]
        #     ReplicationStatus: Optional[ReplicationStatus]
        #     ObjectLockMode: Optional[ObjectLockMode]
        #     ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
        #     ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]

        return response

    @handler("HeadObject", expand=False)
    def head_object(
        self,
        context: RequestContext,
        request: HeadObjectRequest,
    ) -> HeadObjectOutput:
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        # TODO implement PartNumber, don't know about part number + version id?
        #  if_match: IfMatch = None,
        #  if_modified_since: IfModifiedSince = None,
        #  if_none_match: IfNoneMatch = None,
        #  if_unmodified_since: IfUnmodifiedSince = None,

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=request.get("VersionId"),
            http_method="HEAD",
        )

        response = HeadObjectOutput(
            AcceptRanges="bytes",
            **s3_object.get_system_metadata_fields(),
        )
        if s3_object.user_metadata:
            response["Metadata"] = s3_object.user_metadata

        # TODO implements if_match if_modified_since if_none_match if_unmodified_since
        if checksum_algorithm := s3_object.checksum_algorithm:
            if (request.get("ChecksumMode") or "").upper() == "ENABLED":
                response[f"Checksum{checksum_algorithm.upper()}"] = checksum  # noqa

        if range_header := request.get("Range"):
            range_data = parse_range_header(range_header, s3_object.size)
            response["ContentLength"] = range_data.content_length

        if s3_object.parts:
            response["PartsCount"] = len(s3_object.parts)

        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        if s3_object.website_redirect_location:
            response["WebsiteRedirectLocation"] = s3_object.website_redirect_location

        if s3_object.restore:
            response["Restore"] = s3_object.restore

        add_encryption_to_response(response, s3_object=s3_object)

        # TODO: missing return fields:
        # Expiration: Optional[Expiration]
        # ArchiveStatus: Optional[ArchiveStatus]

        # RequestCharged: Optional[RequestCharged]
        # ReplicationStatus: Optional[ReplicationStatus]
        # ObjectLockMode: Optional[ObjectLockMode]
        # ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
        # ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]

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
        # TODO: implement bypass_governance_retention, it is done in moto
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
            # TODO: verify with Suspended bucket? does it override last version or still append?? big question
            #  I think it puts a delete marker with a `null` VersionId, which deletes the object under
            s3_bucket.objects.set(key, delete_marker)
            # TODO: make a proper difference between DeleteMarker and S3Object, not done yet
            #  s3:ObjectRemoved:DeleteMarkerCreated
            self._notify(context, s3_bucket=s3_bucket, s3_object=delete_marker)

            return DeleteObjectOutput(VersionId=delete_marker.version_id, DeleteMarker=True)

        if key not in s3_bucket.objects:
            return DeleteObjectOutput()

        if not (found_object := s3_bucket.objects.pop(object_key=key, version_id=version_id)):
            raise InvalidArgument(
                "Invalid version id specified",
                ArgumentName="versionId",
                ArgumentValue=version_id,
            )

        response = DeleteObjectOutput(VersionId=found_object.version_id)

        if isinstance(found_object, S3DeleteMarker):
            response["DeleteMarker"] = True
        else:
            self._storage_backend.remove(bucket, found_object)
            self._notify(context, s3_bucket=s3_bucket, s3_object=found_object)
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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        objects: list[ObjectIdentifier] = delete.get("Objects")
        if not objects:
            raise MalformedXML()

        # TODO: max 1000 delete at once? test against AWS?
        # TODO: implement ByPassGovernance
        # TODO: implement Locking error

        quiet = delete.get("Quiet", False)
        deleted = []
        errors = []

        to_remove = []
        for to_delete_object in objects:
            # TODO: beware of key encoding (XML?)
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
                found_object := s3_bucket.objects.pop(object_key=object_key, version_id=version_id)
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
        # TODO: handle those parameters next:
        # acl: ObjectCannedACL = None,
        # grant_full_control: GrantFullControl = None,
        # grant_read: GrantRead = None,
        # grant_read_acp: GrantReadACP = None,
        # grant_write_acp: GrantWriteACP = None,
        #
        # copy_source_if_match: CopySourceIfMatch = None,
        # copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        # copy_source_if_none_match: CopySourceIfNoneMatch = None,
        # copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        #
        # request_payer: RequestPayer = None,
        # object_lock_mode: ObjectLockMode = None,
        # object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        # object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        dest_bucket = request["Bucket"]
        dest_key = request["Key"]
        store = self.get_store(context.account_id, context.region)
        if not (dest_s3_bucket := store.buckets.get(dest_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=dest_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request.get("CopySource")
        )

        if not (src_s3_bucket := store.buckets.get(src_bucket)):
            # TODO: validate this
            raise NoSuchBucket("The specified bucket does not exist", BucketName=src_bucket)

        # validate method not allowed?
        # if the object is a delete marker, get_object will raise, like AWS
        src_s3_object = src_s3_bucket.get_object(key=src_key, version_id=src_version_id)

        # TODO: validate StorageClass for ARCHIVES one
        if src_s3_object.storage_class in ARCHIVES_STORAGE_CLASSES:
            raise

        # TODO validate order of validation
        storage_class = request.get("StorageClass")
        server_side_encryption = request.get("ServerSideEncryption")
        metadata_directive = request.get("MetadataDirective")
        website_redirect_location = request.get("WebsiteRedirectLocation")
        # we need to check for identity of the object, to see if the default one has been changed
        is_default_encryption = dest_s3_bucket.encryption_rule is DEFAULT_BUCKET_ENCRYPTION
        if src_key == dest_key and not any(
            (
                storage_class,
                server_side_encryption,
                metadata_directive == "REPLACE",
                website_redirect_location,
                dest_s3_bucket.encryption_rule
                and not is_default_encryption,  # S3 will allow copy in place if the bucket has encryption configured
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

        s3_object = S3Object(
            key=dest_key,
            etag=src_s3_object.etag,
            size=src_s3_object.size,
            version_id=dest_version_id,
            storage_class=storage_class,
            expires=request.get("Expires"),
            user_metadata=user_metadata,
            system_metadata=system_metadata,
            checksum_algorithm=request.get("ChecksumAlgorithm") or src_s3_object.checksum_algorithm,
            encryption=encryption_parameters.encryption,
            kms_key_id=encryption_parameters.kms_key_id,
            bucket_key_enabled=encryption_parameters.bucket_key_enabled,
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            website_redirect_location=website_redirect_location,
            expiration=None,  # TODO, from lifecycle
            acl=None,
        )

        s3_stored_object = self._storage_backend.copy(
            src_bucket=src_bucket,
            src_object=src_s3_object,
            dest_bucket=dest_bucket,
            dest_object=s3_object,
        )
        s3_object.checksum_value = s3_stored_object.checksum() or src_s3_object.checksum_value

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

        if src_version_id:
            response["CopySourceVersionId"] = src_version_id

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        # TODO: URL encode keys (is it done already in serializer?)
        common_prefixes = set()
        count = 0
        is_truncated = False
        next_key_marker = None
        max_keys = max_keys or 1000
        prefix = prefix or ""

        s3_objects: list[Object] = []

        all_objects = s3_bucket.objects.values()
        # sort by key
        all_objects.sort(key=lambda r: r.key)

        for s3_object in all_objects:
            key = s3_object.key
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
                Key=s3_object.key,
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
            if count >= max_keys:
                is_truncated = True
                next_key_marker = s3_object.key
                break

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListObjectsOutput(
            IsTruncated=is_truncated,
            Name=bucket,
            MaxKeys=max_keys,
            EncodingType=EncodingType.url,
            Prefix=prefix or "",
            Marker=marker or "",
        )
        if s3_objects:
            response["Contents"] = s3_objects
        if delimiter:
            response["Delimiter"] = delimiter
        if common_prefixes:
            response["CommonPrefixes"] = common_prefixes
        if delimiter and next_key_marker:
            response["NextMarker"] = next_key_marker

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        if continuation_token and continuation_token == "":
            raise InvalidArgument("The continuation token provided is incorrect")

        # TODO: URL encode keys (is it done already in serializer?)
        common_prefixes = set()
        count = 0
        is_truncated = False
        next_continuation_token = None
        max_keys = max_keys or 1000
        prefix = prefix or ""
        decoded_continuation_token = (
            to_str(base64.urlsafe_b64decode(continuation_token.encode()))
            if continuation_token
            else None
        )

        s3_objects: list[Object] = []

        all_objects = s3_bucket.objects.values()
        # sort by key
        all_objects.sort(key=lambda r: r.key)

        for s3_object in all_objects:
            key = s3_object.key
            # skip all keys that alphabetically come before key_marker
            # TODO: what if there's StartAfter AND ContinuationToken
            if continuation_token:
                if key < decoded_continuation_token:
                    continue

            if start_after:
                if key < start_after:
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

            count += 1
            if count > max_keys:
                is_truncated = True
                next_continuation_token = to_str(base64.urlsafe_b64encode(s3_object.key.encode()))
                break

            # TODO: add RestoreStatus if present
            object_data = Object(
                Key=s3_object.key,
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

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListObjectsV2Output(
            IsTruncated=is_truncated,
            Name=bucket,
            MaxKeys=max_keys,
            EncodingType=EncodingType.url,
            Prefix=prefix or "",
            KeyCount=count,
        )
        if s3_objects:
            response["Contents"] = s3_objects
        if delimiter:
            response["Delimiter"] = delimiter
        if common_prefixes:
            response["CommonPrefixes"] = common_prefixes
        if next_continuation_token:
            response["NextContinuationToken"] = next_continuation_token
        if continuation_token:
            response["ContinuationToken"] = continuation_token
        if start_after:
            response["StartAfter"] = start_after

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        # TODO: URL encode keys (is it done already in serializer?)
        common_prefixes = set()
        count = 0
        is_truncated = False
        next_key_marker = None
        next_version_id_marker = None
        max_keys = max_keys or 1000
        prefix = prefix or ""

        object_versions: list[ObjectVersion] = []
        delete_markers: list[DeleteMarkerEntry] = []

        all_versions = s3_bucket.objects.values(with_versions=True)
        # sort by key, and last-modified-date, to get the last version first
        all_versions.sort(key=lambda r: (r.key, -r.last_modified.timestamp()))

        for version in all_versions:
            key = version.key
            # skip all keys that alphabetically come before key_marker
            if key_marker:
                if key < key_marker:
                    continue
                elif key == key_marker:
                    # if we're at the key_marker, skip versions that are before version_id_marker
                    if version_id_marker and version.version_id < version_id_marker:
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

            count += 1
            if count > max_keys:
                is_truncated = True
                next_key_marker = version.key
                next_version_id_marker = version.version_id
                break

            if isinstance(version, S3DeleteMarker):
                delete_marker = DeleteMarkerEntry(
                    Key=version.key,
                    Owner=s3_bucket.owner,
                    VersionId=version.version_id,
                    IsLatest=version.is_current,
                    LastModified=version.last_modified,
                )
                delete_markers.append(delete_marker)
                continue

            # TODO: add RestoreStatus if present
            object_version = ObjectVersion(
                Key=version.key,
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

        common_prefixes = [CommonPrefix(Prefix=prefix) for prefix in sorted(common_prefixes)]

        response = ListObjectVersionsOutput(
            IsTruncated=is_truncated,
            Name=bucket,
            MaxKeys=max_keys,
            EncodingType=EncodingType.url,
            Prefix=prefix,
            KeyMarker=key_marker or "",
            VersionIdMarker=version_id_marker or "",
        )
        if object_versions:
            response["Versions"] = object_versions
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
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

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
            response["Checksum"] = {  # noqa
                f"Checksum{checksum_algorithm.upper()}": s3_object.checksum_value
            }

        response["LastModified"] = s3_object.last_modified

        if s3_bucket.versioning_status:
            response["VersionId"] = s3_object.version_id

        # TODO implement PartNumber test once multipart is done
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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        #  acl: ObjectCannedACL = None,
        #  grant_full_control: GrantFullControl = None,
        #  grant_read: GrantRead = None,
        #  grant_read_acp: GrantReadACP = None,
        #  grant_write_acp: GrantWriteACP = None,
        #  request_payer: RequestPayer = None,
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        if (
            storage_class := request.get("StorageClass")
        ) is not None and storage_class not in STORAGE_CLASSES:
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

        # TODO: get all default from bucket, maybe extract logic

        # TODO: consolidate ACL into one, and validate it

        # TODO: validate the algorithm?
        checksum_algorithm = request.get("ChecksumAlgorithm")

        encryption_parameters = get_encryption_parameters_from_request_and_bucket(
            request,
            s3_bucket,
            store,
        )

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
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            website_redirect_location=request.get("WebsiteRedirectLocation"),
            expiration=None,  # TODO, from lifecycle, or should it be updated with config?
            acl=None,
            initiator=get_owner_for_account_id(context.account_id),
            tagging=tagging,
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
        # - ChecksumAlgorithm: not currently supported, todo

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
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        upload_id = request.get("UploadId")
        if not (s3_multipart := s3_bucket.multiparts.get(upload_id)):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        # TODO: validate key?
        if s3_multipart.object.key != request.get("Key"):
            pass

        part_number = request.get("PartNumber")
        # TODO: validate PartNumber
        # if part_number > 10000:
        # raise InvalidMaxPartNumberArgument(part_number)

        body = request.get("Body")
        headers = context.request.headers
        is_aws_chunked = headers.get("x-amz-content-sha256", "").startswith("STREAMING-")
        # check if chunked request
        if is_aws_chunked:
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
            body = AwsChunkedDecoder(body, decoded_content_length)

        checksum_algorithm = request.get("ChecksumAlgorithm")
        checksum_value = (
            request.get(f"Checksum{checksum_algorithm.upper()}") if checksum_algorithm else None
        )

        s3_part = S3Part(
            part_number=part_number,
            checksum_algorithm=checksum_algorithm,
            checksum_value=checksum_value,
        )

        stored_multipart = self._storage_backend.get_multipart(bucket_name, s3_multipart)
        stored_s3_part = stored_multipart.open(s3_part)
        stored_s3_part.write(body)

        if checksum_algorithm and s3_part.checksum_value != stored_s3_part.checksum():
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
        dest_key = request["Bucket"]
        store = self.get_store(context.account_id, context.region)
        if not (dest_s3_bucket := store.buckets.get(dest_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=dest_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request.get("CopySource")
        )

        if not (src_s3_bucket := store.buckets.get(src_bucket)):
            # TODO: validate this
            raise NoSuchBucket("The specified bucket does not exist", BucketName=src_bucket)

        # validate method not allowed?
        src_s3_object = src_s3_bucket.get_object(key=src_key, version_id=src_version_id)
        # TODO: validate StorageClass for ARCHIVES one
        if src_s3_object.storage_class in ARCHIVES_STORAGE_CLASSES:
            pass

        upload_id = request.get("UploadId")
        if not (s3_multipart := dest_s3_bucket.multiparts.get(upload_id)):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        # TODO: validate key?
        if s3_multipart.object.key != dest_key:
            pass

        part_number = request.get("PartNumber")
        # TODO: validate PartNumber
        # if part_number > 10000:
        # raise InvalidMaxPartNumberArgument(part_number)

        source_range = request.get("CopySourceRange")
        # TODO implement copy source IF (done in ASF provider)
        range_data = parse_range_header(source_range, src_s3_object.size)

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

        if src_version_id:
            response["CopySourceVersionId"] = src_version_id

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

        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        if not (s3_multipart := s3_bucket.multiparts.get(upload_id)):
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        # TODO: validate key?
        if s3_multipart.object.key != key:
            pass

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
        stored_multipart.complete_multipart(parts_numbers)

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
            Location=f"{get_full_default_bucket_location(bucket)}{bucket}",
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
        # TODO: write tests around this
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        if not (s3_multipart := s3_bucket.multiparts.pop(upload_id, None)):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        if not (s3_multipart := s3_bucket.multiparts.get(upload_id)):
            raise NoSuchUpload(
                "The specified upload does not exist. "
                "The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        #     AbortDate: Optional[AbortDate] TODO: lifecycle
        #     AbortRuleId: Optional[AbortRuleId] TODO: lifecycle
        #     RequestCharged: Optional[RequestCharged]
        #     ChecksumAlgorithm: Optional[ChecksumAlgorithm]

        response = ListPartsOutput(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            Initiator=s3_multipart.initiator,
            Owner=s3_multipart.initiator,
            StorageClass=s3_multipart.object.storage_class,
            IsTruncated=False,
            MaxParts=max_parts or 1000,
        )

        # TODO: implement MaxParts
        # TODO: implement locking for iteration
        parts = [
            Part(
                ETag=part.quoted_etag,
                LastModified=part.last_modified,
                PartNumber=part_number,
                Size=part.size,
            )
            for part_number, part in sorted(s3_multipart.parts.items())
        ]
        response["Parts"] = parts
        last_part = parts[-1]["PartNumber"] if parts else 0
        response["PartNumberMarker"] = last_part - 1 if parts else 0
        response["NextPartNumberMarker"] = last_part

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        s3_multiparts = s3_bucket.multiparts
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html
        # TODO implement Prefix/Delimiter/CommonPrefixes/EncodingType and truncating results
        # should be common from ListObjects?ListVersions

        #     NextKeyMarker: Optional[NextKeyMarker] ?
        #     NextUploadIdMarker: Optional[NextUploadIdMarker] ?

        response = ListMultipartUploadsOutput(
            Bucket=bucket,
            IsTruncated=False,
            KeyMarker=key_marker or "",
            MaxUploads=max_uploads or 1000,
            UploadIdMarker=upload_id_marker or "",
        )
        # TODO: implement locking for iteration
        uploads = [
            MultipartUpload(
                UploadId=multipart.id,
                Key=multipart.object.key,
                Initiated=multipart.initiated,
                StorageClass=multipart.object.storage_class,
                Owner=multipart.initiator,  # TODO: check the difference
                Initiator=multipart.initiator,
            )
            for multipart in s3_multiparts.values()
        ]
        response["Uploads"] = uploads

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)
        if not (versioning_status := versioning_configuration.get("Status")):
            raise CommonServiceException(
                code="IllegalVersioningConfigurationException",
                message="The Versioning element must be specified",
            )

        if versioning_status not in ("Enabled", "Suspended"):
            raise MalformedXML()

        if not s3_bucket.versioning_status:
            s3_bucket.objects = VersionedKeyStore.from_key_store(s3_bucket.objects)

        elif s3_bucket.versioning_status == "Enabled" and versioning_configuration == "Suspended":
            for current_object_version in s3_bucket.objects.values():
                current_object_version.version_id = "null"
                # TODO: update filestorage

        s3_bucket.versioning_status = versioning_status

    def get_bucket_versioning(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketVersioningOutput:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        if not s3_bucket.versioning_status:
            return GetBucketVersioningOutput()

        return GetBucketVersioningOutput(Status=s3_bucket.versioning_status)

    def get_bucket_encryption(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketEncryptionOutput:
        # AWS now encrypts bucket by default with AES256, see:
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        s3_bucket.encryption_rule = None

    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId = None,
        skip_destination_validation: SkipValidation = None,
    ) -> None:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        self._verify_notification_configuration(
            notification_configuration, skip_destination_validation, context, bucket
        )
        s3_bucket.notification_configuration = notification_configuration

    def get_bucket_notification_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfiguration:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        if "TagSet" not in tagging:
            raise MalformedXML()

        validate_tag_set(tagging["TagSet"], type_set="bucket")

        # remove the previous tags before setting the new ones, it overwrites the whole TagSet
        store.TAGS.tags.pop(s3_bucket.bucket_arn, None)
        store.TAGS.tag_resource(s3_bucket.bucket_arn, tags=tagging["TagSet"])

    def get_bucket_tagging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketTaggingOutput:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)
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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

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
            if s3_object.bucket_key_enabled is not None:
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
