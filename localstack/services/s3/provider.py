import logging
import os
import re
from abc import ABC
from typing import Optional
from urllib.parse import urlparse

import xmltodict
from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.exceptions import S3ClientError
from moto.s3.responses import S3_ALL_MULTIPARTS, MalformedXML, is_delete_keys, minidom
from moto.s3.utils import undo_clean_key_name
from moto.s3bucket_path import utils as s3bucket_path_utils

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    MFA,
    AccelerateConfiguration,
    AccessControlPolicy,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    Body,
    BucketCannedACL,
    BucketKeyEnabled,
    BucketLifecycleConfiguration,
    BucketLoggingStatus,
    BucketName,
    BypassGovernanceRetention,
    CacheControl,
    ConfirmRemoveSelfBucketAccess,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentMD5,
    ContentType,
    CopyObjectOutput,
    CopySource,
    CopySourceIfMatch,
    CopySourceIfModifiedSince,
    CopySourceIfNoneMatch,
    CopySourceIfUnmodifiedSince,
    CopySourceRange,
    CopySourceSSECustomerAlgorithm,
    CopySourceSSECustomerKey,
    CopySourceSSECustomerKeyMD5,
    CORSConfiguration,
    CreateBucketConfiguration,
    CreateBucketOutput,
    Expires,
    GrantFullControl,
    GrantRead,
    GrantReadACP,
    GrantWrite,
    GrantWriteACP,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InventoryConfiguration,
    InventoryId,
    LifecycleConfiguration,
    Metadata,
    MetadataDirective,
    MetricsConfiguration,
    MetricsId,
    MultipartUploadId,
    NoSuchBucket,
    NotificationConfiguration,
    NotificationConfigurationDeprecated,
    ObjectCannedACL,
    ObjectKey,
    ObjectLockConfiguration,
    ObjectLockEnabledForBucket,
    ObjectLockLegalHold,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectLockRetainUntilDate,
    ObjectLockRetention,
    ObjectLockToken,
    ObjectOwnership,
    ObjectVersionId,
    OwnershipControls,
    PartNumber,
    Policy,
    PublicAccessBlockConfiguration,
    PutObjectAclOutput,
    PutObjectLegalHoldOutput,
    PutObjectLockConfigurationOutput,
    PutObjectOutput,
    PutObjectRetentionOutput,
    PutObjectTaggingOutput,
    ReplicationConfiguration,
    RequestPayer,
    RequestPaymentConfiguration,
    S3Api,
    ServerSideEncryption,
    ServerSideEncryptionConfiguration,
    SkipValidation,
    SSECustomerAlgorithm,
    SSECustomerKey,
    SSECustomerKeyMD5,
    SSEKMSEncryptionContext,
    SSEKMSKeyId,
    StorageClass,
    Tagging,
    TaggingDirective,
    TaggingHeader,
    UploadPartCopyOutput,
    UploadPartOutput,
    VersioningConfiguration,
    WebsiteConfiguration,
    WebsiteRedirectLocation,
)
from localstack.services.moto import call_moto
from localstack.services.s3 import s3_listener, s3_utils
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.generic.dict_utils import get_safe
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

# max file size for S3 objects kept in memory (500 KB by default)
S3_MAX_FILE_SIZE_BYTES = 512 * 1024

# see https://stackoverflow.com/questions/50480924/regex-for-s3-bucket-name#50484916
BUCKET_NAME_REGEX = (
    r"(?=^.{3,63}$)(?!^(\d+\.)+\d+$)"
    + r"(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)"
)

# temporary state
TMP_STATE = {}
TMP_TAG = {}


class S3Provider(S3Api, ABC):
    def __init__(self):
        super().__init__()

        if not os.environ.get("MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"):
            os.environ["MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"] = str(S3_MAX_FILE_SIZE_BYTES)

    @staticmethod
    def error_response(message, code, status_code=400):
        result = {"Error": {"Code": code, "Message": message}}
        content = xmltodict.unparse(result)
        return S3Provider.xml_response(content, status_code=status_code)

    @staticmethod
    def xml_response(content, status_code=200):
        headers = {"Content-Type": "application/xml"}
        return requests_response(content, status_code=status_code, headers=headers)

    @staticmethod
    def _raise_if_invalid_bucket_name(context: RequestContext, bucket_name: Optional[BucketName]):
        # Support key names containing hashes (e.g., required by Amplify).
        path = context.request.path.replace("#", "%23")
        parsed_path = urlparse(path)
        if bucket_name and not re.match(BUCKET_NAME_REGEX, bucket_name):
            if len(parsed_path.path) <= 1:
                # return S3Provider.error_response(
                #     "Unable to extract valid bucket name. Please ensure that your AWS SDK is "
                #     + "configured to use path style addressing, or send a valid "
                #     + '<Bucket>.s3.localhost.localstack.cloud "Host" header',
                #     "InvalidBucketName",
                #     status_code=400,
                # )
                # TODO: check how to properly raise in providers.
                # TODO: there are no 'InvalidBucketName' exception type?
                raise NoSuchBucket(
                    "Unable to extract valid bucket name. Please ensure that your AWS SDK is "
                    + "configured to use path style addressing, or send a valid "
                    + '<Bucket>.s3.localhost.localstack.cloud "Host" header',
                    "InvalidBucketName",
                )

            # return S3Provider.error_response(
            #     "The specified bucket is not valid.",
            #     "InvalidBucketName",
            #     status_code=400,
            # )
            # TODO: check how to properly raise in providers.
            # TODO: there are no 'InvalidBucketName' exception type?
            # TODO: status code automatically set?
            raise NoSuchBucket("The specified bucket is not valid.", "InvalidBucketName")

    # def abort_multipart_upload(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> AbortMultipartUploadOutput:
    #     raise NotImplementedError

    # def complete_multipart_upload(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     multipart_upload: CompletedMultipartUpload = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> CompleteMultipartUploadOutput:
    #     raise NotImplementedError

    def copy_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        copy_source: CopySource,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_type: ContentType = None,
        copy_source_if_match: CopySourceIfMatch = None,
        copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        copy_source_if_none_match: CopySourceIfNoneMatch = None,
        copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        expires: Expires = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write_acp: GrantWriteACP = None,
        metadata: Metadata = None,
        metadata_directive: MetadataDirective = None,
        tagging_directive: TaggingDirective = None,
        server_side_encryption: ServerSideEncryption = None,
        storage_class: StorageClass = None,
        website_redirect_location: WebsiteRedirectLocation = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        ssekms_key_id: SSEKMSKeyId = None,
        ssekms_encryption_context: SSEKMSEncryptionContext = None,
        bucket_key_enabled: BucketKeyEnabled = None,
        copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
        copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
        copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        tagging: TaggingHeader = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        expected_bucket_owner: AccountId = None,
        expected_source_bucket_owner: AccountId = None,
    ) -> CopyObjectOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return CopyObjectOutput(**call_moto(context))

    def create_bucket(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL = None,
        create_bucket_configuration: CreateBucketConfiguration = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        object_lock_enabled_for_bucket: ObjectLockEnabledForBucket = None,
        object_ownership: ObjectOwnership = None,
    ) -> CreateBucketOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return CreateBucketOutput(**call_moto(context))

    # def create_multipart_upload(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     acl: ObjectCannedACL = None,
    #     cache_control: CacheControl = None,
    #     content_disposition: ContentDisposition = None,
    #     content_encoding: ContentEncoding = None,
    #     content_language: ContentLanguage = None,
    #     content_type: ContentType = None,
    #     expires: Expires = None,
    #     grant_full_control: GrantFullControl = None,
    #     grant_read: GrantRead = None,
    #     grant_read_acp: GrantReadACP = None,
    #     grant_write_acp: GrantWriteACP = None,
    #     metadata: Metadata = None,
    #     server_side_encryption: ServerSideEncryption = None,
    #     storage_class: StorageClass = None,
    #     website_redirect_location: WebsiteRedirectLocation = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     ssekms_key_id: SSEKMSKeyId = None,
    #     ssekms_encryption_context: SSEKMSEncryptionContext = None,
    #     bucket_key_enabled: BucketKeyEnabled = None,
    #     request_payer: RequestPayer = None,
    #     tagging: TaggingHeader = None,
    #     object_lock_mode: ObjectLockMode = None,
    #     object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
    #     object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> CreateMultipartUploadOutput:
    #     raise NotImplementedError

    # def delete_bucket(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_analytics_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: AnalyticsId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_cors(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_encryption(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_intelligent_tiering_configuration(
    #     self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_inventory_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: InventoryId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_lifecycle(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_metrics_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: MetricsId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_ownership_controls(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_policy(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_replication(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_tagging(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_bucket_website(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def delete_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     mfa: MFA = None,
    #     version_id: ObjectVersionId = None,
    #     request_payer: RequestPayer = None,
    #     bypass_governance_retention: BypassGovernanceRetention = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> DeleteObjectOutput:
    #     raise NotImplementedError

    # def delete_object_tagging(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> DeleteObjectTaggingOutput:
    #     raise NotImplementedError

    # def delete_objects(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delete: Delete,
    #     mfa: MFA = None,
    #     request_payer: RequestPayer = None,
    #     bypass_governance_retention: BypassGovernanceRetention = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> DeleteObjectsOutput:
    #     raise NotImplementedError

    # def delete_public_access_block(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def get_bucket_accelerate_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketAccelerateConfigurationOutput:
    #     raise NotImplementedError

    # def get_bucket_acl(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketAclOutput:
    #     raise NotImplementedError

    # def get_bucket_analytics_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: AnalyticsId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketAnalyticsConfigurationOutput:
    #     raise NotImplementedError

    # def get_bucket_cors(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketCorsOutput:
    #     raise NotImplementedError

    # def get_bucket_encryption(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketEncryptionOutput:
    #     raise NotImplementedError

    # def get_bucket_intelligent_tiering_configuration(
    #     self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    # ) -> GetBucketIntelligentTieringConfigurationOutput:
    #     raise NotImplementedError

    # def get_bucket_inventory_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: InventoryId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketInventoryConfigurationOutput:
    #     raise NotImplementedError

    # def get_bucket_lifecycle(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketLifecycleOutput:
    #     raise NotImplementedError

    # def get_bucket_lifecycle_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketLifecycleConfigurationOutput:
    #     raise NotImplementedError

    # def get_bucket_location(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketLocationOutput:
    #     raise NotImplementedError

    # def get_bucket_logging(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketLoggingOutput:
    #     raise NotImplementedError

    # def get_bucket_metrics_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: MetricsId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketMetricsConfigurationOutput:
    #     raise NotImplementedError

    # def get_bucket_notification(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> NotificationConfigurationDeprecated:
    #     raise NotImplementedError

    # def get_bucket_notification_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> NotificationConfiguration:
    #     raise NotImplementedError

    # def get_bucket_ownership_controls(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketOwnershipControlsOutput:
    #     raise NotImplementedError

    # def get_bucket_policy(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketPolicyOutput:
    #     raise NotImplementedError

    # def get_bucket_policy_status(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketPolicyStatusOutput:
    #     raise NotImplementedError

    # def get_bucket_replication(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketReplicationOutput:
    #     raise NotImplementedError

    # def get_bucket_request_payment(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketRequestPaymentOutput:
    #     raise NotImplementedError

    # def get_bucket_tagging(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketTaggingOutput:
    #     raise NotImplementedError

    # def get_bucket_versioning(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketVersioningOutput:
    #     raise NotImplementedError

    # def get_bucket_website(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetBucketWebsiteOutput:
    #     raise NotImplementedError

    # def get_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     if_match: IfMatch = None,
    #     if_modified_since: IfModifiedSince = None,
    #     if_none_match: IfNoneMatch = None,
    #     if_unmodified_since: IfUnmodifiedSince = None,
    #     range: Range = None,
    #     response_cache_control: ResponseCacheControl = None,
    #     response_content_disposition: ResponseContentDisposition = None,
    #     response_content_encoding: ResponseContentEncoding = None,
    #     response_content_language: ResponseContentLanguage = None,
    #     response_content_type: ResponseContentType = None,
    #     response_expires: ResponseExpires = None,
    #     version_id: ObjectVersionId = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     request_payer: RequestPayer = None,
    #     part_number: PartNumber = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetObjectOutput:
    #     raise NotImplementedError

    # def get_object_acl(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetObjectAclOutput:
    #     raise NotImplementedError

    # def get_object_legal_hold(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetObjectLegalHoldOutput:
    #     raise NotImplementedError

    # def get_object_lock_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetObjectLockConfigurationOutput:
    #     raise NotImplementedError

    # def get_object_retention(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetObjectRetentionOutput:
    #     raise NotImplementedError

    # def get_object_tagging(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     expected_bucket_owner: AccountId = None,
    #     request_payer: RequestPayer = None,
    # ) -> GetObjectTaggingOutput:
    #     raise NotImplementedError

    # def get_object_torrent(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetObjectTorrentOutput:
    #     raise NotImplementedError

    # def get_public_access_block(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> GetPublicAccessBlockOutput:
    #     raise NotImplementedError

    # def head_bucket(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     raise NotImplementedError

    # def head_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     if_match: IfMatch = None,
    #     if_modified_since: IfModifiedSince = None,
    #     if_none_match: IfNoneMatch = None,
    #     if_unmodified_since: IfUnmodifiedSince = None,
    #     range: Range = None,
    #     version_id: ObjectVersionId = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     request_payer: RequestPayer = None,
    #     part_number: PartNumber = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> HeadObjectOutput:
    #     raise NotImplementedError

    # def list_bucket_analytics_configurations(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     continuation_token: Token = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListBucketAnalyticsConfigurationsOutput:
    #     raise NotImplementedError

    # def list_bucket_intelligent_tiering_configurations(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     continuation_token: Token = None,
    # ) -> ListBucketIntelligentTieringConfigurationsOutput:
    #     raise NotImplementedError

    # def list_bucket_inventory_configurations(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     continuation_token: Token = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListBucketInventoryConfigurationsOutput:
    #     raise NotImplementedError

    # def list_bucket_metrics_configurations(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     continuation_token: Token = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListBucketMetricsConfigurationsOutput:
    #     raise NotImplementedError

    # def list_buckets(
    #     self,
    #     context: RequestContext,
    # ) -> ListBucketsOutput:
    #     raise NotImplementedError

    # def list_multipart_uploads(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     key_marker: KeyMarker = None,
    #     max_uploads: MaxUploads = None,
    #     prefix: Prefix = None,
    #     upload_id_marker: UploadIdMarker = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListMultipartUploadsOutput:
    #     raise NotImplementedError

    # def list_object_versions(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     key_marker: KeyMarker = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     version_id_marker: VersionIdMarker = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectVersionsOutput:
    #     raise NotImplementedError

    # def list_objects(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     marker: Marker = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectsOutput:
    #     raise NotImplementedError
    #
    # @handler("ListObjectsV2")
    # def list_objects_v2(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     continuation_token: Token = None,
    #     fetch_owner: FetchOwner = None,
    #     start_after: StartAfter = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectsV2Output:
    #     raise NotImplementedError

    # def list_parts(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     max_parts: MaxParts = None,
    #     part_number_marker: PartNumberMarker = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListPartsOutput:
    #     raise NotImplementedError

    def put_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        accelerate_configuration: AccelerateConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL = None,
        access_control_policy: AccessControlPolicy = None,
        content_md5: ContentMD5 = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        analytics_configuration: AnalyticsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        cors_configuration: CORSConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        server_side_encryption_configuration: ServerSideEncryptionConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        intelligent_tiering_configuration: IntelligentTieringConfiguration,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        inventory_configuration: InventoryConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        content_md5: ContentMD5 = None,
        lifecycle_configuration: LifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        lifecycle_configuration: BucketLifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        bucket_logging_status: BucketLoggingStatus,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        metrics_configuration: MetricsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_notification(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfigurationDeprecated,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId = None,
        skip_destination_validation: SkipValidation = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        ownership_controls: OwnershipControls,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        policy: Policy,
        content_md5: ContentMD5 = None,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        replication_configuration: ReplicationConfiguration,
        content_md5: ContentMD5 = None,
        token: ObjectLockToken = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        request_payment_configuration: RequestPaymentConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        tagging: Tagging,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_versioning(
        self,
        context: RequestContext,
        bucket: BucketName,
        versioning_configuration: VersioningConfiguration,
        content_md5: ContentMD5 = None,
        mfa: MFA = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        website_configuration: WebsiteConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        body: Body = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_length: ContentLength = None,
        content_md5: ContentMD5 = None,
        content_type: ContentType = None,
        expires: Expires = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write_acp: GrantWriteACP = None,
        metadata: Metadata = None,
        server_side_encryption: ServerSideEncryption = None,
        storage_class: StorageClass = None,
        website_redirect_location: WebsiteRedirectLocation = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        ssekms_key_id: SSEKMSKeyId = None,
        ssekms_encryption_context: SSEKMSEncryptionContext = None,
        bucket_key_enabled: BucketKeyEnabled = None,
        request_payer: RequestPayer = None,
        tagging: TaggingHeader = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return PutObjectOutput(**call_moto(context))

    def put_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        access_control_policy: AccessControlPolicy = None,
        content_md5: ContentMD5 = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectAclOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return PutObjectAclOutput(**call_moto(context))

    def put_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        legal_hold: ObjectLockLegalHold = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectLegalHoldOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return PutObjectLegalHoldOutput(**call_moto(context))

    def put_object_lock_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        object_lock_configuration: ObjectLockConfiguration = None,
        request_payer: RequestPayer = None,
        token: ObjectLockToken = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectLockConfigurationOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return PutObjectLockConfigurationOutput(**call_moto(context))

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
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectRetentionOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return PutObjectRetentionOutput(**call_moto(context))

    def put_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        tagging: Tagging,
        version_id: ObjectVersionId = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> PutObjectTaggingOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return PutObjectTaggingOutput(**call_moto(context))

    def put_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    # def restore_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     restore_request: RestoreRequest = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> RestoreObjectOutput:
    #     raise NotImplementedError

    # def select_object_content(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     expression: Expression,
    #     expression_type: ExpressionType,
    #     input_serialization: InputSerialization,
    #     output_serialization: OutputSerialization,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     request_progress: RequestProgress = None,
    #     scan_range: ScanRange = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> SelectObjectContentOutput:
    #     raise NotImplementedError

    def upload_part(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        part_number: PartNumber,
        upload_id: MultipartUploadId,
        body: Body = None,
        content_length: ContentLength = None,
        content_md5: ContentMD5 = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> UploadPartOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return UploadPartOutput(**call_moto(context))

    def upload_part_copy(
        self,
        context: RequestContext,
        bucket: BucketName,
        copy_source: CopySource,
        key: ObjectKey,
        part_number: PartNumber,
        upload_id: MultipartUploadId,
        copy_source_if_match: CopySourceIfMatch = None,
        copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        copy_source_if_none_match: CopySourceIfNoneMatch = None,
        copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        copy_source_range: CopySourceRange = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
        copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
        copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
        expected_source_bucket_owner: AccountId = None,
    ) -> UploadPartCopyOutput:
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return UploadPartCopyOutput(**call_moto(context))

    # def write_get_object_response(
    #     self,
    #     context: RequestContext,
    #     request_route: RequestRoute,
    #     request_token: RequestToken,
    #     body: Body = None,
    #     status_code: GetObjectResponseStatusCode = None,
    #     error_code: ErrorCode = None,
    #     error_message: ErrorMessage = None,
    #     accept_ranges: AcceptRanges = None,
    #     cache_control: CacheControl = None,
    #     content_disposition: ContentDisposition = None,
    #     content_encoding: ContentEncoding = None,
    #     content_language: ContentLanguage = None,
    #     content_length: ContentLength = None,
    #     content_range: ContentRange = None,
    #     content_type: ContentType = None,
    #     delete_marker: DeleteMarker = None,
    #     e_tag: ETag = None,
    #     expires: Expires = None,
    #     expiration: Expiration = None,
    #     last_modified: LastModified = None,
    #     missing_meta: MissingMeta = None,
    #     metadata: Metadata = None,
    #     object_lock_mode: ObjectLockMode = None,
    #     object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
    #     object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
    #     parts_count: PartsCount = None,
    #     replication_status: ReplicationStatus = None,
    #     request_charged: RequestCharged = None,
    #     restore: Restore = None,
    #     server_side_encryption: ServerSideEncryption = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     ssekms_key_id: SSEKMSKeyId = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     storage_class: StorageClass = None,
    #     tag_count: TagCount = None,
    #     version_id: ObjectVersionId = None,
    #     bucket_key_enabled: BucketKeyEnabled = None,
    # ) -> None:
    #     raise NotImplementedError


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
@patch(s3_models.s3_backend.create_bucket)
def create_bucket(self, fn, bucket_name, region_name, *args, **kwargs):
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    return fn(bucket_name, region_name, *args, **kwargs)


# patch S3Bucket.get_bucket(..)
@patch(s3_models.s3_backend.get_bucket)
def get_bucket(self, fn, bucket_name, *args, **kwargs):
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    if bucket_name == config.BUCKET_MARKER_LOCAL:
        return None
    return fn(bucket_name, *args, **kwargs)


@patch(s3_responses.ResponseObject._bucket_response_head)
def _bucket_response_head(fn, self, bucket_name, *args, **kwargs):
    code, headers, body = fn(self, bucket_name, *args, **kwargs)
    bucket = s3_models.s3_backend.get_bucket(bucket_name)
    headers["x-amz-bucket-region"] = bucket.region_name
    return code, headers, body


@patch(s3_responses.ResponseObject._bucket_response_get)
def _bucket_response_get(fn, self, bucket_name, querystring, *args, **kwargs):
    result = fn(self, bucket_name, querystring, *args, **kwargs)
    # for some reason in the "get-bucket-location" call, moto doesn't return a code, headers, body triple as a result
    if isinstance(result, tuple) and len(result) == 3:
        code, headers, body = result
        bucket = s3_models.s3_backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
    return result


# patch S3Bucket.get_bucket(..)
@patch(s3_models.s3_backend.delete_bucket)
def delete_bucket(self, fn, bucket_name, *args, **kwargs):
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    s3_listener.remove_bucket_notification(bucket_name)
    return fn(bucket_name, *args, **kwargs)


# patch _key_response_post(..)
@patch(s3_responses.S3ResponseInstance._key_response_post)
def s3_key_response_post(self, fn, request, body, bucket_name, query, key_name, *args, **kwargs):
    result = fn(request, body, bucket_name, query, key_name, *args, **kwargs)
    s3_update_acls(self, request, query, bucket_name, key_name)
    try:
        if query.get("uploadId"):
            if (bucket_name, key_name) in TMP_TAG:
                key = self.backend.get_object(bucket_name, key_name)
                self.backend.set_key_tags(key, TMP_TAG.get((bucket_name, key_name), None), key_name)
                TMP_TAG.pop((bucket_name, key_name))
    except Exception:
        pass
    if query.get("uploads") and request.headers.get("X-Amz-Tagging"):
        tags = self._tagging_from_headers(request.headers)
        TMP_TAG[(bucket_name, key_name)] = tags
    return result


# patch _key_response_put(..)
@patch(s3_responses.S3ResponseInstance._key_response_put)
def s3_key_response_put(
    self, fn, request, body, bucket_name, query, key_name, headers, *args, **kwargs
):
    result = fn(request, body, bucket_name, query, key_name, headers, *args, **kwargs)
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
    code = 400

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
def s3_bucket_response_delete_keys(self, request, body, bucket_name):
    template = self.response_template(s3_delete_keys_response_template)
    elements = minidom.parseString(body).getElementsByTagName("Object")
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
        success = self.backend.delete_object(bucket_name, undo_clean_key_name(key_name), version_id)

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


# Patch utils_is_delete_keys
# https://github.com/localstack/localstack/issues/2866
# https://github.com/localstack/localstack/issues/2850
# https://github.com/localstack/localstack/issues/3931
# https://github.com/localstack/localstack/issues/4015
utils_is_delete_keys_orig = s3bucket_path_utils.is_delete_keys


def utils_is_delete_keys(request, path, bucket_name):
    return "/" + bucket_name + "?delete=" in path or utils_is_delete_keys_orig(
        request, path, bucket_name
    )


@patch(s3_responses.S3ResponseInstance.is_delete_keys, pass_target=False)
def s3_response_is_delete_keys(self, request, path, bucket_name):
    if self.subdomain_based_buckets(request):
        # Temporary fix until moto supports x-id and DeleteObjects (#3931)
        query = self._get_querystring(request.url)
        is_delete_keys_v3 = (
            query and ("delete" in query) and get_safe(query, "$.x-id.0") == "DeleteObjects"
        )
        return is_delete_keys_v3 or is_delete_keys(request, path, bucket_name)
    else:
        return utils_is_delete_keys(request, path, bucket_name)


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


@patch(s3_models.s3_backend.copy_object)
def copy_object(
    self,
    fn,
    src_key,
    dest_bucket_name,
    dest_key_name,
    *args,
    **kwargs,
):
    fn(
        src_key,
        dest_bucket_name,
        dest_key_name,
        *args,
        **kwargs,
    )
    key = self.get_object(dest_bucket_name, dest_key_name)
    # reset etag
    key._etag = None
