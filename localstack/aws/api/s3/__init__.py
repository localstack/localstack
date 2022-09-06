import sys
from datetime import datetime
from typing import IO, Dict, Iterable, Iterator, List, Optional, Union

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AbortRuleId = str
AcceptRanges = str
AccessPointArn = str
AccountId = str
AllowQuotedRecordDelimiter = bool
AllowedHeader = str
AllowedMethod = str
AllowedOrigin = str
AnalyticsId = str
BucketKeyEnabled = bool
BucketName = str
BypassGovernanceRetention = bool
CacheControl = str
ChecksumCRC32 = str
ChecksumCRC32C = str
ChecksumSHA1 = str
ChecksumSHA256 = str
CloudFunction = str
CloudFunctionInvocationRole = str
Code = str
Comments = str
ConfirmRemoveSelfBucketAccess = bool
ContentDisposition = str
ContentEncoding = str
ContentLanguage = str
ContentMD5 = str
ContentRange = str
ContentType = str
CopySource = str
CopySourceIfMatch = str
CopySourceIfNoneMatch = str
CopySourceRange = str
CopySourceSSECustomerAlgorithm = str
CopySourceSSECustomerKey = str
CopySourceSSECustomerKeyMD5 = str
CopySourceVersionId = str
Days = int
DaysAfterInitiation = int
DeleteMarker = bool
DeleteMarkerVersionId = str
Delimiter = str
Description = str
DisplayName = str
ETag = str
EmailAddress = str
EnableRequestProgress = bool
ErrorCode = str
ErrorMessage = str
Expiration = str
ExpiredObjectDeleteMarker = bool
ExposeHeader = str
Expression = str
FetchOwner = bool
FieldDelimiter = str
FilterRuleValue = str
GetObjectResponseStatusCode = int
GrantFullControl = str
GrantRead = str
GrantReadACP = str
GrantWrite = str
GrantWriteACP = str
HostName = str
HttpErrorCodeReturnedEquals = str
HttpRedirectCode = str
ID = str
IfMatch = str
IfNoneMatch = str
IntelligentTieringDays = int
IntelligentTieringId = str
InventoryId = str
IsEnabled = bool
IsLatest = bool
IsPublic = bool
IsTruncated = bool
KMSContext = str
KeyCount = int
KeyMarker = str
KeyPrefixEquals = str
LambdaFunctionArn = str
Location = str
LocationPrefix = str
MFA = str
Marker = str
MaxAgeSeconds = int
MaxKeys = int
MaxParts = int
MaxUploads = int
Message = str
MetadataKey = str
MetadataValue = str
MetricsId = str
Minutes = int
MissingMeta = int
MultipartUploadId = str
NextKeyMarker = str
NextMarker = str
NextPartNumberMarker = int
NextToken = str
NextUploadIdMarker = str
NextVersionIdMarker = str
NotificationId = str
ObjectKey = str
ObjectLockEnabledForBucket = bool
ObjectLockToken = str
ObjectVersionId = str
PartNumber = int
PartNumberMarker = int
PartsCount = int
Policy = str
Prefix = str
Priority = int
QueueArn = str
Quiet = bool
QuoteCharacter = str
QuoteEscapeCharacter = str
Range = str
RecordDelimiter = str
ReplaceKeyPrefixWith = str
ReplaceKeyWith = str
ReplicaKmsKeyID = str
RequestRoute = str
RequestToken = str
ResponseCacheControl = str
ResponseContentDisposition = str
ResponseContentEncoding = str
ResponseContentLanguage = str
ResponseContentType = str
Restore = str
RestoreOutputPath = str
Role = str
SSECustomerAlgorithm = str
SSECustomerKey = str
SSECustomerKeyMD5 = str
SSEKMSEncryptionContext = str
SSEKMSKeyId = str
Setting = bool
Size = int
SkipValidation = bool
StartAfter = str
Suffix = str
TagCount = int
TaggingHeader = str
TargetBucket = str
TargetPrefix = str
Token = str
TopicArn = str
URI = str
UploadIdMarker = str
Value = str
VersionCount = int
VersionIdMarker = str
WebsiteRedirectLocation = str
Years = int


class AnalyticsS3ExportFileFormat(str):
    CSV = "CSV"


class ArchiveStatus(str):
    ARCHIVE_ACCESS = "ARCHIVE_ACCESS"
    DEEP_ARCHIVE_ACCESS = "DEEP_ARCHIVE_ACCESS"


class BucketAccelerateStatus(str):
    Enabled = "Enabled"
    Suspended = "Suspended"


class BucketCannedACL(str):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    authenticated_read = "authenticated-read"


class BucketLocationConstraint(str):
    af_south_1 = "af-south-1"
    ap_east_1 = "ap-east-1"
    ap_northeast_1 = "ap-northeast-1"
    ap_northeast_2 = "ap-northeast-2"
    ap_northeast_3 = "ap-northeast-3"
    ap_south_1 = "ap-south-1"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ca_central_1 = "ca-central-1"
    cn_north_1 = "cn-north-1"
    cn_northwest_1 = "cn-northwest-1"
    EU = "EU"
    eu_central_1 = "eu-central-1"
    eu_north_1 = "eu-north-1"
    eu_south_1 = "eu-south-1"
    eu_west_1 = "eu-west-1"
    eu_west_2 = "eu-west-2"
    eu_west_3 = "eu-west-3"
    me_south_1 = "me-south-1"
    sa_east_1 = "sa-east-1"
    us_east_2 = "us-east-2"
    us_gov_east_1 = "us-gov-east-1"
    us_gov_west_1 = "us-gov-west-1"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"


class BucketLogsPermission(str):
    FULL_CONTROL = "FULL_CONTROL"
    READ = "READ"
    WRITE = "WRITE"


class BucketVersioningStatus(str):
    Enabled = "Enabled"
    Suspended = "Suspended"


class ChecksumAlgorithm(str):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    SHA1 = "SHA1"
    SHA256 = "SHA256"


class ChecksumMode(str):
    ENABLED = "ENABLED"


class CompressionType(str):
    NONE = "NONE"
    GZIP = "GZIP"
    BZIP2 = "BZIP2"


class DeleteMarkerReplicationStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class EncodingType(str):
    url = "url"


class Event(str):
    s3_ReducedRedundancyLostObject = "s3:ReducedRedundancyLostObject"
    s3_ObjectCreated_ = "s3:ObjectCreated:*"
    s3_ObjectCreated_Put = "s3:ObjectCreated:Put"
    s3_ObjectCreated_Post = "s3:ObjectCreated:Post"
    s3_ObjectCreated_Copy = "s3:ObjectCreated:Copy"
    s3_ObjectCreated_CompleteMultipartUpload = "s3:ObjectCreated:CompleteMultipartUpload"
    s3_ObjectRemoved_ = "s3:ObjectRemoved:*"
    s3_ObjectRemoved_Delete = "s3:ObjectRemoved:Delete"
    s3_ObjectRemoved_DeleteMarkerCreated = "s3:ObjectRemoved:DeleteMarkerCreated"
    s3_ObjectRestore_ = "s3:ObjectRestore:*"
    s3_ObjectRestore_Post = "s3:ObjectRestore:Post"
    s3_ObjectRestore_Completed = "s3:ObjectRestore:Completed"
    s3_Replication_ = "s3:Replication:*"
    s3_Replication_OperationFailedReplication = "s3:Replication:OperationFailedReplication"
    s3_Replication_OperationNotTracked = "s3:Replication:OperationNotTracked"
    s3_Replication_OperationMissedThreshold = "s3:Replication:OperationMissedThreshold"
    s3_Replication_OperationReplicatedAfterThreshold = (
        "s3:Replication:OperationReplicatedAfterThreshold"
    )
    s3_ObjectRestore_Delete = "s3:ObjectRestore:Delete"
    s3_LifecycleTransition = "s3:LifecycleTransition"
    s3_IntelligentTiering = "s3:IntelligentTiering"
    s3_ObjectAcl_Put = "s3:ObjectAcl:Put"
    s3_LifecycleExpiration_ = "s3:LifecycleExpiration:*"
    s3_LifecycleExpiration_Delete = "s3:LifecycleExpiration:Delete"
    s3_LifecycleExpiration_DeleteMarkerCreated = "s3:LifecycleExpiration:DeleteMarkerCreated"
    s3_ObjectTagging_ = "s3:ObjectTagging:*"
    s3_ObjectTagging_Put = "s3:ObjectTagging:Put"
    s3_ObjectTagging_Delete = "s3:ObjectTagging:Delete"


class ExistingObjectReplicationStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExpirationStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExpressionType(str):
    SQL = "SQL"


class FileHeaderInfo(str):
    USE = "USE"
    IGNORE = "IGNORE"
    NONE = "NONE"


class FilterRuleName(str):
    prefix = "prefix"
    suffix = "suffix"


class IntelligentTieringAccessTier(str):
    ARCHIVE_ACCESS = "ARCHIVE_ACCESS"
    DEEP_ARCHIVE_ACCESS = "DEEP_ARCHIVE_ACCESS"


class IntelligentTieringStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class InventoryFormat(str):
    CSV = "CSV"
    ORC = "ORC"
    Parquet = "Parquet"


class InventoryFrequency(str):
    Daily = "Daily"
    Weekly = "Weekly"


class InventoryIncludedObjectVersions(str):
    All = "All"
    Current = "Current"


class InventoryOptionalField(str):
    Size = "Size"
    LastModifiedDate = "LastModifiedDate"
    StorageClass = "StorageClass"
    ETag = "ETag"
    IsMultipartUploaded = "IsMultipartUploaded"
    ReplicationStatus = "ReplicationStatus"
    EncryptionStatus = "EncryptionStatus"
    ObjectLockRetainUntilDate = "ObjectLockRetainUntilDate"
    ObjectLockMode = "ObjectLockMode"
    ObjectLockLegalHoldStatus = "ObjectLockLegalHoldStatus"
    IntelligentTieringAccessTier = "IntelligentTieringAccessTier"
    BucketKeyStatus = "BucketKeyStatus"
    ChecksumAlgorithm = "ChecksumAlgorithm"


class JSONType(str):
    DOCUMENT = "DOCUMENT"
    LINES = "LINES"


class MFADelete(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MFADeleteStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MetadataDirective(str):
    COPY = "COPY"
    REPLACE = "REPLACE"


class MetricsStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ObjectAttributes(str):
    ETag = "ETag"
    Checksum = "Checksum"
    ObjectParts = "ObjectParts"
    StorageClass = "StorageClass"
    ObjectSize = "ObjectSize"


class ObjectCannedACL(str):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    authenticated_read = "authenticated-read"
    aws_exec_read = "aws-exec-read"
    bucket_owner_read = "bucket-owner-read"
    bucket_owner_full_control = "bucket-owner-full-control"


class ObjectLockEnabled(str):
    Enabled = "Enabled"


class ObjectLockLegalHoldStatus(str):
    ON = "ON"
    OFF = "OFF"


class ObjectLockMode(str):
    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class ObjectLockRetentionMode(str):
    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class ObjectOwnership(str):
    BucketOwnerPreferred = "BucketOwnerPreferred"
    ObjectWriter = "ObjectWriter"
    BucketOwnerEnforced = "BucketOwnerEnforced"


class ObjectStorageClass(str):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    GLACIER = "GLACIER"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"


class ObjectVersionStorageClass(str):
    STANDARD = "STANDARD"


class OwnerOverride(str):
    Destination = "Destination"


class Payer(str):
    Requester = "Requester"
    BucketOwner = "BucketOwner"


class Permission(str):
    FULL_CONTROL = "FULL_CONTROL"
    WRITE = "WRITE"
    WRITE_ACP = "WRITE_ACP"
    READ = "READ"
    READ_ACP = "READ_ACP"


class Protocol(str):
    http = "http"
    https = "https"


class QuoteFields(str):
    ALWAYS = "ALWAYS"
    ASNEEDED = "ASNEEDED"


class ReplicaModificationsStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReplicationRuleStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReplicationStatus(str):
    COMPLETE = "COMPLETE"
    PENDING = "PENDING"
    FAILED = "FAILED"
    REPLICA = "REPLICA"


class ReplicationTimeStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class RequestCharged(str):
    requester = "requester"


class RequestPayer(str):
    requester = "requester"


class RestoreRequestType(str):
    SELECT = "SELECT"


class ServerSideEncryption(str):
    AES256 = "AES256"
    aws_kms = "aws:kms"


class SseKmsEncryptedObjectsStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class StorageClass(str):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"


class StorageClassAnalysisSchemaVersion(str):
    V_1 = "V_1"


class TaggingDirective(str):
    COPY = "COPY"
    REPLACE = "REPLACE"


class Tier(str):
    Standard = "Standard"
    Bulk = "Bulk"
    Expedited = "Expedited"


class TransitionStorageClass(str):
    GLACIER = "GLACIER"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    GLACIER_IR = "GLACIER_IR"


class Type(str):
    CanonicalUser = "CanonicalUser"
    AmazonCustomerByEmail = "AmazonCustomerByEmail"
    Group = "Group"


class BucketAlreadyExists(ServiceException):
    """The requested bucket name is not available. The bucket namespace is
    shared by all users of the system. Select a different name and try
    again.
    """

    code: str = "BucketAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class BucketAlreadyOwnedByYou(ServiceException):
    """The bucket you tried to create already exists, and you own it. Amazon S3
    returns this error in all Amazon Web Services Regions except in the
    North Virginia Region. For legacy compatibility, if you re-create an
    existing bucket that you already own in the North Virginia Region,
    Amazon S3 returns 200 OK and resets the bucket access control lists
    (ACLs).
    """

    code: str = "BucketAlreadyOwnedByYou"
    sender_fault: bool = False
    status_code: int = 400


class InvalidObjectState(ServiceException):
    """Object is archived and inaccessible until restored."""

    code: str = "InvalidObjectState"
    sender_fault: bool = False
    status_code: int = 400
    StorageClass: Optional[StorageClass]
    AccessTier: Optional[IntelligentTieringAccessTier]


class NoSuchBucket(ServiceException):
    """The specified bucket does not exist."""

    code: str = "NoSuchBucket"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: Optional[BucketName]


class NoSuchKey(ServiceException):
    """The specified key does not exist."""

    code: str = "NoSuchKey"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchUpload(ServiceException):
    """The specified multipart upload does not exist."""

    code: str = "NoSuchUpload"
    sender_fault: bool = False
    status_code: int = 400


class ObjectAlreadyInActiveTierError(ServiceException):
    """This action is not allowed against this storage tier."""

    code: str = "ObjectAlreadyInActiveTierError"
    sender_fault: bool = False
    status_code: int = 400


class ObjectNotInActiveTierError(ServiceException):
    """The source object of the COPY action is not in the active tier and is
    only stored in Amazon S3 Glacier.
    """

    code: str = "ObjectNotInActiveTierError"
    sender_fault: bool = False
    status_code: int = 400


AbortDate = datetime


class AbortIncompleteMultipartUpload(TypedDict, total=False):
    """Specifies the days since the initiation of an incomplete multipart
    upload that Amazon S3 will wait before permanently removing all parts of
    the upload. For more information, see `Aborting Incomplete Multipart
    Uploads Using a Bucket Lifecycle
    Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html#mpu-abort-incomplete-mpu-lifecycle-config>`__
    in the *Amazon S3 User Guide*.
    """

    DaysAfterInitiation: Optional[DaysAfterInitiation]


class AbortMultipartUploadOutput(TypedDict, total=False):
    RequestCharged: Optional[RequestCharged]


class AbortMultipartUploadRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    UploadId: MultipartUploadId
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class AccelerateConfiguration(TypedDict, total=False):
    """Configures the transfer acceleration state for an Amazon S3 bucket. For
    more information, see `Amazon S3 Transfer
    Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`__
    in the *Amazon S3 User Guide*.
    """

    Status: Optional[BucketAccelerateStatus]


class Owner(TypedDict, total=False):
    """Container for the owner's display name and ID."""

    DisplayName: Optional[DisplayName]
    ID: Optional[ID]


class Grantee(TypedDict, total=False):
    """Container for the person being granted permissions."""

    DisplayName: Optional[DisplayName]
    EmailAddress: Optional[EmailAddress]
    ID: Optional[ID]
    Type: Type
    URI: Optional[URI]


class Grant(TypedDict, total=False):
    """Container for grant information."""

    Grantee: Optional[Grantee]
    Permission: Optional[Permission]


Grants = List[Grant]


class AccessControlPolicy(TypedDict, total=False):
    """Contains the elements that set the ACL permissions for an object per
    grantee.
    """

    Grants: Optional[Grants]
    Owner: Optional[Owner]


class AccessControlTranslation(TypedDict, total=False):
    """A container for information about access control for replicas."""

    Owner: OwnerOverride


AllowedHeaders = List[AllowedHeader]
AllowedMethods = List[AllowedMethod]
AllowedOrigins = List[AllowedOrigin]


class Tag(TypedDict, total=False):
    """A container of a key value name pair."""

    Key: ObjectKey
    Value: Value


TagSet = List[Tag]


class AnalyticsAndOperator(TypedDict, total=False):
    """A conjunction (logical AND) of predicates, which is used in evaluating a
    metrics filter. The operator must have at least two predicates in any
    combination, and an object must match all of the predicates for the
    filter to apply.
    """

    Prefix: Optional[Prefix]
    Tags: Optional[TagSet]


class AnalyticsS3BucketDestination(TypedDict, total=False):
    """Contains information about where to publish the analytics results."""

    Format: AnalyticsS3ExportFileFormat
    BucketAccountId: Optional[AccountId]
    Bucket: BucketName
    Prefix: Optional[Prefix]


class AnalyticsExportDestination(TypedDict, total=False):
    """Where to publish the analytics results."""

    S3BucketDestination: AnalyticsS3BucketDestination


class StorageClassAnalysisDataExport(TypedDict, total=False):
    """Container for data related to the storage class analysis for an Amazon
    S3 bucket for export.
    """

    OutputSchemaVersion: StorageClassAnalysisSchemaVersion
    Destination: AnalyticsExportDestination


class StorageClassAnalysis(TypedDict, total=False):
    """Specifies data related to access patterns to be collected and made
    available to analyze the tradeoffs between different storage classes for
    an Amazon S3 bucket.
    """

    DataExport: Optional[StorageClassAnalysisDataExport]


class AnalyticsFilter(TypedDict, total=False):
    """The filter used to describe a set of objects for analyses. A filter must
    have exactly one prefix, one tag, or one conjunction
    (AnalyticsAndOperator). If no filter is provided, all objects will be
    considered in any analysis.
    """

    Prefix: Optional[Prefix]
    Tag: Optional[Tag]
    And: Optional[AnalyticsAndOperator]


class AnalyticsConfiguration(TypedDict, total=False):
    """Specifies the configuration and any analyses for the analytics filter of
    an Amazon S3 bucket.
    """

    Id: AnalyticsId
    Filter: Optional[AnalyticsFilter]
    StorageClassAnalysis: StorageClassAnalysis


AnalyticsConfigurationList = List[AnalyticsConfiguration]
Body = bytes
CreationDate = datetime


class Bucket(TypedDict, total=False):
    """In terms of implementation, a Bucket is a resource. An Amazon S3 bucket
    name is globally unique, and the namespace is shared by all Amazon Web
    Services accounts.
    """

    Name: Optional[BucketName]
    CreationDate: Optional[CreationDate]


class NoncurrentVersionExpiration(TypedDict, total=False):
    """Specifies when noncurrent object versions expire. Upon expiration,
    Amazon S3 permanently deletes the noncurrent object versions. You set
    this lifecycle configuration action on a bucket that has versioning
    enabled (or suspended) to request that Amazon S3 delete noncurrent
    object versions at a specific period in the object's lifetime.
    """

    NoncurrentDays: Optional[Days]
    NewerNoncurrentVersions: Optional[VersionCount]


class NoncurrentVersionTransition(TypedDict, total=False):
    """Container for the transition rule that describes when noncurrent objects
    transition to the ``STANDARD_IA``, ``ONEZONE_IA``,
    ``INTELLIGENT_TIERING``, ``GLACIER_IR``, ``GLACIER``, or
    ``DEEP_ARCHIVE`` storage class. If your bucket is versioning-enabled (or
    versioning is suspended), you can set this action to request that Amazon
    S3 transition noncurrent object versions to the ``STANDARD_IA``,
    ``ONEZONE_IA``, ``INTELLIGENT_TIERING``, ``GLACIER_IR``, ``GLACIER``, or
    ``DEEP_ARCHIVE`` storage class at a specific period in the object's
    lifetime.
    """

    NoncurrentDays: Optional[Days]
    StorageClass: Optional[TransitionStorageClass]
    NewerNoncurrentVersions: Optional[VersionCount]


NoncurrentVersionTransitionList = List[NoncurrentVersionTransition]
Date = datetime


class Transition(TypedDict, total=False):
    """Specifies when an object transitions to a specified storage class. For
    more information about Amazon S3 lifecycle configuration rules, see
    `Transitioning Objects Using Amazon S3
    Lifecycle <https://docs.aws.amazon.com/AmazonS3/latest/dev/lifecycle-transition-general-considerations.html>`__
    in the *Amazon S3 User Guide*.
    """

    Date: Optional[Date]
    Days: Optional[Days]
    StorageClass: Optional[TransitionStorageClass]


TransitionList = List[Transition]
ObjectSizeLessThanBytes = int
ObjectSizeGreaterThanBytes = int


class LifecycleRuleAndOperator(TypedDict, total=False):
    """This is used in a Lifecycle Rule Filter to apply a logical AND to two or
    more predicates. The Lifecycle Rule will apply to any object matching
    all of the predicates configured inside the And operator.
    """

    Prefix: Optional[Prefix]
    Tags: Optional[TagSet]
    ObjectSizeGreaterThan: Optional[ObjectSizeGreaterThanBytes]
    ObjectSizeLessThan: Optional[ObjectSizeLessThanBytes]


class LifecycleRuleFilter(TypedDict, total=False):
    """The ``Filter`` is used to identify objects that a Lifecycle Rule applies
    to. A ``Filter`` must have exactly one of ``Prefix``, ``Tag``, or
    ``And`` specified.
    """

    Prefix: Optional[Prefix]
    Tag: Optional[Tag]
    ObjectSizeGreaterThan: Optional[ObjectSizeGreaterThanBytes]
    ObjectSizeLessThan: Optional[ObjectSizeLessThanBytes]
    And: Optional[LifecycleRuleAndOperator]


class LifecycleExpiration(TypedDict, total=False):
    """Container for the expiration for the lifecycle of the object."""

    Date: Optional[Date]
    Days: Optional[Days]
    ExpiredObjectDeleteMarker: Optional[ExpiredObjectDeleteMarker]


class LifecycleRule(TypedDict, total=False):
    """A lifecycle rule for individual objects in an Amazon S3 bucket."""

    Expiration: Optional[LifecycleExpiration]
    ID: Optional[ID]
    Prefix: Optional[Prefix]
    Filter: Optional[LifecycleRuleFilter]
    Status: ExpirationStatus
    Transitions: Optional[TransitionList]
    NoncurrentVersionTransitions: Optional[NoncurrentVersionTransitionList]
    NoncurrentVersionExpiration: Optional[NoncurrentVersionExpiration]
    AbortIncompleteMultipartUpload: Optional[AbortIncompleteMultipartUpload]


LifecycleRules = List[LifecycleRule]


class BucketLifecycleConfiguration(TypedDict, total=False):
    """Specifies the lifecycle configuration for objects in an Amazon S3
    bucket. For more information, see `Object Lifecycle
    Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`__
    in the *Amazon S3 User Guide*.
    """

    Rules: LifecycleRules


class TargetGrant(TypedDict, total=False):
    """Container for granting information.

    Buckets that use the bucket owner enforced setting for Object Ownership
    don't support target grants. For more information, see `Permissions
    server access log
    delivery <https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html#grant-log-delivery-permissions-general>`__
    in the *Amazon S3 User Guide*.
    """

    Grantee: Optional[Grantee]
    Permission: Optional[BucketLogsPermission]


TargetGrants = List[TargetGrant]


class LoggingEnabled(TypedDict, total=False):
    """Describes where logs are stored and the prefix that Amazon S3 assigns to
    all log object keys for a bucket. For more information, see `PUT Bucket
    logging <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html>`__
    in the *Amazon S3 API Reference*.
    """

    TargetBucket: TargetBucket
    TargetGrants: Optional[TargetGrants]
    TargetPrefix: TargetPrefix


class BucketLoggingStatus(TypedDict, total=False):
    """Container for logging status information."""

    LoggingEnabled: Optional[LoggingEnabled]


Buckets = List[Bucket]
BytesProcessed = int
BytesReturned = int
BytesScanned = int
ExposeHeaders = List[ExposeHeader]


class CORSRule(TypedDict, total=False):
    """Specifies a cross-origin access rule for an Amazon S3 bucket."""

    ID: Optional[ID]
    AllowedHeaders: Optional[AllowedHeaders]
    AllowedMethods: AllowedMethods
    AllowedOrigins: AllowedOrigins
    ExposeHeaders: Optional[ExposeHeaders]
    MaxAgeSeconds: Optional[MaxAgeSeconds]


CORSRules = List[CORSRule]


class CORSConfiguration(TypedDict, total=False):
    """Describes the cross-origin access configuration for objects in an Amazon
    S3 bucket. For more information, see `Enabling Cross-Origin Resource
    Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`__
    in the *Amazon S3 User Guide*.
    """

    CORSRules: CORSRules


class CSVInput(TypedDict, total=False):
    """Describes how an uncompressed comma-separated values (CSV)-formatted
    input object is formatted.
    """

    FileHeaderInfo: Optional[FileHeaderInfo]
    Comments: Optional[Comments]
    QuoteEscapeCharacter: Optional[QuoteEscapeCharacter]
    RecordDelimiter: Optional[RecordDelimiter]
    FieldDelimiter: Optional[FieldDelimiter]
    QuoteCharacter: Optional[QuoteCharacter]
    AllowQuotedRecordDelimiter: Optional[AllowQuotedRecordDelimiter]


class CSVOutput(TypedDict, total=False):
    """Describes how uncompressed comma-separated values (CSV)-formatted
    results are formatted.
    """

    QuoteFields: Optional[QuoteFields]
    QuoteEscapeCharacter: Optional[QuoteEscapeCharacter]
    RecordDelimiter: Optional[RecordDelimiter]
    FieldDelimiter: Optional[FieldDelimiter]
    QuoteCharacter: Optional[QuoteCharacter]


class Checksum(TypedDict, total=False):
    """Contains all the possible checksum or digest values for an object."""

    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]


ChecksumAlgorithmList = List[ChecksumAlgorithm]
EventList = List[Event]


class CloudFunctionConfiguration(TypedDict, total=False):
    """Container for specifying the Lambda notification configuration."""

    Id: Optional[NotificationId]
    Event: Optional[Event]
    Events: Optional[EventList]
    CloudFunction: Optional[CloudFunction]
    InvocationRole: Optional[CloudFunctionInvocationRole]


class CommonPrefix(TypedDict, total=False):
    """Container for all (if there are any) keys between Prefix and the next
    occurrence of the string specified by a delimiter. CommonPrefixes lists
    keys that act like subdirectories in the directory specified by Prefix.
    For example, if the prefix is notes/ and the delimiter is a slash (/) as
    in notes/summer/july, the common prefix is notes/summer/.
    """

    Prefix: Optional[Prefix]


CommonPrefixList = List[CommonPrefix]


class CompleteMultipartUploadOutput(TypedDict, total=False):
    Location: Optional[Location]
    Bucket: Optional[BucketName]
    Key: Optional[ObjectKey]
    Expiration: Optional[Expiration]
    ETag: Optional[ETag]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    ServerSideEncryption: Optional[ServerSideEncryption]
    VersionId: Optional[ObjectVersionId]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestCharged: Optional[RequestCharged]


class CompletedPart(TypedDict, total=False):
    """Details of the parts that were uploaded."""

    ETag: Optional[ETag]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    PartNumber: Optional[PartNumber]


CompletedPartList = List[CompletedPart]


class CompletedMultipartUpload(TypedDict, total=False):
    """The container for the completed multipart upload details."""

    Parts: Optional[CompletedPartList]


class CompleteMultipartUploadRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    MultipartUpload: Optional[CompletedMultipartUpload]
    UploadId: MultipartUploadId
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]


class Condition(TypedDict, total=False):
    """A container for describing a condition that must be met for the
    specified redirect to apply. For example, 1. If request is for pages in
    the ``/docs`` folder, redirect to the ``/documents`` folder. 2. If
    request results in HTTP error 4xx, redirect request to another host
    where you might process the error.
    """

    HttpErrorCodeReturnedEquals: Optional[HttpErrorCodeReturnedEquals]
    KeyPrefixEquals: Optional[KeyPrefixEquals]


ContentLength = int


class ContinuationEvent(TypedDict, total=False):
    pass


LastModified = datetime


class CopyObjectResult(TypedDict, total=False):
    """Container for all response elements."""

    ETag: Optional[ETag]
    LastModified: Optional[LastModified]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]


class CopyObjectOutput(TypedDict, total=False):
    CopyObjectResult: Optional[CopyObjectResult]
    Expiration: Optional[Expiration]
    CopySourceVersionId: Optional[CopySourceVersionId]
    VersionId: Optional[ObjectVersionId]
    ServerSideEncryption: Optional[ServerSideEncryption]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestCharged: Optional[RequestCharged]


ObjectLockRetainUntilDate = datetime
Metadata = Dict[MetadataKey, MetadataValue]
Expires = datetime
CopySourceIfUnmodifiedSince = datetime
CopySourceIfModifiedSince = datetime


class CopyObjectRequest(ServiceRequest):
    ACL: Optional[ObjectCannedACL]
    Bucket: BucketName
    CacheControl: Optional[CacheControl]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ContentDisposition: Optional[ContentDisposition]
    ContentEncoding: Optional[ContentEncoding]
    ContentLanguage: Optional[ContentLanguage]
    ContentType: Optional[ContentType]
    CopySource: CopySource
    CopySourceIfMatch: Optional[CopySourceIfMatch]
    CopySourceIfModifiedSince: Optional[CopySourceIfModifiedSince]
    CopySourceIfNoneMatch: Optional[CopySourceIfNoneMatch]
    CopySourceIfUnmodifiedSince: Optional[CopySourceIfUnmodifiedSince]
    Expires: Optional[Expires]
    GrantFullControl: Optional[GrantFullControl]
    GrantRead: Optional[GrantRead]
    GrantReadACP: Optional[GrantReadACP]
    GrantWriteACP: Optional[GrantWriteACP]
    Key: ObjectKey
    Metadata: Optional[Metadata]
    MetadataDirective: Optional[MetadataDirective]
    TaggingDirective: Optional[TaggingDirective]
    ServerSideEncryption: Optional[ServerSideEncryption]
    StorageClass: Optional[StorageClass]
    WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    CopySourceSSECustomerAlgorithm: Optional[CopySourceSSECustomerAlgorithm]
    CopySourceSSECustomerKey: Optional[CopySourceSSECustomerKey]
    CopySourceSSECustomerKeyMD5: Optional[CopySourceSSECustomerKeyMD5]
    RequestPayer: Optional[RequestPayer]
    Tagging: Optional[TaggingHeader]
    ObjectLockMode: Optional[ObjectLockMode]
    ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
    ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]
    ExpectedBucketOwner: Optional[AccountId]
    ExpectedSourceBucketOwner: Optional[AccountId]


class CopyPartResult(TypedDict, total=False):
    """Container for all response elements."""

    ETag: Optional[ETag]
    LastModified: Optional[LastModified]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]


class CreateBucketConfiguration(TypedDict, total=False):
    """The configuration information for the bucket."""

    LocationConstraint: Optional[BucketLocationConstraint]


class CreateBucketOutput(TypedDict, total=False):
    Location: Optional[Location]


class CreateBucketRequest(ServiceRequest):
    ACL: Optional[BucketCannedACL]
    Bucket: BucketName
    CreateBucketConfiguration: Optional[CreateBucketConfiguration]
    GrantFullControl: Optional[GrantFullControl]
    GrantRead: Optional[GrantRead]
    GrantReadACP: Optional[GrantReadACP]
    GrantWrite: Optional[GrantWrite]
    GrantWriteACP: Optional[GrantWriteACP]
    ObjectLockEnabledForBucket: Optional[ObjectLockEnabledForBucket]
    ObjectOwnership: Optional[ObjectOwnership]


class CreateMultipartUploadOutput(TypedDict, total=False):
    AbortDate: Optional[AbortDate]
    AbortRuleId: Optional[AbortRuleId]
    Bucket: Optional[BucketName]
    Key: Optional[ObjectKey]
    UploadId: Optional[MultipartUploadId]
    ServerSideEncryption: Optional[ServerSideEncryption]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestCharged: Optional[RequestCharged]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]


class CreateMultipartUploadRequest(ServiceRequest):
    ACL: Optional[ObjectCannedACL]
    Bucket: BucketName
    CacheControl: Optional[CacheControl]
    ContentDisposition: Optional[ContentDisposition]
    ContentEncoding: Optional[ContentEncoding]
    ContentLanguage: Optional[ContentLanguage]
    ContentType: Optional[ContentType]
    Expires: Optional[Expires]
    GrantFullControl: Optional[GrantFullControl]
    GrantRead: Optional[GrantRead]
    GrantReadACP: Optional[GrantReadACP]
    GrantWriteACP: Optional[GrantWriteACP]
    Key: ObjectKey
    Metadata: Optional[Metadata]
    ServerSideEncryption: Optional[ServerSideEncryption]
    StorageClass: Optional[StorageClass]
    WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestPayer: Optional[RequestPayer]
    Tagging: Optional[TaggingHeader]
    ObjectLockMode: Optional[ObjectLockMode]
    ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
    ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]
    ExpectedBucketOwner: Optional[AccountId]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]


class DefaultRetention(TypedDict, total=False):
    """The container element for specifying the default Object Lock retention
    settings for new objects placed in the specified bucket.

    -  The ``DefaultRetention`` settings require both a mode and a period.

    -  The ``DefaultRetention`` period can be either ``Days`` or ``Years``
       but you must select one. You cannot specify ``Days`` and ``Years`` at
       the same time.
    """

    Mode: Optional[ObjectLockRetentionMode]
    Days: Optional[Days]
    Years: Optional[Years]


class ObjectIdentifier(TypedDict, total=False):
    """Object Identifier is unique value to identify objects."""

    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]


ObjectIdentifierList = List[ObjectIdentifier]


class Delete(TypedDict, total=False):
    """Container for the objects to delete."""

    Objects: ObjectIdentifierList
    Quiet: Optional[Quiet]


class DeleteBucketAnalyticsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: AnalyticsId
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketCorsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketEncryptionRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketIntelligentTieringConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: IntelligentTieringId


class DeleteBucketInventoryConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: InventoryId
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketLifecycleRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketMetricsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: MetricsId
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketOwnershipControlsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketPolicyRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketReplicationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketTaggingRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteBucketWebsiteRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class DeleteMarkerEntry(TypedDict, total=False):
    """Information about the delete marker."""

    Owner: Optional[Owner]
    Key: Optional[ObjectKey]
    VersionId: Optional[ObjectVersionId]
    IsLatest: Optional[IsLatest]
    LastModified: Optional[LastModified]


class DeleteMarkerReplication(TypedDict, total=False):
    """Specifies whether Amazon S3 replicates delete markers. If you specify a
    ``Filter`` in your replication configuration, you must also include a
    ``DeleteMarkerReplication`` element. If your ``Filter`` includes a
    ``Tag`` element, the ``DeleteMarkerReplication`` ``Status`` must be set
    to Disabled, because Amazon S3 does not support replicating delete
    markers for tag-based rules. For an example configuration, see `Basic
    Rule
    Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-config-min-rule-config>`__.

    For more information about delete marker replication, see `Basic Rule
    Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/delete-marker-replication.html>`__.

    If you are using an earlier version of the replication configuration,
    Amazon S3 handles replication of delete markers differently. For more
    information, see `Backward
    Compatibility <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-backward-compat-considerations>`__.
    """

    Status: Optional[DeleteMarkerReplicationStatus]


DeleteMarkers = List[DeleteMarkerEntry]


class DeleteObjectOutput(TypedDict, total=False):
    DeleteMarker: Optional[DeleteMarker]
    VersionId: Optional[ObjectVersionId]
    RequestCharged: Optional[RequestCharged]


class DeleteObjectRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    MFA: Optional[MFA]
    VersionId: Optional[ObjectVersionId]
    RequestPayer: Optional[RequestPayer]
    BypassGovernanceRetention: Optional[BypassGovernanceRetention]
    ExpectedBucketOwner: Optional[AccountId]


class DeleteObjectTaggingOutput(TypedDict, total=False):
    VersionId: Optional[ObjectVersionId]


class DeleteObjectTaggingRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    ExpectedBucketOwner: Optional[AccountId]


class Error(TypedDict, total=False):
    """Container for all error elements."""

    Key: Optional[ObjectKey]
    VersionId: Optional[ObjectVersionId]
    Code: Optional[Code]
    Message: Optional[Message]


Errors = List[Error]


class DeletedObject(TypedDict, total=False):
    """Information about the deleted object."""

    Key: Optional[ObjectKey]
    VersionId: Optional[ObjectVersionId]
    DeleteMarker: Optional[DeleteMarker]
    DeleteMarkerVersionId: Optional[DeleteMarkerVersionId]


DeletedObjects = List[DeletedObject]


class DeleteObjectsOutput(TypedDict, total=False):
    Deleted: Optional[DeletedObjects]
    RequestCharged: Optional[RequestCharged]
    Errors: Optional[Errors]


class DeleteObjectsRequest(ServiceRequest):
    Bucket: BucketName
    Delete: Delete
    MFA: Optional[MFA]
    RequestPayer: Optional[RequestPayer]
    BypassGovernanceRetention: Optional[BypassGovernanceRetention]
    ExpectedBucketOwner: Optional[AccountId]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]


class DeletePublicAccessBlockRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class ReplicationTimeValue(TypedDict, total=False):
    """A container specifying the time value for S3 Replication Time Control
    (S3 RTC) and replication metrics ``EventThreshold``.
    """

    Minutes: Optional[Minutes]


class Metrics(TypedDict, total=False):
    """A container specifying replication metrics-related settings enabling
    replication metrics and events.
    """

    Status: MetricsStatus
    EventThreshold: Optional[ReplicationTimeValue]


class ReplicationTime(TypedDict, total=False):
    """A container specifying S3 Replication Time Control (S3 RTC) related
    information, including whether S3 RTC is enabled and the time when all
    objects and operations on objects must be replicated. Must be specified
    together with a ``Metrics`` block.
    """

    Status: ReplicationTimeStatus
    Time: ReplicationTimeValue


class EncryptionConfiguration(TypedDict, total=False):
    """Specifies encryption-related information for an Amazon S3 bucket that is
    a destination for replicated objects.
    """

    ReplicaKmsKeyID: Optional[ReplicaKmsKeyID]


class Destination(TypedDict, total=False):
    """Specifies information about where to publish analysis or configuration
    results for an Amazon S3 bucket and S3 Replication Time Control (S3
    RTC).
    """

    Bucket: BucketName
    Account: Optional[AccountId]
    StorageClass: Optional[StorageClass]
    AccessControlTranslation: Optional[AccessControlTranslation]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    ReplicationTime: Optional[ReplicationTime]
    Metrics: Optional[Metrics]


class Encryption(TypedDict, total=False):
    """Contains the type of server-side encryption used."""

    EncryptionType: ServerSideEncryption
    KMSKeyId: Optional[SSEKMSKeyId]
    KMSContext: Optional[KMSContext]


End = int


class EndEvent(TypedDict, total=False):
    """A message that indicates the request is complete and no more messages
    will be sent. You should not assume that the request is complete until
    the client receives an ``EndEvent``.
    """


class ErrorDocument(TypedDict, total=False):
    """The error information."""

    Key: ObjectKey


class EventBridgeConfiguration(TypedDict, total=False):
    """A container for specifying the configuration for Amazon EventBridge."""


class ExistingObjectReplication(TypedDict, total=False):
    """Optional configuration to replicate existing source bucket objects. For
    more information, see `Replicating Existing
    Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-what-is-isnot-replicated.html#existing-object-replication>`__
    in the *Amazon S3 User Guide*.
    """

    Status: ExistingObjectReplicationStatus


class FilterRule(TypedDict, total=False):
    """Specifies the Amazon S3 object key name to filter on and whether to
    filter on the suffix or prefix of the key name.
    """

    Name: Optional[FilterRuleName]
    Value: Optional[FilterRuleValue]


FilterRuleList = List[FilterRule]


class GetBucketAccelerateConfigurationOutput(TypedDict, total=False):
    Status: Optional[BucketAccelerateStatus]


class GetBucketAccelerateConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketAclOutput(TypedDict, total=False):
    Owner: Optional[Owner]
    Grants: Optional[Grants]


class GetBucketAclRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketAnalyticsConfigurationOutput(TypedDict, total=False):
    AnalyticsConfiguration: Optional[AnalyticsConfiguration]


class GetBucketAnalyticsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: AnalyticsId
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketCorsOutput(TypedDict, total=False):
    CORSRules: Optional[CORSRules]


class GetBucketCorsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class ServerSideEncryptionByDefault(TypedDict, total=False):
    """Describes the default server-side encryption to apply to new objects in
    the bucket. If a PUT Object request doesn't specify any server-side
    encryption, this default encryption will be applied. If you don't
    specify a customer managed key at configuration, Amazon S3 automatically
    creates an Amazon Web Services KMS key in your Amazon Web Services
    account the first time that you add an object encrypted with SSE-KMS to
    a bucket. By default, Amazon S3 uses this KMS key for SSE-KMS. For more
    information, see `PUT Bucket
    encryption <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTencryption.html>`__
    in the *Amazon S3 API Reference*.
    """

    SSEAlgorithm: ServerSideEncryption
    KMSMasterKeyID: Optional[SSEKMSKeyId]


class ServerSideEncryptionRule(TypedDict, total=False):
    """Specifies the default server-side encryption configuration."""

    ApplyServerSideEncryptionByDefault: Optional[ServerSideEncryptionByDefault]
    BucketKeyEnabled: Optional[BucketKeyEnabled]


ServerSideEncryptionRules = List[ServerSideEncryptionRule]


class ServerSideEncryptionConfiguration(TypedDict, total=False):
    """Specifies the default server-side-encryption configuration."""

    Rules: ServerSideEncryptionRules


class GetBucketEncryptionOutput(TypedDict, total=False):
    ServerSideEncryptionConfiguration: Optional[ServerSideEncryptionConfiguration]


class GetBucketEncryptionRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class Tiering(TypedDict, total=False):
    """The S3 Intelligent-Tiering storage class is designed to optimize storage
    costs by automatically moving data to the most cost-effective storage
    access tier, without additional operational overhead.
    """

    Days: IntelligentTieringDays
    AccessTier: IntelligentTieringAccessTier


TieringList = List[Tiering]


class IntelligentTieringAndOperator(TypedDict, total=False):
    """A container for specifying S3 Intelligent-Tiering filters. The filters
    determine the subset of objects to which the rule applies.
    """

    Prefix: Optional[Prefix]
    Tags: Optional[TagSet]


class IntelligentTieringFilter(TypedDict, total=False):
    """The ``Filter`` is used to identify objects that the S3
    Intelligent-Tiering configuration applies to.
    """

    Prefix: Optional[Prefix]
    Tag: Optional[Tag]
    And: Optional[IntelligentTieringAndOperator]


class IntelligentTieringConfiguration(TypedDict, total=False):
    """Specifies the S3 Intelligent-Tiering configuration for an Amazon S3
    bucket.

    For information about the S3 Intelligent-Tiering storage class, see
    `Storage class for automatically optimizing frequently and infrequently
    accessed
    objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`__.
    """

    Id: IntelligentTieringId
    Filter: Optional[IntelligentTieringFilter]
    Status: IntelligentTieringStatus
    Tierings: TieringList


class GetBucketIntelligentTieringConfigurationOutput(TypedDict, total=False):
    IntelligentTieringConfiguration: Optional[IntelligentTieringConfiguration]


class GetBucketIntelligentTieringConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: IntelligentTieringId


class InventorySchedule(TypedDict, total=False):
    """Specifies the schedule for generating inventory results."""

    Frequency: InventoryFrequency


InventoryOptionalFields = List[InventoryOptionalField]


class InventoryFilter(TypedDict, total=False):
    """Specifies an inventory filter. The inventory only includes objects that
    meet the filter's criteria.
    """

    Prefix: Prefix


class SSEKMS(TypedDict, total=False):
    """Specifies the use of SSE-KMS to encrypt delivered inventory reports."""

    KeyId: SSEKMSKeyId


class SSES3(TypedDict, total=False):
    """Specifies the use of SSE-S3 to encrypt delivered inventory reports."""


class InventoryEncryption(TypedDict, total=False):
    """Contains the type of server-side encryption used to encrypt the
    inventory results.
    """

    SSES3: Optional[SSES3]
    SSEKMS: Optional[SSEKMS]


class InventoryS3BucketDestination(TypedDict, total=False):
    """Contains the bucket name, file format, bucket owner (optional), and
    prefix (optional) where inventory results are published.
    """

    AccountId: Optional[AccountId]
    Bucket: BucketName
    Format: InventoryFormat
    Prefix: Optional[Prefix]
    Encryption: Optional[InventoryEncryption]


class InventoryDestination(TypedDict, total=False):
    """Specifies the inventory configuration for an Amazon S3 bucket."""

    S3BucketDestination: InventoryS3BucketDestination


class InventoryConfiguration(TypedDict, total=False):
    """Specifies the inventory configuration for an Amazon S3 bucket. For more
    information, see `GET Bucket
    inventory <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html>`__
    in the *Amazon S3 API Reference*.
    """

    Destination: InventoryDestination
    IsEnabled: IsEnabled
    Filter: Optional[InventoryFilter]
    Id: InventoryId
    IncludedObjectVersions: InventoryIncludedObjectVersions
    OptionalFields: Optional[InventoryOptionalFields]
    Schedule: InventorySchedule


class GetBucketInventoryConfigurationOutput(TypedDict, total=False):
    InventoryConfiguration: Optional[InventoryConfiguration]


class GetBucketInventoryConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: InventoryId
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketLifecycleConfigurationOutput(TypedDict, total=False):
    Rules: Optional[LifecycleRules]


class GetBucketLifecycleConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class Rule(TypedDict, total=False):
    """Specifies lifecycle rules for an Amazon S3 bucket. For more information,
    see `Put Bucket Lifecycle
    Configuration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlifecycle.html>`__
    in the *Amazon S3 API Reference*. For examples, see `Put Bucket
    Lifecycle Configuration
    Examples <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html#API_PutBucketLifecycleConfiguration_Examples>`__.
    """

    Expiration: Optional[LifecycleExpiration]
    ID: Optional[ID]
    Prefix: Prefix
    Status: ExpirationStatus
    Transition: Optional[Transition]
    NoncurrentVersionTransition: Optional[NoncurrentVersionTransition]
    NoncurrentVersionExpiration: Optional[NoncurrentVersionExpiration]
    AbortIncompleteMultipartUpload: Optional[AbortIncompleteMultipartUpload]


Rules = List[Rule]


class GetBucketLifecycleOutput(TypedDict, total=False):
    Rules: Optional[Rules]


class GetBucketLifecycleRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketLocationOutput(TypedDict, total=False):
    LocationConstraint: Optional[BucketLocationConstraint]


class GetBucketLocationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketLoggingOutput(TypedDict, total=False):
    LoggingEnabled: Optional[LoggingEnabled]


class GetBucketLoggingRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class MetricsAndOperator(TypedDict, total=False):
    """A conjunction (logical AND) of predicates, which is used in evaluating a
    metrics filter. The operator must have at least two predicates, and an
    object must match all of the predicates in order for the filter to
    apply.
    """

    Prefix: Optional[Prefix]
    Tags: Optional[TagSet]
    AccessPointArn: Optional[AccessPointArn]


class MetricsFilter(TypedDict, total=False):
    """Specifies a metrics configuration filter. The metrics configuration only
    includes objects that meet the filter's criteria. A filter must be a
    prefix, an object tag, an access point ARN, or a conjunction
    (MetricsAndOperator). For more information, see
    `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketMetricsConfiguration.html>`__.
    """

    Prefix: Optional[Prefix]
    Tag: Optional[Tag]
    AccessPointArn: Optional[AccessPointArn]
    And: Optional[MetricsAndOperator]


class MetricsConfiguration(TypedDict, total=False):
    """Specifies a metrics configuration for the CloudWatch request metrics
    (specified by the metrics configuration ID) from an Amazon S3 bucket. If
    you're updating an existing metrics configuration, note that this is a
    full replacement of the existing metrics configuration. If you don't
    include the elements you want to keep, they are erased. For more
    information, see
    `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html>`__.
    """

    Id: MetricsId
    Filter: Optional[MetricsFilter]


class GetBucketMetricsConfigurationOutput(TypedDict, total=False):
    MetricsConfiguration: Optional[MetricsConfiguration]


class GetBucketMetricsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: MetricsId
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketNotificationConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class OwnershipControlsRule(TypedDict, total=False):
    """The container element for an ownership control rule."""

    ObjectOwnership: ObjectOwnership


OwnershipControlsRules = List[OwnershipControlsRule]


class OwnershipControls(TypedDict, total=False):
    """The container element for a bucket's ownership controls."""

    Rules: OwnershipControlsRules


class GetBucketOwnershipControlsOutput(TypedDict, total=False):
    OwnershipControls: Optional[OwnershipControls]


class GetBucketOwnershipControlsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketPolicyOutput(TypedDict, total=False):
    Policy: Optional[Policy]


class GetBucketPolicyRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class PolicyStatus(TypedDict, total=False):
    """The container element for a bucket's policy status."""

    IsPublic: Optional[IsPublic]


class GetBucketPolicyStatusOutput(TypedDict, total=False):
    PolicyStatus: Optional[PolicyStatus]


class GetBucketPolicyStatusRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class ReplicaModifications(TypedDict, total=False):
    """A filter that you can specify for selection for modifications on
    replicas. Amazon S3 doesn't replicate replica modifications by default.
    In the latest version of replication configuration (when ``Filter`` is
    specified), you can specify this element and set the status to
    ``Enabled`` to replicate modifications on replicas.

    If you don't specify the ``Filter`` element, Amazon S3 assumes that the
    replication configuration is the earlier version, V1. In the earlier
    version, this element is not allowed.
    """

    Status: ReplicaModificationsStatus


class SseKmsEncryptedObjects(TypedDict, total=False):
    """A container for filter information for the selection of S3 objects
    encrypted with Amazon Web Services KMS.
    """

    Status: SseKmsEncryptedObjectsStatus


class SourceSelectionCriteria(TypedDict, total=False):
    """A container that describes additional filters for identifying the source
    objects that you want to replicate. You can choose to enable or disable
    the replication of these objects. Currently, Amazon S3 supports only the
    filter that you can specify for objects created with server-side
    encryption using a customer managed key stored in Amazon Web Services
    Key Management Service (SSE-KMS).
    """

    SseKmsEncryptedObjects: Optional[SseKmsEncryptedObjects]
    ReplicaModifications: Optional[ReplicaModifications]


class ReplicationRuleAndOperator(TypedDict, total=False):
    """A container for specifying rule filters. The filters determine the
    subset of objects to which the rule applies. This element is required
    only if you specify more than one filter.

    For example:

    -  If you specify both a ``Prefix`` and a ``Tag`` filter, wrap these
       filters in an ``And`` tag.

    -  If you specify a filter based on multiple tags, wrap the ``Tag``
       elements in an ``And`` tag.
    """

    Prefix: Optional[Prefix]
    Tags: Optional[TagSet]


class ReplicationRuleFilter(TypedDict, total=False):
    """A filter that identifies the subset of objects to which the replication
    rule applies. A ``Filter`` must specify exactly one ``Prefix``, ``Tag``,
    or an ``And`` child element.
    """

    Prefix: Optional[Prefix]
    Tag: Optional[Tag]
    And: Optional[ReplicationRuleAndOperator]


class ReplicationRule(TypedDict, total=False):
    """Specifies which Amazon S3 objects to replicate and where to store the
    replicas.
    """

    ID: Optional[ID]
    Priority: Optional[Priority]
    Prefix: Optional[Prefix]
    Filter: Optional[ReplicationRuleFilter]
    Status: ReplicationRuleStatus
    SourceSelectionCriteria: Optional[SourceSelectionCriteria]
    ExistingObjectReplication: Optional[ExistingObjectReplication]
    Destination: Destination
    DeleteMarkerReplication: Optional[DeleteMarkerReplication]


ReplicationRules = List[ReplicationRule]


class ReplicationConfiguration(TypedDict, total=False):
    """A container for replication rules. You can add up to 1,000 rules. The
    maximum size of a replication configuration is 2 MB.
    """

    Role: Role
    Rules: ReplicationRules


class GetBucketReplicationOutput(TypedDict, total=False):
    ReplicationConfiguration: Optional[ReplicationConfiguration]


class GetBucketReplicationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketRequestPaymentOutput(TypedDict, total=False):
    Payer: Optional[Payer]


class GetBucketRequestPaymentRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketTaggingOutput(TypedDict, total=False):
    TagSet: TagSet


class GetBucketTaggingRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetBucketVersioningOutput(TypedDict, total=False):
    Status: Optional[BucketVersioningStatus]
    MFADelete: Optional[MFADeleteStatus]


class GetBucketVersioningRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class Redirect(TypedDict, total=False):
    """Specifies how requests are redirected. In the event of an error, you can
    specify a different error code to return.
    """

    HostName: Optional[HostName]
    HttpRedirectCode: Optional[HttpRedirectCode]
    Protocol: Optional[Protocol]
    ReplaceKeyPrefixWith: Optional[ReplaceKeyPrefixWith]
    ReplaceKeyWith: Optional[ReplaceKeyWith]


class RoutingRule(TypedDict, total=False):
    """Specifies the redirect behavior and when a redirect is applied. For more
    information about routing rules, see `Configuring advanced conditional
    redirects <https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-page-redirect.html#advanced-conditional-redirects>`__
    in the *Amazon S3 User Guide*.
    """

    Condition: Optional[Condition]
    Redirect: Redirect


RoutingRules = List[RoutingRule]


class IndexDocument(TypedDict, total=False):
    """Container for the ``Suffix`` element."""

    Suffix: Suffix


class RedirectAllRequestsTo(TypedDict, total=False):
    """Specifies the redirect behavior of all requests to a website endpoint of
    an Amazon S3 bucket.
    """

    HostName: HostName
    Protocol: Optional[Protocol]


class GetBucketWebsiteOutput(TypedDict, total=False):
    RedirectAllRequestsTo: Optional[RedirectAllRequestsTo]
    IndexDocument: Optional[IndexDocument]
    ErrorDocument: Optional[ErrorDocument]
    RoutingRules: Optional[RoutingRules]


class GetBucketWebsiteRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetObjectAclOutput(TypedDict, total=False):
    Owner: Optional[Owner]
    Grants: Optional[Grants]
    RequestCharged: Optional[RequestCharged]


class GetObjectAclRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


ObjectSize = int


class ObjectPart(TypedDict, total=False):
    """A container for elements related to an individual part."""

    PartNumber: Optional[PartNumber]
    Size: Optional[Size]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]


PartsList = List[ObjectPart]


class GetObjectAttributesParts(TypedDict, total=False):
    """A collection of parts associated with a multipart upload."""

    TotalPartsCount: Optional[PartsCount]
    PartNumberMarker: Optional[PartNumberMarker]
    NextPartNumberMarker: Optional[NextPartNumberMarker]
    MaxParts: Optional[MaxParts]
    IsTruncated: Optional[IsTruncated]
    Parts: Optional[PartsList]


class GetObjectAttributesOutput(TypedDict, total=False):
    DeleteMarker: Optional[DeleteMarker]
    LastModified: Optional[LastModified]
    VersionId: Optional[ObjectVersionId]
    RequestCharged: Optional[RequestCharged]
    ETag: Optional[ETag]
    Checksum: Optional[Checksum]
    ObjectParts: Optional[GetObjectAttributesParts]
    StorageClass: Optional[StorageClass]
    ObjectSize: Optional[ObjectSize]


ObjectAttributesList = List[ObjectAttributes]


class GetObjectAttributesRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    MaxParts: Optional[MaxParts]
    PartNumberMarker: Optional[PartNumberMarker]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]
    ObjectAttributes: ObjectAttributesList


class ObjectLockLegalHold(TypedDict, total=False):
    """A legal hold configuration for an object."""

    Status: Optional[ObjectLockLegalHoldStatus]


class GetObjectLegalHoldOutput(TypedDict, total=False):
    LegalHold: Optional[ObjectLockLegalHold]


class GetObjectLegalHoldRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class ObjectLockRule(TypedDict, total=False):
    """The container element for an Object Lock rule."""

    DefaultRetention: Optional[DefaultRetention]


class ObjectLockConfiguration(TypedDict, total=False):
    """The container element for Object Lock configuration parameters."""

    ObjectLockEnabled: Optional[ObjectLockEnabled]
    Rule: Optional[ObjectLockRule]


class GetObjectLockConfigurationOutput(TypedDict, total=False):
    ObjectLockConfiguration: Optional[ObjectLockConfiguration]


class GetObjectLockConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GetObjectOutput(TypedDict, total=False):
    Body: Optional[Union[Body, IO[Body], Iterable[Body]]]
    DeleteMarker: Optional[DeleteMarker]
    AcceptRanges: Optional[AcceptRanges]
    Expiration: Optional[Expiration]
    Restore: Optional[Restore]
    LastModified: Optional[LastModified]
    ContentLength: Optional[ContentLength]
    ETag: Optional[ETag]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    MissingMeta: Optional[MissingMeta]
    VersionId: Optional[ObjectVersionId]
    CacheControl: Optional[CacheControl]
    ContentDisposition: Optional[ContentDisposition]
    ContentEncoding: Optional[ContentEncoding]
    ContentLanguage: Optional[ContentLanguage]
    ContentRange: Optional[ContentRange]
    ContentType: Optional[ContentType]
    Expires: Optional[Expires]
    WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
    ServerSideEncryption: Optional[ServerSideEncryption]
    Metadata: Optional[Metadata]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    StorageClass: Optional[StorageClass]
    RequestCharged: Optional[RequestCharged]
    ReplicationStatus: Optional[ReplicationStatus]
    PartsCount: Optional[PartsCount]
    TagCount: Optional[TagCount]
    ObjectLockMode: Optional[ObjectLockMode]
    ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
    ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]


ResponseExpires = datetime
IfUnmodifiedSince = datetime
IfModifiedSince = datetime


class GetObjectRequest(ServiceRequest):
    Bucket: BucketName
    IfMatch: Optional[IfMatch]
    IfModifiedSince: Optional[IfModifiedSince]
    IfNoneMatch: Optional[IfNoneMatch]
    IfUnmodifiedSince: Optional[IfUnmodifiedSince]
    Key: ObjectKey
    Range: Optional[Range]
    ResponseCacheControl: Optional[ResponseCacheControl]
    ResponseContentDisposition: Optional[ResponseContentDisposition]
    ResponseContentEncoding: Optional[ResponseContentEncoding]
    ResponseContentLanguage: Optional[ResponseContentLanguage]
    ResponseContentType: Optional[ResponseContentType]
    ResponseExpires: Optional[ResponseExpires]
    VersionId: Optional[ObjectVersionId]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    RequestPayer: Optional[RequestPayer]
    PartNumber: Optional[PartNumber]
    ExpectedBucketOwner: Optional[AccountId]
    ChecksumMode: Optional[ChecksumMode]


class ObjectLockRetention(TypedDict, total=False):
    """A Retention configuration for an object."""

    Mode: Optional[ObjectLockRetentionMode]
    RetainUntilDate: Optional[Date]


class GetObjectRetentionOutput(TypedDict, total=False):
    Retention: Optional[ObjectLockRetention]


class GetObjectRetentionRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class GetObjectTaggingOutput(TypedDict, total=False):
    VersionId: Optional[ObjectVersionId]
    TagSet: TagSet


class GetObjectTaggingRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    ExpectedBucketOwner: Optional[AccountId]
    RequestPayer: Optional[RequestPayer]


class GetObjectTorrentOutput(TypedDict, total=False):
    Body: Optional[Union[Body, IO[Body], Iterable[Body]]]
    RequestCharged: Optional[RequestCharged]


class GetObjectTorrentRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class PublicAccessBlockConfiguration(TypedDict, total=False):
    """The PublicAccessBlock configuration that you want to apply to this
    Amazon S3 bucket. You can enable the configuration options in any
    combination. For more information about when Amazon S3 considers a
    bucket or object public, see `The Meaning of
    "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`__
    in the *Amazon S3 User Guide*.
    """

    BlockPublicAcls: Optional[Setting]
    IgnorePublicAcls: Optional[Setting]
    BlockPublicPolicy: Optional[Setting]
    RestrictPublicBuckets: Optional[Setting]


class GetPublicAccessBlockOutput(TypedDict, total=False):
    PublicAccessBlockConfiguration: Optional[PublicAccessBlockConfiguration]


class GetPublicAccessBlockRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class GlacierJobParameters(TypedDict, total=False):
    """Container for S3 Glacier job parameters."""

    Tier: Tier


class HeadBucketRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: Optional[AccountId]


class HeadObjectOutput(TypedDict, total=False):
    DeleteMarker: Optional[DeleteMarker]
    AcceptRanges: Optional[AcceptRanges]
    Expiration: Optional[Expiration]
    Restore: Optional[Restore]
    ArchiveStatus: Optional[ArchiveStatus]
    LastModified: Optional[LastModified]
    ContentLength: Optional[ContentLength]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    ETag: Optional[ETag]
    MissingMeta: Optional[MissingMeta]
    VersionId: Optional[ObjectVersionId]
    CacheControl: Optional[CacheControl]
    ContentDisposition: Optional[ContentDisposition]
    ContentEncoding: Optional[ContentEncoding]
    ContentLanguage: Optional[ContentLanguage]
    ContentType: Optional[ContentType]
    Expires: Optional[Expires]
    WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
    ServerSideEncryption: Optional[ServerSideEncryption]
    Metadata: Optional[Metadata]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    StorageClass: Optional[StorageClass]
    RequestCharged: Optional[RequestCharged]
    ReplicationStatus: Optional[ReplicationStatus]
    PartsCount: Optional[PartsCount]
    ObjectLockMode: Optional[ObjectLockMode]
    ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
    ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]


class HeadObjectRequest(ServiceRequest):
    Bucket: BucketName
    IfMatch: Optional[IfMatch]
    IfModifiedSince: Optional[IfModifiedSince]
    IfNoneMatch: Optional[IfNoneMatch]
    IfUnmodifiedSince: Optional[IfUnmodifiedSince]
    Key: ObjectKey
    Range: Optional[Range]
    VersionId: Optional[ObjectVersionId]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    RequestPayer: Optional[RequestPayer]
    PartNumber: Optional[PartNumber]
    ExpectedBucketOwner: Optional[AccountId]
    ChecksumMode: Optional[ChecksumMode]


Initiated = datetime


class Initiator(TypedDict, total=False):
    """Container element that identifies who initiated the multipart upload."""

    ID: Optional[ID]
    DisplayName: Optional[DisplayName]


class ParquetInput(TypedDict, total=False):
    """Container for Parquet."""


class JSONInput(TypedDict, total=False):
    """Specifies JSON as object's input serialization format."""

    Type: Optional[JSONType]


class InputSerialization(TypedDict, total=False):
    """Describes the serialization format of the object."""

    CSV: Optional[CSVInput]
    CompressionType: Optional[CompressionType]
    JSON: Optional[JSONInput]
    Parquet: Optional[ParquetInput]


IntelligentTieringConfigurationList = List[IntelligentTieringConfiguration]
InventoryConfigurationList = List[InventoryConfiguration]


class JSONOutput(TypedDict, total=False):
    """Specifies JSON as request's output serialization format."""

    RecordDelimiter: Optional[RecordDelimiter]


class S3KeyFilter(TypedDict, total=False):
    """A container for object key name prefix and suffix filtering rules."""

    FilterRules: Optional[FilterRuleList]


class NotificationConfigurationFilter(TypedDict, total=False):
    """Specifies object key name filtering rules. For information about key
    name filtering, see `Configuring Event
    Notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`__
    in the *Amazon S3 User Guide*.
    """

    Key: Optional[S3KeyFilter]


class LambdaFunctionConfiguration(TypedDict, total=False):
    """A container for specifying the configuration for Lambda notifications."""

    Id: Optional[NotificationId]
    LambdaFunctionArn: LambdaFunctionArn
    Events: EventList
    Filter: Optional[NotificationConfigurationFilter]


LambdaFunctionConfigurationList = List[LambdaFunctionConfiguration]


class LifecycleConfiguration(TypedDict, total=False):
    """Container for lifecycle rules. You can add as many as 1000 rules."""

    Rules: Rules


class ListBucketAnalyticsConfigurationsOutput(TypedDict, total=False):
    IsTruncated: Optional[IsTruncated]
    ContinuationToken: Optional[Token]
    NextContinuationToken: Optional[NextToken]
    AnalyticsConfigurationList: Optional[AnalyticsConfigurationList]


class ListBucketAnalyticsConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Optional[Token]
    ExpectedBucketOwner: Optional[AccountId]


class ListBucketIntelligentTieringConfigurationsOutput(TypedDict, total=False):
    IsTruncated: Optional[IsTruncated]
    ContinuationToken: Optional[Token]
    NextContinuationToken: Optional[NextToken]
    IntelligentTieringConfigurationList: Optional[IntelligentTieringConfigurationList]


class ListBucketIntelligentTieringConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Optional[Token]


class ListBucketInventoryConfigurationsOutput(TypedDict, total=False):
    ContinuationToken: Optional[Token]
    InventoryConfigurationList: Optional[InventoryConfigurationList]
    IsTruncated: Optional[IsTruncated]
    NextContinuationToken: Optional[NextToken]


class ListBucketInventoryConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Optional[Token]
    ExpectedBucketOwner: Optional[AccountId]


MetricsConfigurationList = List[MetricsConfiguration]


class ListBucketMetricsConfigurationsOutput(TypedDict, total=False):
    IsTruncated: Optional[IsTruncated]
    ContinuationToken: Optional[Token]
    NextContinuationToken: Optional[NextToken]
    MetricsConfigurationList: Optional[MetricsConfigurationList]


class ListBucketMetricsConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Optional[Token]
    ExpectedBucketOwner: Optional[AccountId]


class ListBucketsOutput(TypedDict, total=False):
    Buckets: Optional[Buckets]
    Owner: Optional[Owner]


class MultipartUpload(TypedDict, total=False):
    """Container for the ``MultipartUpload`` for the Amazon S3 object."""

    UploadId: Optional[MultipartUploadId]
    Key: Optional[ObjectKey]
    Initiated: Optional[Initiated]
    StorageClass: Optional[StorageClass]
    Owner: Optional[Owner]
    Initiator: Optional[Initiator]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]


MultipartUploadList = List[MultipartUpload]


class ListMultipartUploadsOutput(TypedDict, total=False):
    Bucket: Optional[BucketName]
    KeyMarker: Optional[KeyMarker]
    UploadIdMarker: Optional[UploadIdMarker]
    NextKeyMarker: Optional[NextKeyMarker]
    Prefix: Optional[Prefix]
    Delimiter: Optional[Delimiter]
    NextUploadIdMarker: Optional[NextUploadIdMarker]
    MaxUploads: Optional[MaxUploads]
    IsTruncated: Optional[IsTruncated]
    Uploads: Optional[MultipartUploadList]
    CommonPrefixes: Optional[CommonPrefixList]
    EncodingType: Optional[EncodingType]


class ListMultipartUploadsRequest(ServiceRequest):
    Bucket: BucketName
    Delimiter: Optional[Delimiter]
    EncodingType: Optional[EncodingType]
    KeyMarker: Optional[KeyMarker]
    MaxUploads: Optional[MaxUploads]
    Prefix: Optional[Prefix]
    UploadIdMarker: Optional[UploadIdMarker]
    ExpectedBucketOwner: Optional[AccountId]


class ObjectVersion(TypedDict, total=False):
    """The version of an object."""

    ETag: Optional[ETag]
    ChecksumAlgorithm: Optional[ChecksumAlgorithmList]
    Size: Optional[Size]
    StorageClass: Optional[ObjectVersionStorageClass]
    Key: Optional[ObjectKey]
    VersionId: Optional[ObjectVersionId]
    IsLatest: Optional[IsLatest]
    LastModified: Optional[LastModified]
    Owner: Optional[Owner]


ObjectVersionList = List[ObjectVersion]


class ListObjectVersionsOutput(TypedDict, total=False):
    IsTruncated: Optional[IsTruncated]
    KeyMarker: Optional[KeyMarker]
    VersionIdMarker: Optional[VersionIdMarker]
    NextKeyMarker: Optional[NextKeyMarker]
    NextVersionIdMarker: Optional[NextVersionIdMarker]
    Versions: Optional[ObjectVersionList]
    DeleteMarkers: Optional[DeleteMarkers]
    Name: Optional[BucketName]
    Prefix: Optional[Prefix]
    Delimiter: Optional[Delimiter]
    MaxKeys: Optional[MaxKeys]
    CommonPrefixes: Optional[CommonPrefixList]
    EncodingType: Optional[EncodingType]


class ListObjectVersionsRequest(ServiceRequest):
    Bucket: BucketName
    Delimiter: Optional[Delimiter]
    EncodingType: Optional[EncodingType]
    KeyMarker: Optional[KeyMarker]
    MaxKeys: Optional[MaxKeys]
    Prefix: Optional[Prefix]
    VersionIdMarker: Optional[VersionIdMarker]
    ExpectedBucketOwner: Optional[AccountId]


class Object(TypedDict, total=False):
    """An object consists of data and its descriptive metadata."""

    Key: Optional[ObjectKey]
    LastModified: Optional[LastModified]
    ETag: Optional[ETag]
    ChecksumAlgorithm: Optional[ChecksumAlgorithmList]
    Size: Optional[Size]
    StorageClass: Optional[ObjectStorageClass]
    Owner: Optional[Owner]


ObjectList = List[Object]


class ListObjectsOutput(TypedDict, total=False):
    IsTruncated: Optional[IsTruncated]
    Marker: Optional[Marker]
    NextMarker: Optional[NextMarker]
    Contents: Optional[ObjectList]
    Name: Optional[BucketName]
    Prefix: Optional[Prefix]
    Delimiter: Optional[Delimiter]
    MaxKeys: Optional[MaxKeys]
    CommonPrefixes: Optional[CommonPrefixList]
    EncodingType: Optional[EncodingType]


class ListObjectsRequest(ServiceRequest):
    Bucket: BucketName
    Delimiter: Optional[Delimiter]
    EncodingType: Optional[EncodingType]
    Marker: Optional[Marker]
    MaxKeys: Optional[MaxKeys]
    Prefix: Optional[Prefix]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class ListObjectsV2Output(TypedDict, total=False):
    IsTruncated: Optional[IsTruncated]
    Contents: Optional[ObjectList]
    Name: Optional[BucketName]
    Prefix: Optional[Prefix]
    Delimiter: Optional[Delimiter]
    MaxKeys: Optional[MaxKeys]
    CommonPrefixes: Optional[CommonPrefixList]
    EncodingType: Optional[EncodingType]
    KeyCount: Optional[KeyCount]
    ContinuationToken: Optional[Token]
    NextContinuationToken: Optional[NextToken]
    StartAfter: Optional[StartAfter]


class ListObjectsV2Request(ServiceRequest):
    Bucket: BucketName
    Delimiter: Optional[Delimiter]
    EncodingType: Optional[EncodingType]
    MaxKeys: Optional[MaxKeys]
    Prefix: Optional[Prefix]
    ContinuationToken: Optional[Token]
    FetchOwner: Optional[FetchOwner]
    StartAfter: Optional[StartAfter]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class Part(TypedDict, total=False):
    """Container for elements related to a part."""

    PartNumber: Optional[PartNumber]
    LastModified: Optional[LastModified]
    ETag: Optional[ETag]
    Size: Optional[Size]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]


Parts = List[Part]


class ListPartsOutput(TypedDict, total=False):
    AbortDate: Optional[AbortDate]
    AbortRuleId: Optional[AbortRuleId]
    Bucket: Optional[BucketName]
    Key: Optional[ObjectKey]
    UploadId: Optional[MultipartUploadId]
    PartNumberMarker: Optional[PartNumberMarker]
    NextPartNumberMarker: Optional[NextPartNumberMarker]
    MaxParts: Optional[MaxParts]
    IsTruncated: Optional[IsTruncated]
    Parts: Optional[Parts]
    Initiator: Optional[Initiator]
    Owner: Optional[Owner]
    StorageClass: Optional[StorageClass]
    RequestCharged: Optional[RequestCharged]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]


class ListPartsRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    MaxParts: Optional[MaxParts]
    PartNumberMarker: Optional[PartNumberMarker]
    UploadId: MultipartUploadId
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]


class MetadataEntry(TypedDict, total=False):
    """A metadata key-value pair to store with an object."""

    Name: Optional[MetadataKey]
    Value: Optional[MetadataValue]


class QueueConfiguration(TypedDict, total=False):
    """Specifies the configuration for publishing messages to an Amazon Simple
    Queue Service (Amazon SQS) queue when Amazon S3 detects specified
    events.
    """

    Id: Optional[NotificationId]
    QueueArn: QueueArn
    Events: EventList
    Filter: Optional[NotificationConfigurationFilter]


QueueConfigurationList = List[QueueConfiguration]


class TopicConfiguration(TypedDict, total=False):
    """A container for specifying the configuration for publication of messages
    to an Amazon Simple Notification Service (Amazon SNS) topic when Amazon
    S3 detects specified events.
    """

    Id: Optional[NotificationId]
    TopicArn: TopicArn
    Events: EventList
    Filter: Optional[NotificationConfigurationFilter]


TopicConfigurationList = List[TopicConfiguration]


class NotificationConfiguration(TypedDict, total=False):
    """A container for specifying the notification configuration of the bucket.
    If this element is empty, notifications are turned off for the bucket.
    """

    TopicConfigurations: Optional[TopicConfigurationList]
    QueueConfigurations: Optional[QueueConfigurationList]
    LambdaFunctionConfigurations: Optional[LambdaFunctionConfigurationList]
    EventBridgeConfiguration: Optional[EventBridgeConfiguration]


class QueueConfigurationDeprecated(TypedDict, total=False):
    """This data type is deprecated. Use
    `QueueConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_QueueConfiguration.html>`__
    for the same purposes. This data type specifies the configuration for
    publishing messages to an Amazon Simple Queue Service (Amazon SQS) queue
    when Amazon S3 detects specified events.
    """

    Id: Optional[NotificationId]
    Event: Optional[Event]
    Events: Optional[EventList]
    Queue: Optional[QueueArn]


class TopicConfigurationDeprecated(TypedDict, total=False):
    """A container for specifying the configuration for publication of messages
    to an Amazon Simple Notification Service (Amazon SNS) topic when Amazon
    S3 detects specified events. This data type is deprecated. Use
    `TopicConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_TopicConfiguration.html>`__
    instead.
    """

    Id: Optional[NotificationId]
    Events: Optional[EventList]
    Event: Optional[Event]
    Topic: Optional[TopicArn]


class NotificationConfigurationDeprecated(TypedDict, total=False):
    TopicConfiguration: Optional[TopicConfigurationDeprecated]
    QueueConfiguration: Optional[QueueConfigurationDeprecated]
    CloudFunctionConfiguration: Optional[CloudFunctionConfiguration]


UserMetadata = List[MetadataEntry]


class Tagging(TypedDict, total=False):
    """Container for ``TagSet`` elements."""

    TagSet: TagSet


class S3Location(TypedDict, total=False):
    """Describes an Amazon S3 location that will receive the results of the
    restore request.
    """

    BucketName: BucketName
    Prefix: LocationPrefix
    Encryption: Optional[Encryption]
    CannedACL: Optional[ObjectCannedACL]
    AccessControlList: Optional[Grants]
    Tagging: Optional[Tagging]
    UserMetadata: Optional[UserMetadata]
    StorageClass: Optional[StorageClass]


class OutputLocation(TypedDict, total=False):
    """Describes the location where the restore job's output is stored."""

    S3: Optional[S3Location]


class OutputSerialization(TypedDict, total=False):
    """Describes how results of the Select job are serialized."""

    CSV: Optional[CSVOutput]
    JSON: Optional[JSONOutput]


class Progress(TypedDict, total=False):
    """This data type contains information about progress of an operation."""

    BytesScanned: Optional[BytesScanned]
    BytesProcessed: Optional[BytesProcessed]
    BytesReturned: Optional[BytesReturned]


class ProgressEvent(TypedDict, total=False):
    """This data type contains information about the progress event of an
    operation.
    """

    Details: Optional[Progress]


class PutBucketAccelerateConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    AccelerateConfiguration: AccelerateConfiguration
    ExpectedBucketOwner: Optional[AccountId]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]


class PutBucketAclRequest(ServiceRequest):
    ACL: Optional[BucketCannedACL]
    AccessControlPolicy: Optional[AccessControlPolicy]
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    GrantFullControl: Optional[GrantFullControl]
    GrantRead: Optional[GrantRead]
    GrantReadACP: Optional[GrantReadACP]
    GrantWrite: Optional[GrantWrite]
    GrantWriteACP: Optional[GrantWriteACP]
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketAnalyticsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: AnalyticsId
    AnalyticsConfiguration: AnalyticsConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketCorsRequest(ServiceRequest):
    Bucket: BucketName
    CORSConfiguration: CORSConfiguration
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketEncryptionRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ServerSideEncryptionConfiguration: ServerSideEncryptionConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketIntelligentTieringConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: IntelligentTieringId
    IntelligentTieringConfiguration: IntelligentTieringConfiguration


class PutBucketInventoryConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: InventoryId
    InventoryConfiguration: InventoryConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketLifecycleConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    LifecycleConfiguration: Optional[BucketLifecycleConfiguration]
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketLifecycleRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    LifecycleConfiguration: Optional[LifecycleConfiguration]
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketLoggingRequest(ServiceRequest):
    Bucket: BucketName
    BucketLoggingStatus: BucketLoggingStatus
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketMetricsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: MetricsId
    MetricsConfiguration: MetricsConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketNotificationConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    NotificationConfiguration: NotificationConfiguration
    ExpectedBucketOwner: Optional[AccountId]
    SkipDestinationValidation: Optional[SkipValidation]


class PutBucketNotificationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    NotificationConfiguration: NotificationConfigurationDeprecated
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketOwnershipControlsRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ExpectedBucketOwner: Optional[AccountId]
    OwnershipControls: OwnershipControls


class PutBucketPolicyRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ConfirmRemoveSelfBucketAccess: Optional[ConfirmRemoveSelfBucketAccess]
    Policy: Policy
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketReplicationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ReplicationConfiguration: ReplicationConfiguration
    Token: Optional[ObjectLockToken]
    ExpectedBucketOwner: Optional[AccountId]


class RequestPaymentConfiguration(TypedDict, total=False):
    """Container for Payer."""

    Payer: Payer


class PutBucketRequestPaymentRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    RequestPaymentConfiguration: RequestPaymentConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class PutBucketTaggingRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    Tagging: Tagging
    ExpectedBucketOwner: Optional[AccountId]


class VersioningConfiguration(TypedDict, total=False):
    """Describes the versioning state of an Amazon S3 bucket. For more
    information, see `PUT Bucket
    versioning <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTVersioningStatus.html>`__
    in the *Amazon S3 API Reference*.
    """

    MFADelete: Optional[MFADelete]
    Status: Optional[BucketVersioningStatus]


class PutBucketVersioningRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    MFA: Optional[MFA]
    VersioningConfiguration: VersioningConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class WebsiteConfiguration(TypedDict, total=False):
    """Specifies website configuration parameters for an Amazon S3 bucket."""

    ErrorDocument: Optional[ErrorDocument]
    IndexDocument: Optional[IndexDocument]
    RedirectAllRequestsTo: Optional[RedirectAllRequestsTo]
    RoutingRules: Optional[RoutingRules]


class PutBucketWebsiteRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    WebsiteConfiguration: WebsiteConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class PutObjectAclOutput(TypedDict, total=False):
    RequestCharged: Optional[RequestCharged]


class PutObjectAclRequest(ServiceRequest):
    ACL: Optional[ObjectCannedACL]
    AccessControlPolicy: Optional[AccessControlPolicy]
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    GrantFullControl: Optional[GrantFullControl]
    GrantRead: Optional[GrantRead]
    GrantReadACP: Optional[GrantReadACP]
    GrantWrite: Optional[GrantWrite]
    GrantWriteACP: Optional[GrantWriteACP]
    Key: ObjectKey
    RequestPayer: Optional[RequestPayer]
    VersionId: Optional[ObjectVersionId]
    ExpectedBucketOwner: Optional[AccountId]


class PutObjectLegalHoldOutput(TypedDict, total=False):
    RequestCharged: Optional[RequestCharged]


class PutObjectLegalHoldRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    LegalHold: Optional[ObjectLockLegalHold]
    RequestPayer: Optional[RequestPayer]
    VersionId: Optional[ObjectVersionId]
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ExpectedBucketOwner: Optional[AccountId]


class PutObjectLockConfigurationOutput(TypedDict, total=False):
    RequestCharged: Optional[RequestCharged]


class PutObjectLockConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ObjectLockConfiguration: Optional[ObjectLockConfiguration]
    RequestPayer: Optional[RequestPayer]
    Token: Optional[ObjectLockToken]
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ExpectedBucketOwner: Optional[AccountId]


class PutObjectOutput(TypedDict, total=False):
    Expiration: Optional[Expiration]
    ETag: Optional[ETag]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    ServerSideEncryption: Optional[ServerSideEncryption]
    VersionId: Optional[ObjectVersionId]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestCharged: Optional[RequestCharged]


class PutObjectRequest(ServiceRequest):
    Body: Optional[IO[Body]]
    ACL: Optional[ObjectCannedACL]
    Bucket: BucketName
    CacheControl: Optional[CacheControl]
    ContentDisposition: Optional[ContentDisposition]
    ContentEncoding: Optional[ContentEncoding]
    ContentLanguage: Optional[ContentLanguage]
    ContentLength: Optional[ContentLength]
    ContentMD5: Optional[ContentMD5]
    ContentType: Optional[ContentType]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    Expires: Optional[Expires]
    GrantFullControl: Optional[GrantFullControl]
    GrantRead: Optional[GrantRead]
    GrantReadACP: Optional[GrantReadACP]
    GrantWriteACP: Optional[GrantWriteACP]
    Key: ObjectKey
    Metadata: Optional[Metadata]
    ServerSideEncryption: Optional[ServerSideEncryption]
    StorageClass: Optional[StorageClass]
    WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestPayer: Optional[RequestPayer]
    Tagging: Optional[TaggingHeader]
    ObjectLockMode: Optional[ObjectLockMode]
    ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
    ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]
    ExpectedBucketOwner: Optional[AccountId]


class PutObjectRetentionOutput(TypedDict, total=False):
    RequestCharged: Optional[RequestCharged]


class PutObjectRetentionRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    Retention: Optional[ObjectLockRetention]
    RequestPayer: Optional[RequestPayer]
    VersionId: Optional[ObjectVersionId]
    BypassGovernanceRetention: Optional[BypassGovernanceRetention]
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ExpectedBucketOwner: Optional[AccountId]


class PutObjectTaggingOutput(TypedDict, total=False):
    VersionId: Optional[ObjectVersionId]


class PutObjectTaggingRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    Tagging: Tagging
    ExpectedBucketOwner: Optional[AccountId]
    RequestPayer: Optional[RequestPayer]


class PutPublicAccessBlockRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration
    ExpectedBucketOwner: Optional[AccountId]


class RecordsEvent(TypedDict, total=False):
    """The container for the records event."""

    Payload: Optional[Body]


class RequestProgress(TypedDict, total=False):
    """Container for specifying if periodic ``QueryProgress`` messages should
    be sent.
    """

    Enabled: Optional[EnableRequestProgress]


class RestoreObjectOutput(TypedDict, total=False):
    RequestCharged: Optional[RequestCharged]
    RestoreOutputPath: Optional[RestoreOutputPath]


class SelectParameters(TypedDict, total=False):
    """Describes the parameters for Select job types."""

    InputSerialization: InputSerialization
    ExpressionType: ExpressionType
    Expression: Expression
    OutputSerialization: OutputSerialization


class RestoreRequest(TypedDict, total=False):
    """Container for restore job parameters."""

    Days: Optional[Days]
    GlacierJobParameters: Optional[GlacierJobParameters]
    Type: Optional[RestoreRequestType]
    Tier: Optional[Tier]
    Description: Optional[Description]
    SelectParameters: Optional[SelectParameters]
    OutputLocation: Optional[OutputLocation]


class RestoreObjectRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: Optional[ObjectVersionId]
    RestoreRequest: Optional[RestoreRequest]
    RequestPayer: Optional[RequestPayer]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ExpectedBucketOwner: Optional[AccountId]


Start = int


class ScanRange(TypedDict, total=False):
    """Specifies the byte range of the object to get the records from. A record
    is processed when its first byte is contained by the range. This
    parameter is optional, but when specified, it must not be empty. See RFC
    2616, Section 14.35.1 about how to specify the start and end of the
    range.
    """

    Start: Optional[Start]
    End: Optional[End]


class Stats(TypedDict, total=False):
    """Container for the stats details."""

    BytesScanned: Optional[BytesScanned]
    BytesProcessed: Optional[BytesProcessed]
    BytesReturned: Optional[BytesReturned]


class StatsEvent(TypedDict, total=False):
    """Container for the Stats Event."""

    Details: Optional[Stats]


class SelectObjectContentEventStream(TypedDict, total=False):
    """The container for selecting objects from a content event stream."""

    Records: Optional[RecordsEvent]
    Stats: Optional[StatsEvent]
    Progress: Optional[ProgressEvent]
    Cont: Optional[ContinuationEvent]
    End: Optional[EndEvent]


class SelectObjectContentOutput(TypedDict, total=False):
    Payload: Iterator[SelectObjectContentEventStream]


class SelectObjectContentRequest(ServiceRequest):
    """Request to filter the contents of an Amazon S3 object based on a simple
    Structured Query Language (SQL) statement. In the request, along with
    the SQL expression, you must specify a data serialization format (JSON
    or CSV) of the object. Amazon S3 uses this to parse object data into
    records. It returns only records that match the specified SQL
    expression. You must also specify the data serialization format for the
    response. For more information, see `S3Select API
    Documentation <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectSELECTContent.html>`__.
    """

    Bucket: BucketName
    Key: ObjectKey
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    Expression: Expression
    ExpressionType: ExpressionType
    RequestProgress: Optional[RequestProgress]
    InputSerialization: InputSerialization
    OutputSerialization: OutputSerialization
    ScanRange: Optional[ScanRange]
    ExpectedBucketOwner: Optional[AccountId]


class UploadPartCopyOutput(TypedDict, total=False):
    CopySourceVersionId: Optional[CopySourceVersionId]
    CopyPartResult: Optional[CopyPartResult]
    ServerSideEncryption: Optional[ServerSideEncryption]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestCharged: Optional[RequestCharged]


class UploadPartCopyRequest(ServiceRequest):
    Bucket: BucketName
    CopySource: CopySource
    CopySourceIfMatch: Optional[CopySourceIfMatch]
    CopySourceIfModifiedSince: Optional[CopySourceIfModifiedSince]
    CopySourceIfNoneMatch: Optional[CopySourceIfNoneMatch]
    CopySourceIfUnmodifiedSince: Optional[CopySourceIfUnmodifiedSince]
    CopySourceRange: Optional[CopySourceRange]
    Key: ObjectKey
    PartNumber: PartNumber
    UploadId: MultipartUploadId
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    CopySourceSSECustomerAlgorithm: Optional[CopySourceSSECustomerAlgorithm]
    CopySourceSSECustomerKey: Optional[CopySourceSSECustomerKey]
    CopySourceSSECustomerKeyMD5: Optional[CopySourceSSECustomerKeyMD5]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]
    ExpectedSourceBucketOwner: Optional[AccountId]


class UploadPartOutput(TypedDict, total=False):
    ServerSideEncryption: Optional[ServerSideEncryption]
    ETag: Optional[ETag]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    BucketKeyEnabled: Optional[BucketKeyEnabled]
    RequestCharged: Optional[RequestCharged]


class UploadPartRequest(ServiceRequest):
    Body: Optional[IO[Body]]
    Bucket: BucketName
    ContentLength: Optional[ContentLength]
    ContentMD5: Optional[ContentMD5]
    ChecksumAlgorithm: Optional[ChecksumAlgorithm]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    Key: ObjectKey
    PartNumber: PartNumber
    UploadId: MultipartUploadId
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSECustomerKey: Optional[SSECustomerKey]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    RequestPayer: Optional[RequestPayer]
    ExpectedBucketOwner: Optional[AccountId]


class WriteGetObjectResponseRequest(ServiceRequest):
    Body: Optional[IO[Body]]
    RequestRoute: RequestRoute
    RequestToken: RequestToken
    StatusCode: Optional[GetObjectResponseStatusCode]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]
    AcceptRanges: Optional[AcceptRanges]
    CacheControl: Optional[CacheControl]
    ContentDisposition: Optional[ContentDisposition]
    ContentEncoding: Optional[ContentEncoding]
    ContentLanguage: Optional[ContentLanguage]
    ContentLength: Optional[ContentLength]
    ContentRange: Optional[ContentRange]
    ContentType: Optional[ContentType]
    ChecksumCRC32: Optional[ChecksumCRC32]
    ChecksumCRC32C: Optional[ChecksumCRC32C]
    ChecksumSHA1: Optional[ChecksumSHA1]
    ChecksumSHA256: Optional[ChecksumSHA256]
    DeleteMarker: Optional[DeleteMarker]
    ETag: Optional[ETag]
    Expires: Optional[Expires]
    Expiration: Optional[Expiration]
    LastModified: Optional[LastModified]
    MissingMeta: Optional[MissingMeta]
    Metadata: Optional[Metadata]
    ObjectLockMode: Optional[ObjectLockMode]
    ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]
    ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
    PartsCount: Optional[PartsCount]
    ReplicationStatus: Optional[ReplicationStatus]
    RequestCharged: Optional[RequestCharged]
    Restore: Optional[Restore]
    ServerSideEncryption: Optional[ServerSideEncryption]
    SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
    SSEKMSKeyId: Optional[SSEKMSKeyId]
    SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
    StorageClass: Optional[StorageClass]
    TagCount: Optional[TagCount]
    VersionId: Optional[ObjectVersionId]
    BucketKeyEnabled: Optional[BucketKeyEnabled]


class S3Api:

    service = "s3"
    version = "2006-03-01"

    @handler("AbortMultipartUpload")
    def abort_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> AbortMultipartUploadOutput:
        """This action aborts a multipart upload. After a multipart upload is
        aborted, no additional parts can be uploaded using that upload ID. The
        storage consumed by any previously uploaded parts will be freed.
        However, if any part uploads are currently in progress, those part
        uploads might or might not succeed. As a result, it might be necessary
        to abort a given multipart upload multiple times in order to completely
        free all storage consumed by all parts.

        To verify that all parts have been removed, so you don't get charged for
        the part storage, you should call the
        `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__
        action and ensure that the parts list is empty.

        For information about permissions required to use the multipart upload,
        see `Multipart Upload and
        Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__.

        The following operations are related to ``AbortMultipartUpload``:

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `ListMultipartUploads <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html>`__

        :param bucket: The bucket name to which the upload was taking place.
        :param key: Key of the object for which the multipart upload was initiated.
        :param upload_id: Upload ID that identifies the multipart upload.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: AbortMultipartUploadOutput
        :raises NoSuchUpload:
        """
        raise NotImplementedError

    @handler("CompleteMultipartUpload")
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
        """Completes a multipart upload by assembling previously uploaded parts.

        You first initiate the multipart upload and then upload all parts using
        the
        `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__
        operation. After successfully uploading all relevant parts of an upload,
        you call this action to complete the upload. Upon receiving this
        request, Amazon S3 concatenates all the parts in ascending order by part
        number to create a new object. In the Complete Multipart Upload request,
        you must provide the parts list. You must ensure that the parts list is
        complete. This action concatenates the parts that you provide in the
        list. For each part in the list, you must provide the part number and
        the ``ETag`` value, returned after that part was uploaded.

        Processing of a Complete Multipart Upload request could take several
        minutes to complete. After Amazon S3 begins processing the request, it
        sends an HTTP response header that specifies a 200 OK response. While
        processing is in progress, Amazon S3 periodically sends white space
        characters to keep the connection from timing out. Because a request
        could fail after the initial 200 OK response has been sent, it is
        important that you check the response body to determine whether the
        request succeeded.

        Note that if ``CompleteMultipartUpload`` fails, applications should be
        prepared to retry the failed requests. For more information, see `Amazon
        S3 Error Best
        Practices <https://docs.aws.amazon.com/AmazonS3/latest/dev/ErrorBestPractices.html>`__.

        You cannot use ``Content-Type: application/x-www-form-urlencoded`` with
        Complete Multipart Upload requests. Also, if you do not provide a
        ``Content-Type`` header, ``CompleteMultipartUpload`` returns a 200 OK
        response.

        For more information about multipart uploads, see `Uploading Objects
        Using Multipart
        Upload <https://docs.aws.amazon.com/AmazonS3/latest/dev/uploadobjusingmpu.html>`__.

        For information about permissions required to use the multipart upload
        API, see `Multipart Upload and
        Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__.

        ``CompleteMultipartUpload`` has the following special errors:

        -  Error code: ``EntityTooSmall``

           -  Description: Your proposed upload is smaller than the minimum
              allowed object size. Each part must be at least 5 MB in size,
              except the last part.

           -  400 Bad Request

        -  Error code: ``InvalidPart``

           -  Description: One or more of the specified parts could not be
              found. The part might not have been uploaded, or the specified
              entity tag might not have matched the part's entity tag.

           -  400 Bad Request

        -  Error code: ``InvalidPartOrder``

           -  Description: The list of parts was not in ascending order. The
              parts list must be specified in order by part number.

           -  400 Bad Request

        -  Error code: ``NoSuchUpload``

           -  Description: The specified multipart upload does not exist. The
              upload ID might be invalid, or the multipart upload might have
              been aborted or completed.

           -  404 Not Found

        The following operations are related to ``CompleteMultipartUpload``:

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `ListMultipartUploads <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html>`__

        :param bucket: Name of the bucket to which the multipart upload was initiated.
        :param key: Object key for which the multipart upload was initiated.
        :param upload_id: ID for the initiated multipart upload.
        :param multipart_upload: The container for the multipart upload request information.
        :param checksum_crc32: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_crc32_c: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha1: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha256: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param sse_customer_algorithm: The server-side encryption (SSE) algorithm used to encrypt the object.
        :param sse_customer_key: The server-side encryption (SSE) customer managed key.
        :param sse_customer_key_md5: The MD5 server-side encryption (SSE) customer managed key.
        :returns: CompleteMultipartUploadOutput
        """
        raise NotImplementedError

    @handler("CopyObject")
    def copy_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        copy_source: CopySource,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        cache_control: CacheControl = None,
        checksum_algorithm: ChecksumAlgorithm = None,
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
        """Creates a copy of an object that is already stored in Amazon S3.

        You can store individual objects of up to 5 TB in Amazon S3. You create
        a copy of your object up to 5 GB in size in a single atomic action using
        this API. However, to copy an object greater than 5 GB, you must use the
        multipart upload Upload Part - Copy (UploadPartCopy) API. For more
        information, see `Copy Object Using the REST Multipart Upload
        API <https://docs.aws.amazon.com/AmazonS3/latest/dev/CopyingObjctsUsingRESTMPUapi.html>`__.

        All copy requests must be authenticated. Additionally, you must have
        *read* access to the source object and *write* access to the destination
        bucket. For more information, see `REST
        Authentication <https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html>`__.
        Both the Region that you want to copy the object from and the Region
        that you want to copy the object to must be enabled for your account.

        A copy request might return an error when Amazon S3 receives the copy
        request or while Amazon S3 is copying the files. If the error occurs
        before the copy action starts, you receive a standard Amazon S3 error.
        If the error occurs during the copy operation, the error response is
        embedded in the ``200 OK`` response. This means that a ``200 OK``
        response can contain either a success or an error. Design your
        application to parse the contents of the response and handle it
        appropriately.

        If the copy is successful, you receive a response with information about
        the copied object.

        If the request is an HTTP 1.1 request, the response is chunk encoded. If
        it were not, it would not contain the content-length, and you would need
        to read the entire body.

        The copy request charge is based on the storage class and Region that
        you specify for the destination object. For pricing information, see
        `Amazon S3 pricing <http://aws.amazon.com/s3/pricing/>`__.

        Amazon S3 transfer acceleration does not support cross-Region copies. If
        you request a cross-Region copy using a transfer acceleration endpoint,
        you get a 400 ``Bad Request`` error. For more information, see `Transfer
        Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`__.

        **Metadata**

        When copying an object, you can preserve all metadata (default) or
        specify new metadata. However, the ACL is not preserved and is set to
        private for the user making the request. To override the default ACL
        setting, specify a new ACL when generating a copy request. For more
        information, see `Using
        ACLs <https://docs.aws.amazon.com/AmazonS3/latest/dev/S3_ACLs_UsingACLs.html>`__.

        To specify whether you want the object metadata copied from the source
        object or replaced with metadata provided in the request, you can
        optionally add the ``x-amz-metadata-directive`` header. When you grant
        permissions, you can use the ``s3:x-amz-metadata-directive`` condition
        key to enforce certain metadata behavior when objects are uploaded. For
        more information, see `Specifying Conditions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/amazon-s3-policy-keys.html>`__
        in the *Amazon S3 User Guide*. For a complete list of Amazon S3-specific
        condition keys, see `Actions, Resources, and Condition Keys for Amazon
        S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/list_amazons3.html>`__.

        **x-amz-copy-source-if Headers**

        To only copy an object under certain conditions, such as whether the
        ``Etag`` matches or whether the object was modified before or after a
        specified date, use the following request parameters:

        -  ``x-amz-copy-source-if-match``

        -  ``x-amz-copy-source-if-none-match``

        -  ``x-amz-copy-source-if-unmodified-since``

        -  ``x-amz-copy-source-if-modified-since``

        If both the ``x-amz-copy-source-if-match`` and
        ``x-amz-copy-source-if-unmodified-since`` headers are present in the
        request and evaluate as follows, Amazon S3 returns ``200 OK`` and copies
        the data:

        -  ``x-amz-copy-source-if-match`` condition evaluates to true

        -  ``x-amz-copy-source-if-unmodified-since`` condition evaluates to
           false

        If both the ``x-amz-copy-source-if-none-match`` and
        ``x-amz-copy-source-if-modified-since`` headers are present in the
        request and evaluate as follows, Amazon S3 returns the
        ``412 Precondition Failed`` response code:

        -  ``x-amz-copy-source-if-none-match`` condition evaluates to false

        -  ``x-amz-copy-source-if-modified-since`` condition evaluates to true

        All headers with the ``x-amz-`` prefix, including ``x-amz-copy-source``,
        must be signed.

        **Server-side encryption**

        When you perform a CopyObject operation, you can optionally use the
        appropriate encryption-related headers to encrypt the object using
        server-side encryption with Amazon Web Services managed encryption keys
        (SSE-S3 or SSE-KMS) or a customer-provided encryption key. With
        server-side encryption, Amazon S3 encrypts your data as it writes it to
        disks in its data centers and decrypts the data when you access it. For
        more information about server-side encryption, see `Using Server-Side
        Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html>`__.

        If a target object uses SSE-KMS, you can enable an S3 Bucket Key for the
        object. For more information, see `Amazon S3 Bucket
        Keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-key.html>`__
        in the *Amazon S3 User Guide*.

        **Access Control List (ACL)-Specific Request Headers**

        When copying an object, you can optionally use headers to grant
        ACL-based permissions. By default, all objects are private. Only the
        owner has full access control. When adding a new object, you can grant
        permissions to individual Amazon Web Services accounts or to predefined
        groups defined by Amazon S3. These permissions are then added to the ACL
        on the object. For more information, see `Access Control List (ACL)
        Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__
        and `Managing ACLs Using the REST
        API <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-using-rest-api.html>`__.

        If the bucket that you're copying objects to uses the bucket owner
        enforced setting for S3 Object Ownership, ACLs are disabled and no
        longer affect permissions. Buckets that use this setting only accept PUT
        requests that don't specify an ACL or PUT requests that specify bucket
        owner full control ACLs, such as the ``bucket-owner-full-control``
        canned ACL or an equivalent form of this ACL expressed in the XML
        format.

        For more information, see `Controlling ownership of objects and
        disabling
        ACLs <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        If your bucket uses the bucket owner enforced setting for Object
        Ownership, all objects written to the bucket by any account will be
        owned by the bucket owner.

        **Checksums**

        When copying an object, if it has a checksum, that checksum will be
        copied to the new object by default. When you copy the object over, you
        may optionally specify a different checksum algorithm to use with the
        ``x-amz-checksum-algorithm`` header.

        **Storage Class Options**

        You can use the ``CopyObject`` action to change the storage class of an
        object that is already stored in Amazon S3 using the ``StorageClass``
        parameter. For more information, see `Storage
        Classes <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html>`__
        in the *Amazon S3 User Guide*.

        **Versioning**

        By default, ``x-amz-copy-source`` identifies the current version of an
        object to copy. If the current version is a delete marker, Amazon S3
        behaves as if the object was deleted. To copy a different version, use
        the ``versionId`` subresource.

        If you enable versioning on the target bucket, Amazon S3 generates a
        unique version ID for the object being copied. This version ID is
        different from the version ID of the source object. Amazon S3 returns
        the version ID of the copied object in the ``x-amz-version-id`` response
        header in the response.

        If you do not enable versioning or suspend it on the target bucket, the
        version ID that Amazon S3 generates is always null.

        If the source object's storage class is GLACIER, you must restore a copy
        of this object before you can use it as a source object for the copy
        operation. For more information, see
        `RestoreObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html>`__.

        The following operations are related to ``CopyObject``:

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        For more information, see `Copying
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/CopyingObjectsExamples.html>`__.

        :param bucket: The name of the destination bucket.
        :param copy_source: Specifies the source object for the copy operation.
        :param key: The key of the destination object.
        :param acl: The canned ACL to apply to the object.
        :param cache_control: Specifies caching behavior along the request/reply chain.
        :param checksum_algorithm: Indicates the algorithm you want Amazon S3 to use to create the checksum
        for the object.
        :param content_disposition: Specifies presentational information for the object.
        :param content_encoding: Specifies what content encodings have been applied to the object and
        thus what decoding mechanisms must be applied to obtain the media-type
        referenced by the Content-Type header field.
        :param content_language: The language the content is in.
        :param content_type: A standard MIME type describing the format of the object data.
        :param copy_source_if_match: Copies the object if its entity tag (ETag) matches the specified tag.
        :param copy_source_if_modified_since: Copies the object if it has been modified since the specified time.
        :param copy_source_if_none_match: Copies the object if its entity tag (ETag) is different than the
        specified ETag.
        :param copy_source_if_unmodified_since: Copies the object if it hasn't been modified since the specified time.
        :param expires: The date and time at which the object is no longer cacheable.
        :param grant_full_control: Gives the grantee READ, READ_ACP, and WRITE_ACP permissions on the
        object.
        :param grant_read: Allows grantee to read the object data and its metadata.
        :param grant_read_acp: Allows grantee to read the object ACL.
        :param grant_write_acp: Allows grantee to write the ACL for the applicable object.
        :param metadata: A map of metadata to store with the object in S3.
        :param metadata_directive: Specifies whether the metadata is copied from the source object or
        replaced with metadata provided in the request.
        :param tagging_directive: Specifies whether the object tag-set are copied from the source object
        or replaced with tag-set provided in the request.
        :param server_side_encryption: The server-side encryption algorithm used when storing this object in
        Amazon S3 (for example, AES256, aws:kms).
        :param storage_class: By default, Amazon S3 uses the STANDARD Storage Class to store newly
        created objects.
        :param website_redirect_location: If the bucket is configured as a website, redirects requests for this
        object to another object in the same bucket or to an external URL.
        :param sse_customer_algorithm: Specifies the algorithm to use to when encrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param ssekms_key_id: Specifies the Amazon Web Services KMS key ID to use for object
        encryption.
        :param ssekms_encryption_context: Specifies the Amazon Web Services KMS Encryption Context to use for
        object encryption.
        :param bucket_key_enabled: Specifies whether Amazon S3 should use an S3 Bucket Key for object
        encryption with server-side encryption using AWS KMS (SSE-KMS).
        :param copy_source_sse_customer_algorithm: Specifies the algorithm to use when decrypting the source object (for
        example, AES256).
        :param copy_source_sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use to
        decrypt the source object.
        :param copy_source_sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param tagging: The tag-set for the object destination object this value must be used in
        conjunction with the ``TaggingDirective``.
        :param object_lock_mode: The Object Lock mode that you want to apply to the copied object.
        :param object_lock_retain_until_date: The date and time when you want the copied object's Object Lock to
        expire.
        :param object_lock_legal_hold_status: Specifies whether you want to apply a legal hold to the copied object.
        :param expected_bucket_owner: The account ID of the expected destination bucket owner.
        :param expected_source_bucket_owner: The account ID of the expected source bucket owner.
        :returns: CopyObjectOutput
        :raises ObjectNotInActiveTierError:
        """
        raise NotImplementedError

    @handler("CreateBucket")
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
        """Creates a new S3 bucket. To create a bucket, you must register with
        Amazon S3 and have a valid Amazon Web Services Access Key ID to
        authenticate requests. Anonymous requests are never allowed to create
        buckets. By creating the bucket, you become the bucket owner.

        Not every string is an acceptable bucket name. For information about
        bucket naming restrictions, see `Bucket naming
        rules <https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html>`__.

        If you want to create an Amazon S3 on Outposts bucket, see `Create
        Bucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateBucket.html>`__.

        By default, the bucket is created in the US East (N. Virginia) Region.
        You can optionally specify a Region in the request body. You might
        choose a Region to optimize latency, minimize costs, or address
        regulatory requirements. For example, if you reside in Europe, you will
        probably find it advantageous to create buckets in the Europe (Ireland)
        Region. For more information, see `Accessing a
        bucket <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro>`__.

        If you send your create bucket request to the ``s3.amazonaws.com``
        endpoint, the request goes to the us-east-1 Region. Accordingly, the
        signature calculations in Signature Version 4 must use us-east-1 as the
        Region, even if the location constraint in the request specifies another
        Region where the bucket is to be created. If you create a bucket in a
        Region other than US East (N. Virginia), your application must be able
        to handle 307 redirect. For more information, see `Virtual hosting of
        buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html>`__.

        **Access control lists (ACLs)**

        When creating a bucket using this operation, you can optionally
        configure the bucket ACL to specify the accounts or groups that should
        be granted specific permissions on the bucket.

        If your CreateBucket request sets bucket owner enforced for S3 Object
        Ownership and specifies a bucket ACL that provides access to an external
        Amazon Web Services account, your request fails with a ``400`` error and
        returns the ``InvalidBucketAclWithObjectOwnership`` error code. For more
        information, see `Controlling object
        ownership <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        There are two ways to grant the appropriate permissions using the
        request headers.

        -  Specify a canned ACL using the ``x-amz-acl`` request header. Amazon
           S3 supports a set of predefined ACLs, known as *canned ACLs*. Each
           canned ACL has a predefined set of grantees and permissions. For more
           information, see `Canned
           ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#CannedACL>`__.

        -  Specify access permissions explicitly using the ``x-amz-grant-read``,
           ``x-amz-grant-write``, ``x-amz-grant-read-acp``,
           ``x-amz-grant-write-acp``, and ``x-amz-grant-full-control`` headers.
           These headers map to the set of permissions Amazon S3 supports in an
           ACL. For more information, see `Access control list (ACL)
           overview <https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html>`__.

           You specify each grantee as a type=value pair, where the type is one
           of the following:

           -  ``id`` – if the value specified is the canonical user ID of an
              Amazon Web Services account

           -  ``uri`` – if you are granting permissions to a predefined group

           -  ``emailAddress`` – if the value specified is the email address of
              an Amazon Web Services account

              Using email addresses to specify a grantee is only supported in
              the following Amazon Web Services Regions:

              -  US East (N. Virginia)

              -  US West (N. California)

              -  US West (Oregon)

              -  Asia Pacific (Singapore)

              -  Asia Pacific (Sydney)

              -  Asia Pacific (Tokyo)

              -  Europe (Ireland)

              -  South America (São Paulo)

              For a list of all the Amazon S3 supported Regions and endpoints,
              see `Regions and
              Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region>`__
              in the Amazon Web Services General Reference.

           For example, the following ``x-amz-grant-read`` header grants the
           Amazon Web Services accounts identified by account IDs permissions to
           read object data and its metadata:

           ``x-amz-grant-read: id="11112222333", id="444455556666"``

        You can use either a canned ACL or specify access permissions
        explicitly. You cannot do both.

        **Permissions**

        In addition to ``s3:CreateBucket``, the following permissions are
        required when your CreateBucket includes specific headers:

        -  **ACLs** - If your ``CreateBucket`` request specifies ACL permissions
           and the ACL is public-read, public-read-write, authenticated-read, or
           if you specify access permissions explicitly through any other ACL,
           both ``s3:CreateBucket`` and ``s3:PutBucketAcl`` permissions are
           needed. If the ACL the ``CreateBucket`` request is private or doesn't
           specify any ACLs, only ``s3:CreateBucket`` permission is needed.

        -  **Object Lock** - If ``ObjectLockEnabledForBucket`` is set to true in
           your ``CreateBucket`` request,
           ``s3:PutBucketObjectLockConfiguration`` and
           ``s3:PutBucketVersioning`` permissions are required.

        -  **S3 Object Ownership** - If your CreateBucket request includes the
           the ``x-amz-object-ownership`` header,
           ``s3:PutBucketOwnershipControls`` permission is required.

        The following operations are related to ``CreateBucket``:

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `DeleteBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html>`__

        :param bucket: The name of the bucket to create.
        :param acl: The canned ACL to apply to the bucket.
        :param create_bucket_configuration: The configuration information for the bucket.
        :param grant_full_control: Allows grantee the read, write, read ACP, and write ACP permissions on
        the bucket.
        :param grant_read: Allows grantee to list the objects in the bucket.
        :param grant_read_acp: Allows grantee to read the bucket ACL.
        :param grant_write: Allows grantee to create new objects in the bucket.
        :param grant_write_acp: Allows grantee to write the ACL for the applicable bucket.
        :param object_lock_enabled_for_bucket: Specifies whether you want S3 Object Lock to be enabled for the new
        bucket.
        :param object_ownership: The container element for object ownership for a bucket's ownership
        controls.
        :returns: CreateBucketOutput
        :raises BucketAlreadyExists:
        :raises BucketAlreadyOwnedByYou:
        """
        raise NotImplementedError

    @handler("CreateMultipartUpload")
    def create_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
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
        checksum_algorithm: ChecksumAlgorithm = None,
    ) -> CreateMultipartUploadOutput:
        """This action initiates a multipart upload and returns an upload ID. This
        upload ID is used to associate all of the parts in the specific
        multipart upload. You specify this upload ID in each of your subsequent
        upload part requests (see
        `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__).
        You also include this upload ID in the final request to either complete
        or abort the multipart upload request.

        For more information about multipart uploads, see `Multipart Upload
        Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html>`__.

        If you have configured a lifecycle rule to abort incomplete multipart
        uploads, the upload must complete within the number of days specified in
        the bucket lifecycle configuration. Otherwise, the incomplete multipart
        upload becomes eligible for an abort action and Amazon S3 aborts the
        multipart upload. For more information, see `Aborting Incomplete
        Multipart Uploads Using a Bucket Lifecycle
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html#mpu-abort-incomplete-mpu-lifecycle-config>`__.

        For information about the permissions required to use the multipart
        upload API, see `Multipart Upload and
        Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__.

        For request signing, multipart upload is just a series of regular
        requests. You initiate a multipart upload, send one or more requests to
        upload parts, and then complete the multipart upload process. You sign
        each request individually. There is nothing special about signing
        multipart upload requests. For more information about signing, see
        `Authenticating Requests (Amazon Web Services Signature Version
        4) <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html>`__.

        After you initiate a multipart upload and upload one or more parts, to
        stop being charged for storing the uploaded parts, you must either
        complete or abort the multipart upload. Amazon S3 frees up the space
        used to store the parts and stop charging you for storing them only
        after you either complete or abort a multipart upload.

        You can optionally request server-side encryption. For server-side
        encryption, Amazon S3 encrypts your data as it writes it to disks in its
        data centers and decrypts it when you access it. You can provide your
        own encryption key, or use Amazon Web Services KMS keys or Amazon
        S3-managed encryption keys. If you choose to provide your own encryption
        key, the request headers you provide in
        `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__
        and
        `UploadPartCopy <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html>`__
        requests must match the headers you used in the request to initiate the
        upload by using ``CreateMultipartUpload``.

        To perform a multipart upload with encryption using an Amazon Web
        Services KMS key, the requester must have permission to the
        ``kms:Decrypt`` and ``kms:GenerateDataKey*`` actions on the key. These
        permissions are required because Amazon S3 must decrypt and read data
        from the encrypted file parts before it completes the multipart upload.
        For more information, see `Multipart upload API and
        permissions <https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html#mpuAndPermissions>`__
        in the *Amazon S3 User Guide*.

        If your Identity and Access Management (IAM) user or role is in the same
        Amazon Web Services account as the KMS key, then you must have these
        permissions on the key policy. If your IAM user or role belongs to a
        different account than the key, then you must have the permissions on
        both the key policy and your IAM user or role.

        For more information, see `Protecting Data Using Server-Side
        Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html>`__.

        Access Permissions
           When copying an object, you can optionally specify the accounts or
           groups that should be granted specific permissions on the new object.
           There are two ways to grant the permissions using the request
           headers:

           -  Specify a canned ACL with the ``x-amz-acl`` request header. For
              more information, see `Canned
              ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#CannedACL>`__.

           -  Specify access permissions explicitly with the
              ``x-amz-grant-read``, ``x-amz-grant-read-acp``,
              ``x-amz-grant-write-acp``, and ``x-amz-grant-full-control``
              headers. These parameters map to the set of permissions that
              Amazon S3 supports in an ACL. For more information, see `Access
              Control List (ACL)
              Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__.

           You can use either a canned ACL or specify access permissions
           explicitly. You cannot do both.

        Server-Side- Encryption-Specific Request Headers
           You can optionally tell Amazon S3 to encrypt data at rest using
           server-side encryption. Server-side encryption is for data encryption
           at rest. Amazon S3 encrypts your data as it writes it to disks in its
           data centers and decrypts it when you access it. The option you use
           depends on whether you want to use Amazon Web Services managed
           encryption keys or provide your own encryption key.

           -  Use encryption keys managed by Amazon S3 or customer managed key
              stored in Amazon Web Services Key Management Service (Amazon Web
              Services KMS) – If you want Amazon Web Services to manage the keys
              used to encrypt data, specify the following headers in the
              request.

              -  ``x-amz-server-side-encryption``

              -  ``x-amz-server-side-encryption-aws-kms-key-id``

              -  ``x-amz-server-side-encryption-context``

              If you specify ``x-amz-server-side-encryption:aws:kms``, but don't
              provide ``x-amz-server-side-encryption-aws-kms-key-id``, Amazon S3
              uses the Amazon Web Services managed key in Amazon Web Services
              KMS to protect the data.

              All GET and PUT requests for an object protected by Amazon Web
              Services KMS fail if you don't make them with SSL or by using
              SigV4.

              For more information about server-side encryption with KMS key
              (SSE-KMS), see `Protecting Data Using Server-Side Encryption with
              KMS
              keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html>`__.

           -  Use customer-provided encryption keys – If you want to manage your
              own encryption keys, provide all the following headers in the
              request.

              -  ``x-amz-server-side-encryption-customer-algorithm``

              -  ``x-amz-server-side-encryption-customer-key``

              -  ``x-amz-server-side-encryption-customer-key-MD5``

              For more information about server-side encryption with KMS keys
              (SSE-KMS), see `Protecting Data Using Server-Side Encryption with
              KMS
              keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html>`__.

        Access-Control-List (ACL)-Specific Request Headers
           You also can use the following access control–related headers with
           this operation. By default, all objects are private. Only the owner
           has full access control. When adding a new object, you can grant
           permissions to individual Amazon Web Services accounts or to
           predefined groups defined by Amazon S3. These permissions are then
           added to the access control list (ACL) on the object. For more
           information, see `Using
           ACLs <https://docs.aws.amazon.com/AmazonS3/latest/dev/S3_ACLs_UsingACLs.html>`__.
           With this operation, you can grant access permissions using one of
           the following two methods:

           -  Specify a canned ACL (``x-amz-acl``) — Amazon S3 supports a set of
              predefined ACLs, known as *canned ACLs*. Each canned ACL has a
              predefined set of grantees and permissions. For more information,
              see `Canned
              ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#CannedACL>`__.

           -  Specify access permissions explicitly — To explicitly grant access
              permissions to specific Amazon Web Services accounts or groups,
              use the following headers. Each header maps to specific
              permissions that Amazon S3 supports in an ACL. For more
              information, see `Access Control List (ACL)
              Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__.
              In the header, you specify a list of grantees who get the specific
              permission. To grant permissions explicitly, use:

              -  ``x-amz-grant-read``

              -  ``x-amz-grant-write``

              -  ``x-amz-grant-read-acp``

              -  ``x-amz-grant-write-acp``

              -  ``x-amz-grant-full-control``

              You specify each grantee as a type=value pair, where the type is
              one of the following:

              -  ``id`` – if the value specified is the canonical user ID of an
                 Amazon Web Services account

              -  ``uri`` – if you are granting permissions to a predefined group

              -  ``emailAddress`` – if the value specified is the email address
                 of an Amazon Web Services account

                 Using email addresses to specify a grantee is only supported in
                 the following Amazon Web Services Regions:

                 -  US East (N. Virginia)

                 -  US West (N. California)

                 -  US West (Oregon)

                 -  Asia Pacific (Singapore)

                 -  Asia Pacific (Sydney)

                 -  Asia Pacific (Tokyo)

                 -  Europe (Ireland)

                 -  South America (São Paulo)

                 For a list of all the Amazon S3 supported Regions and
                 endpoints, see `Regions and
                 Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region>`__
                 in the Amazon Web Services General Reference.

              For example, the following ``x-amz-grant-read`` header grants the
              Amazon Web Services accounts identified by account IDs permissions
              to read object data and its metadata:

              ``x-amz-grant-read: id="11112222333", id="444455556666"``

        The following operations are related to ``CreateMultipartUpload``:

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `ListMultipartUploads <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html>`__

        :param bucket: The name of the bucket to which to initiate the upload

        When using this action with an access point, you must direct requests to
        the access point hostname.
        :param key: Object key for which the multipart upload is to be initiated.
        :param acl: The canned ACL to apply to the object.
        :param cache_control: Specifies caching behavior along the request/reply chain.
        :param content_disposition: Specifies presentational information for the object.
        :param content_encoding: Specifies what content encodings have been applied to the object and
        thus what decoding mechanisms must be applied to obtain the media-type
        referenced by the Content-Type header field.
        :param content_language: The language the content is in.
        :param content_type: A standard MIME type describing the format of the object data.
        :param expires: The date and time at which the object is no longer cacheable.
        :param grant_full_control: Gives the grantee READ, READ_ACP, and WRITE_ACP permissions on the
        object.
        :param grant_read: Allows grantee to read the object data and its metadata.
        :param grant_read_acp: Allows grantee to read the object ACL.
        :param grant_write_acp: Allows grantee to write the ACL for the applicable object.
        :param metadata: A map of metadata to store with the object in S3.
        :param server_side_encryption: The server-side encryption algorithm used when storing this object in
        Amazon S3 (for example, AES256, aws:kms).
        :param storage_class: By default, Amazon S3 uses the STANDARD Storage Class to store newly
        created objects.
        :param website_redirect_location: If the bucket is configured as a website, redirects requests for this
        object to another object in the same bucket or to an external URL.
        :param sse_customer_algorithm: Specifies the algorithm to use to when encrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param ssekms_key_id: Specifies the ID of the symmetric customer managed key to use for object
        encryption.
        :param ssekms_encryption_context: Specifies the Amazon Web Services KMS Encryption Context to use for
        object encryption.
        :param bucket_key_enabled: Specifies whether Amazon S3 should use an S3 Bucket Key for object
        encryption with server-side encryption using AWS KMS (SSE-KMS).
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param tagging: The tag-set for the object.
        :param object_lock_mode: Specifies the Object Lock mode that you want to apply to the uploaded
        object.
        :param object_lock_retain_until_date: Specifies the date and time when you want the Object Lock to expire.
        :param object_lock_legal_hold_status: Specifies whether you want to apply a legal hold to the uploaded object.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param checksum_algorithm: Indicates the algorithm you want Amazon S3 to use to create the checksum
        for the object.
        :returns: CreateMultipartUploadOutput
        """
        raise NotImplementedError

    @handler("DeleteBucket")
    def delete_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Deletes the S3 bucket. All objects (including all object versions and
        delete markers) in the bucket must be deleted before the bucket itself
        can be deleted.

        **Related Resources**

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `DeleteObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>`__

        :param bucket: Specifies the bucket being deleted.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketAnalyticsConfiguration")
    def delete_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Deletes an analytics configuration for the bucket (specified by the
        analytics configuration ID).

        To use this operation, you must have permissions to perform the
        ``s3:PutAnalyticsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about the Amazon S3 analytics feature, see `Amazon S3
        Analytics – Storage Class
        Analysis <https://docs.aws.amazon.com/AmazonS3/latest/dev/analytics-storage-class.html>`__.

        The following operations are related to
        ``DeleteBucketAnalyticsConfiguration``:

        -  `GetBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAnalyticsConfiguration.html>`__

        -  `ListBucketAnalyticsConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketAnalyticsConfigurations.html>`__

        -  `PutBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAnalyticsConfiguration.html>`__

        :param bucket: The name of the bucket from which an analytics configuration is deleted.
        :param id: The ID that identifies the analytics configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketCors")
    def delete_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Deletes the ``cors`` configuration information set for the bucket.

        To use this operation, you must have permission to perform the
        ``s3:PutBucketCORS`` action. The bucket owner has this permission by
        default and can grant this permission to others.

        For information about ``cors``, see `Enabling Cross-Origin Resource
        Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`__
        in the *Amazon S3 User Guide*.

        **Related Resources:**

        -  `PutBucketCors <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html>`__

        -  `RESTOPTIONSobject <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTOPTIONSobject.html>`__

        :param bucket: Specifies the bucket whose ``cors`` configuration is being deleted.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketEncryption")
    def delete_bucket_encryption(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """This implementation of the DELETE action removes default encryption from
        the bucket. For information about the Amazon S3 default encryption
        feature, see `Amazon S3 Default Bucket
        Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`__
        in the *Amazon S3 User Guide*.

        To use this operation, you must have permissions to perform the
        ``s3:PutEncryptionConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the *Amazon S3 User Guide*.

        **Related Resources**

        -  `PutBucketEncryption <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html>`__

        -  `GetBucketEncryption <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html>`__

        :param bucket: The name of the bucket containing the server-side encryption
        configuration to delete.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketIntelligentTieringConfiguration")
    def delete_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> None:
        """Deletes the S3 Intelligent-Tiering configuration from the specified
        bucket.

        The S3 Intelligent-Tiering storage class is designed to optimize storage
        costs by automatically moving data to the most cost-effective storage
        access tier, without performance impact or operational overhead. S3
        Intelligent-Tiering delivers automatic cost savings in three low latency
        and high throughput access tiers. To get the lowest storage cost on data
        that can be accessed in minutes to hours, you can choose to activate
        additional archiving capabilities.

        The S3 Intelligent-Tiering storage class is the ideal storage class for
        data with unknown, changing, or unpredictable access patterns,
        independent of object size or retention period. If the size of an object
        is less than 128 KB, it is not monitored and not eligible for
        auto-tiering. Smaller objects can be stored, but they are always charged
        at the Frequent Access tier rates in the S3 Intelligent-Tiering storage
        class.

        For more information, see `Storage class for automatically optimizing
        frequently and infrequently accessed
        objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`__.

        Operations related to ``DeleteBucketIntelligentTieringConfiguration``
        include:

        -  `GetBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketIntelligentTieringConfiguration.html>`__

        -  `PutBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketIntelligentTieringConfiguration.html>`__

        -  `ListBucketIntelligentTieringConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketIntelligentTieringConfigurations.html>`__

        :param bucket: The name of the Amazon S3 bucket whose configuration you want to modify
        or retrieve.
        :param id: The ID used to identify the S3 Intelligent-Tiering configuration.
        """
        raise NotImplementedError

    @handler("DeleteBucketInventoryConfiguration")
    def delete_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Deletes an inventory configuration (identified by the inventory ID) from
        the bucket.

        To use this operation, you must have permissions to perform the
        ``s3:PutInventoryConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about the Amazon S3 inventory feature, see `Amazon S3
        Inventory <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html>`__.

        Operations related to ``DeleteBucketInventoryConfiguration`` include:

        -  `GetBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketInventoryConfiguration.html>`__

        -  `PutBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketInventoryConfiguration.html>`__

        -  `ListBucketInventoryConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketInventoryConfigurations.html>`__

        :param bucket: The name of the bucket containing the inventory configuration to delete.
        :param id: The ID used to identify the inventory configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketLifecycle")
    def delete_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Deletes the lifecycle configuration from the specified bucket. Amazon S3
        removes all the lifecycle configuration rules in the lifecycle
        subresource associated with the bucket. Your objects never expire, and
        Amazon S3 no longer automatically deletes any objects on the basis of
        rules contained in the deleted lifecycle configuration.

        To use this operation, you must have permission to perform the
        ``s3:PutLifecycleConfiguration`` action. By default, the bucket owner
        has this permission and the bucket owner can grant this permission to
        others.

        There is usually some time lag before lifecycle configuration deletion
        is fully propagated to all the Amazon S3 systems.

        For more information about the object expiration, see `Elements to
        Describe Lifecycle
        Actions <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html#intro-lifecycle-rules-actions>`__.

        Related actions include:

        -  `PutBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html>`__

        -  `GetBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html>`__

        :param bucket: The bucket name of the lifecycle to delete.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketMetricsConfiguration")
    def delete_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Deletes a metrics configuration for the Amazon CloudWatch request
        metrics (specified by the metrics configuration ID) from the bucket.
        Note that this doesn't include the daily storage metrics.

        To use this operation, you must have permissions to perform the
        ``s3:PutMetricsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about CloudWatch request metrics for Amazon S3, see
        `Monitoring Metrics with Amazon
        CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudwatch-monitoring.html>`__.

        The following operations are related to
        ``DeleteBucketMetricsConfiguration``:

        -  `GetBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketMetricsConfiguration.html>`__

        -  `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketMetricsConfiguration.html>`__

        -  `ListBucketMetricsConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketMetricsConfigurations.html>`__

        -  `Monitoring Metrics with Amazon
           CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudwatch-monitoring.html>`__

        :param bucket: The name of the bucket containing the metrics configuration to delete.
        :param id: The ID used to identify the metrics configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketOwnershipControls")
    def delete_bucket_ownership_controls(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Removes ``OwnershipControls`` for an Amazon S3 bucket. To use this
        operation, you must have the ``s3:PutBucketOwnershipControls``
        permission. For more information about Amazon S3 permissions, see
        `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__.

        For information about Amazon S3 Object Ownership, see `Using Object
        Ownership <https://docs.aws.amazon.com/AmazonS3/latest/dev/about-object-ownership.html>`__.

        The following operations are related to
        ``DeleteBucketOwnershipControls``:

        -  GetBucketOwnershipControls

        -  PutBucketOwnershipControls

        :param bucket: The Amazon S3 bucket whose ``OwnershipControls`` you want to delete.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketPolicy")
    def delete_bucket_policy(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """This implementation of the DELETE action uses the policy subresource to
        delete the policy of a specified bucket. If you are using an identity
        other than the root user of the Amazon Web Services account that owns
        the bucket, the calling identity must have the ``DeleteBucketPolicy``
        permissions on the specified bucket and belong to the bucket owner's
        account to use this operation.

        If you don't have ``DeleteBucketPolicy`` permissions, Amazon S3 returns
        a ``403 Access Denied`` error. If you have the correct permissions, but
        you're not using an identity that belongs to the bucket owner's account,
        Amazon S3 returns a ``405 Method Not Allowed`` error.

        As a security precaution, the root user of the Amazon Web Services
        account that owns a bucket can always use this operation, even if the
        policy explicitly denies the root user the ability to perform this
        action.

        For more information about bucket policies, see `Using Bucket Policies
        and
        UserPolicies <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html>`__.

        The following operations are related to ``DeleteBucketPolicy``

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `DeleteObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>`__

        :param bucket: The bucket name.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketReplication")
    def delete_bucket_replication(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Deletes the replication configuration from the bucket.

        To use this operation, you must have permissions to perform the
        ``s3:PutReplicationConfiguration`` action. The bucket owner has these
        permissions by default and can grant it to others. For more information
        about permissions, see `Permissions Related to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        It can take a while for the deletion of a replication configuration to
        fully propagate.

        For information about replication configuration, see
        `Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html>`__
        in the *Amazon S3 User Guide*.

        The following operations are related to ``DeleteBucketReplication``:

        -  `PutBucketReplication <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html>`__

        -  `GetBucketReplication <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketReplication.html>`__

        :param bucket: The bucket name.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketTagging")
    def delete_bucket_tagging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Deletes the tags from the bucket.

        To use this operation, you must have permission to perform the
        ``s3:PutBucketTagging`` action. By default, the bucket owner has this
        permission and can grant this permission to others.

        The following operations are related to ``DeleteBucketTagging``:

        -  `GetBucketTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html>`__

        -  `PutBucketTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html>`__

        :param bucket: The bucket that has the tag set to be removed.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteBucketWebsite")
    def delete_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """This action removes the website configuration for a bucket. Amazon S3
        returns a ``200 OK`` response upon successfully deleting a website
        configuration on the specified bucket. You will get a ``200 OK``
        response if the website configuration you are trying to delete does not
        exist on the bucket. Amazon S3 returns a ``404`` response if the bucket
        specified in the request does not exist.

        This DELETE action requires the ``S3:DeleteBucketWebsite`` permission.
        By default, only the bucket owner can delete the website configuration
        attached to a bucket. However, bucket owners can grant other users
        permission to delete the website configuration by writing a bucket
        policy granting them the ``S3:DeleteBucketWebsite`` permission.

        For more information about hosting websites, see `Hosting Websites on
        Amazon
        S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`__.

        The following operations are related to ``DeleteBucketWebsite``:

        -  `GetBucketWebsite <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html>`__

        -  `PutBucketWebsite <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html>`__

        :param bucket: The bucket name for which you want to remove the website configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("DeleteObject")
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
        """Removes the null version (if there is one) of an object and inserts a
        delete marker, which becomes the latest version of the object. If there
        isn't a null version, Amazon S3 does not remove any objects but will
        still respond that the command was successful.

        To remove a specific version, you must be the bucket owner and you must
        use the version Id subresource. Using this subresource permanently
        deletes the version. If the object deleted is a delete marker, Amazon S3
        sets the response header, ``x-amz-delete-marker``, to true.

        If the object you want to delete is in a bucket where the bucket
        versioning configuration is MFA Delete enabled, you must include the
        ``x-amz-mfa`` request header in the DELETE ``versionId`` request.
        Requests that include ``x-amz-mfa`` must use HTTPS.

        For more information about MFA Delete, see `Using MFA
        Delete <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html>`__.
        To see sample requests that use versioning, see `Sample
        Request <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETE.html#ExampleVersionObjectDelete>`__.

        You can delete objects by explicitly calling DELETE Object or configure
        its lifecycle
        (`PutBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycle.html>`__)
        to enable Amazon S3 to remove them for you. If you want to block users
        or accounts from removing or deleting objects from your bucket, you must
        deny them the ``s3:DeleteObject``, ``s3:DeleteObjectVersion``, and
        ``s3:PutLifeCycleConfiguration`` actions.

        The following action is related to ``DeleteObject``:

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        :param bucket: The bucket name of the bucket containing the object.
        :param key: Key name of the object to delete.
        :param mfa: The concatenation of the authentication device's serial number, a space,
        and the value that is displayed on your authentication device.
        :param version_id: VersionId used to reference a specific version of the object.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param bypass_governance_retention: Indicates whether S3 Object Lock should bypass Governance-mode
        restrictions to process this operation.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: DeleteObjectOutput
        """
        raise NotImplementedError

    @handler("DeleteObjectTagging")
    def delete_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectTaggingOutput:
        """Removes the entire tag set from the specified object. For more
        information about managing object tags, see `Object
        Tagging <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-tagging.html>`__.

        To use this operation, you must have permission to perform the
        ``s3:DeleteObjectTagging`` action.

        To delete tags of a specific object version, add the ``versionId`` query
        parameter in the request. You will need permission for the
        ``s3:DeleteObjectVersionTagging`` action.

        The following operations are related to
        ``DeleteBucketMetricsConfiguration``:

        -  `PutObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html>`__

        -  `GetObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html>`__

        :param bucket: The bucket name containing the objects from which to remove the tags.
        :param key: The key that identifies the object in the bucket from which to remove
        all tags.
        :param version_id: The versionId of the object that the tag-set will be removed from.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: DeleteObjectTaggingOutput
        """
        raise NotImplementedError

    @handler("DeleteObjects")
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
        """This action enables you to delete multiple objects from a bucket using a
        single HTTP request. If you know the object keys that you want to
        delete, then this action provides a suitable alternative to sending
        individual delete requests, reducing per-request overhead.

        The request contains a list of up to 1000 keys that you want to delete.
        In the XML, you provide the object key names, and optionally, version
        IDs if you want to delete a specific version of the object from a
        versioning-enabled bucket. For each key, Amazon S3 performs a delete
        action and returns the result of that delete, success, or failure, in
        the response. Note that if the object specified in the request is not
        found, Amazon S3 returns the result as deleted.

        The action supports two modes for the response: verbose and quiet. By
        default, the action uses verbose mode in which the response includes the
        result of deletion of each key in your request. In quiet mode the
        response includes only keys where the delete action encountered an
        error. For a successful deletion, the action does not return any
        information about the delete in the response body.

        When performing this action on an MFA Delete enabled bucket, that
        attempts to delete any versioned objects, you must include an MFA token.
        If you do not provide one, the entire request will fail, even if there
        are non-versioned objects you are trying to delete. If you provide an
        invalid token, whether there are versioned keys in the request or not,
        the entire Multi-Object Delete request will fail. For information about
        MFA Delete, see `MFA
        Delete <https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete>`__.

        Finally, the Content-MD5 header is required for all Multi-Object Delete
        requests. Amazon S3 uses the header value to ensure that your request
        body has not been altered in transit.

        The following operations are related to ``DeleteObjects``:

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        :param bucket: The bucket name containing the objects to delete.
        :param delete: Container for the request.
        :param mfa: The concatenation of the authentication device's serial number, a space,
        and the value that is displayed on your authentication device.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param bypass_governance_retention: Specifies whether you want to delete this object even if it has a
        Governance-type Object Lock in place.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :returns: DeleteObjectsOutput
        """
        raise NotImplementedError

    @handler("DeletePublicAccessBlock")
    def delete_public_access_block(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """Removes the ``PublicAccessBlock`` configuration for an Amazon S3 bucket.
        To use this operation, you must have the
        ``s3:PutBucketPublicAccessBlock`` permission. For more information about
        permissions, see `Permissions Related to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        The following operations are related to ``DeletePublicAccessBlock``:

        -  `Using Amazon S3 Block Public
           Access <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html>`__

        -  `GetPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html>`__

        -  `PutPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html>`__

        -  `GetBucketPolicyStatus <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html>`__

        :param bucket: The Amazon S3 bucket whose ``PublicAccessBlock`` configuration you want
        to delete.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("GetBucketAccelerateConfiguration")
    def get_bucket_accelerate_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketAccelerateConfigurationOutput:
        """This implementation of the GET action uses the ``accelerate``
        subresource to return the Transfer Acceleration state of a bucket, which
        is either ``Enabled`` or ``Suspended``. Amazon S3 Transfer Acceleration
        is a bucket-level feature that enables you to perform faster data
        transfers to and from Amazon S3.

        To use this operation, you must have permission to perform the
        ``s3:GetAccelerateConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the *Amazon S3 User Guide*.

        You set the Transfer Acceleration state of an existing bucket to
        ``Enabled`` or ``Suspended`` by using the
        `PutBucketAccelerateConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAccelerateConfiguration.html>`__
        operation.

        A GET ``accelerate`` request does not return a state value for a bucket
        that has no transfer acceleration state. A bucket has no Transfer
        Acceleration state if a state has never been set on the bucket.

        For more information about transfer acceleration, see `Transfer
        Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`__
        in the Amazon S3 User Guide.

        **Related Resources**

        -  `PutBucketAccelerateConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAccelerateConfiguration.html>`__

        :param bucket: The name of the bucket for which the accelerate configuration is
        retrieved.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketAccelerateConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetBucketAcl")
    def get_bucket_acl(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketAclOutput:
        """This implementation of the ``GET`` action uses the ``acl`` subresource
        to return the access control list (ACL) of a bucket. To use ``GET`` to
        return the ACL of the bucket, you must have ``READ_ACP`` access to the
        bucket. If ``READ_ACP`` permission is granted to the anonymous user, you
        can return the ACL of the bucket without using an authorization header.

        If your bucket uses the bucket owner enforced setting for S3 Object
        Ownership, requests to read ACLs are still supported and return the
        ``bucket-owner-full-control`` ACL with the owner being the account that
        created the bucket. For more information, see `Controlling object
        ownership and disabling
        ACLs <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        **Related Resources**

        -  `ListObjects <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html>`__

        :param bucket: Specifies the S3 bucket whose ACL is being requested.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketAclOutput
        """
        raise NotImplementedError

    @handler("GetBucketAnalyticsConfiguration")
    def get_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketAnalyticsConfigurationOutput:
        """This implementation of the GET action returns an analytics configuration
        (identified by the analytics configuration ID) from the bucket.

        To use this operation, you must have permissions to perform the
        ``s3:GetAnalyticsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the *Amazon S3 User Guide*.

        For information about Amazon S3 analytics feature, see `Amazon S3
        Analytics – Storage Class
        Analysis <https://docs.aws.amazon.com/AmazonS3/latest/dev/analytics-storage-class.html>`__
        in the *Amazon S3 User Guide*.

        **Related Resources**

        -  `DeleteBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketAnalyticsConfiguration.html>`__

        -  `ListBucketAnalyticsConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketAnalyticsConfigurations.html>`__

        -  `PutBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAnalyticsConfiguration.html>`__

        :param bucket: The name of the bucket from which an analytics configuration is
        retrieved.
        :param id: The ID that identifies the analytics configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketAnalyticsConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetBucketCors")
    def get_bucket_cors(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketCorsOutput:
        """Returns the Cross-Origin Resource Sharing (CORS) configuration
        information set for the bucket.

        To use this operation, you must have permission to perform the
        ``s3:GetBucketCORS`` action. By default, the bucket owner has this
        permission and can grant it to others.

        For more information about CORS, see `Enabling Cross-Origin Resource
        Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`__.

        The following operations are related to ``GetBucketCors``:

        -  `PutBucketCors <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html>`__

        -  `DeleteBucketCors <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html>`__

        :param bucket: The bucket name for which to get the cors configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketCorsOutput
        """
        raise NotImplementedError

    @handler("GetBucketEncryption")
    def get_bucket_encryption(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketEncryptionOutput:
        """Returns the default encryption configuration for an Amazon S3 bucket. If
        the bucket does not have a default encryption configuration,
        GetBucketEncryption returns
        ``ServerSideEncryptionConfigurationNotFoundError``.

        For information about the Amazon S3 default encryption feature, see
        `Amazon S3 Default Bucket
        Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`__.

        To use this operation, you must have permission to perform the
        ``s3:GetEncryptionConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        The following operations are related to ``GetBucketEncryption``:

        -  `PutBucketEncryption <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html>`__

        -  `DeleteBucketEncryption <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html>`__

        :param bucket: The name of the bucket from which the server-side encryption
        configuration is retrieved.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketEncryptionOutput
        """
        raise NotImplementedError

    @handler("GetBucketIntelligentTieringConfiguration")
    def get_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> GetBucketIntelligentTieringConfigurationOutput:
        """Gets the S3 Intelligent-Tiering configuration from the specified bucket.

        The S3 Intelligent-Tiering storage class is designed to optimize storage
        costs by automatically moving data to the most cost-effective storage
        access tier, without performance impact or operational overhead. S3
        Intelligent-Tiering delivers automatic cost savings in three low latency
        and high throughput access tiers. To get the lowest storage cost on data
        that can be accessed in minutes to hours, you can choose to activate
        additional archiving capabilities.

        The S3 Intelligent-Tiering storage class is the ideal storage class for
        data with unknown, changing, or unpredictable access patterns,
        independent of object size or retention period. If the size of an object
        is less than 128 KB, it is not monitored and not eligible for
        auto-tiering. Smaller objects can be stored, but they are always charged
        at the Frequent Access tier rates in the S3 Intelligent-Tiering storage
        class.

        For more information, see `Storage class for automatically optimizing
        frequently and infrequently accessed
        objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`__.

        Operations related to ``GetBucketIntelligentTieringConfiguration``
        include:

        -  `DeleteBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketIntelligentTieringConfiguration.html>`__

        -  `PutBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketIntelligentTieringConfiguration.html>`__

        -  `ListBucketIntelligentTieringConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketIntelligentTieringConfigurations.html>`__

        :param bucket: The name of the Amazon S3 bucket whose configuration you want to modify
        or retrieve.
        :param id: The ID used to identify the S3 Intelligent-Tiering configuration.
        :returns: GetBucketIntelligentTieringConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetBucketInventoryConfiguration")
    def get_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketInventoryConfigurationOutput:
        """Returns an inventory configuration (identified by the inventory
        configuration ID) from the bucket.

        To use this operation, you must have permissions to perform the
        ``s3:GetInventoryConfiguration`` action. The bucket owner has this
        permission by default and can grant this permission to others. For more
        information about permissions, see `Permissions Related to Bucket
        Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about the Amazon S3 inventory feature, see `Amazon S3
        Inventory <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html>`__.

        The following operations are related to
        ``GetBucketInventoryConfiguration``:

        -  `DeleteBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketInventoryConfiguration.html>`__

        -  `ListBucketInventoryConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketInventoryConfigurations.html>`__

        -  `PutBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketInventoryConfiguration.html>`__

        :param bucket: The name of the bucket containing the inventory configuration to
        retrieve.
        :param id: The ID used to identify the inventory configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketInventoryConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetBucketLifecycle")
    def get_bucket_lifecycle(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleOutput:
        """For an updated version of this API, see
        `GetBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html>`__.
        If you configured a bucket lifecycle using the ``filter`` element, you
        should see the updated version of this topic. This topic is provided for
        backward compatibility.

        Returns the lifecycle configuration information set on the bucket. For
        information about lifecycle configuration, see `Object Lifecycle
        Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`__.

        To use this operation, you must have permission to perform the
        ``s3:GetLifecycleConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        ``GetBucketLifecycle`` has the following special error:

        -  Error code: ``NoSuchLifecycleConfiguration``

           -  Description: The lifecycle configuration does not exist.

           -  HTTP Status Code: 404 Not Found

           -  SOAP Fault Code Prefix: Client

        The following operations are related to ``GetBucketLifecycle``:

        -  `GetBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html>`__

        -  `PutBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycle.html>`__

        -  `DeleteBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html>`__

        :param bucket: The name of the bucket for which to get the lifecycle information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketLifecycleOutput
        """
        raise NotImplementedError

    @handler("GetBucketLifecycleConfiguration")
    def get_bucket_lifecycle_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLifecycleConfigurationOutput:
        """Bucket lifecycle configuration now supports specifying a lifecycle rule
        using an object key name prefix, one or more object tags, or a
        combination of both. Accordingly, this section describes the latest API.
        The response describes the new filter element that you can use to
        specify a filter to select a subset of objects to which the rule
        applies. If you are using a previous version of the lifecycle
        configuration, it still works. For the earlier action, see
        `GetBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html>`__.

        Returns the lifecycle configuration information set on the bucket. For
        information about lifecycle configuration, see `Object Lifecycle
        Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`__.

        To use this operation, you must have permission to perform the
        ``s3:GetLifecycleConfiguration`` action. The bucket owner has this
        permission, by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        ``GetBucketLifecycleConfiguration`` has the following special error:

        -  Error code: ``NoSuchLifecycleConfiguration``

           -  Description: The lifecycle configuration does not exist.

           -  HTTP Status Code: 404 Not Found

           -  SOAP Fault Code Prefix: Client

        The following operations are related to
        ``GetBucketLifecycleConfiguration``:

        -  `GetBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html>`__

        -  `PutBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycle.html>`__

        -  `DeleteBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html>`__

        :param bucket: The name of the bucket for which to get the lifecycle information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketLifecycleConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetBucketLocation")
    def get_bucket_location(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLocationOutput:
        """Returns the Region the bucket resides in. You set the bucket's Region
        using the ``LocationConstraint`` request parameter in a ``CreateBucket``
        request. For more information, see
        `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__.

        To use this implementation of the operation, you must be the bucket
        owner.

        To use this API against an access point, provide the alias of the access
        point in place of the bucket name.

        The following operations are related to ``GetBucketLocation``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        :param bucket: The name of the bucket for which to get the location.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketLocationOutput
        """
        raise NotImplementedError

    @handler("GetBucketLogging")
    def get_bucket_logging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketLoggingOutput:
        """Returns the logging status of a bucket and the permissions users have to
        view and modify that status. To use GET, you must be the bucket owner.

        The following operations are related to ``GetBucketLogging``:

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `PutBucketLogging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html>`__

        :param bucket: The bucket name for which to get the logging information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketLoggingOutput
        """
        raise NotImplementedError

    @handler("GetBucketMetricsConfiguration")
    def get_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketMetricsConfigurationOutput:
        """Gets a metrics configuration (specified by the metrics configuration ID)
        from the bucket. Note that this doesn't include the daily storage
        metrics.

        To use this operation, you must have permissions to perform the
        ``s3:GetMetricsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about CloudWatch request metrics for Amazon S3, see
        `Monitoring Metrics with Amazon
        CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudwatch-monitoring.html>`__.

        The following operations are related to
        ``GetBucketMetricsConfiguration``:

        -  `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketMetricsConfiguration.html>`__

        -  `DeleteBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketMetricsConfiguration.html>`__

        -  `ListBucketMetricsConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketMetricsConfigurations.html>`__

        -  `Monitoring Metrics with Amazon
           CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudwatch-monitoring.html>`__

        :param bucket: The name of the bucket containing the metrics configuration to retrieve.
        :param id: The ID used to identify the metrics configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketMetricsConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetBucketNotification")
    def get_bucket_notification(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfigurationDeprecated:
        """No longer used, see
        `GetBucketNotificationConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketNotificationConfiguration.html>`__.

        :param bucket: The name of the bucket for which to get the notification configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: NotificationConfigurationDeprecated
        """
        raise NotImplementedError

    @handler("GetBucketNotificationConfiguration")
    def get_bucket_notification_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> NotificationConfiguration:
        """Returns the notification configuration of a bucket.

        If notifications are not enabled on the bucket, the action returns an
        empty ``NotificationConfiguration`` element.

        By default, you must be the bucket owner to read the notification
        configuration of a bucket. However, the bucket owner can use a bucket
        policy to grant permission to other users to read this configuration
        with the ``s3:GetBucketNotification`` permission.

        For more information about setting and reading the notification
        configuration on a bucket, see `Setting Up Notification of Bucket
        Events <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`__.
        For more information about bucket policies, see `Using Bucket
        Policies <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html>`__.

        The following action is related to ``GetBucketNotification``:

        -  `PutBucketNotification <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotification.html>`__

        :param bucket: The name of the bucket for which to get the notification configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: NotificationConfiguration
        """
        raise NotImplementedError

    @handler("GetBucketOwnershipControls")
    def get_bucket_ownership_controls(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketOwnershipControlsOutput:
        """Retrieves ``OwnershipControls`` for an Amazon S3 bucket. To use this
        operation, you must have the ``s3:GetBucketOwnershipControls``
        permission. For more information about Amazon S3 permissions, see
        `Specifying permissions in a
        policy <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html>`__.

        For information about Amazon S3 Object Ownership, see `Using Object
        Ownership <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__.

        The following operations are related to ``GetBucketOwnershipControls``:

        -  PutBucketOwnershipControls

        -  DeleteBucketOwnershipControls

        :param bucket: The name of the Amazon S3 bucket whose ``OwnershipControls`` you want to
        retrieve.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketOwnershipControlsOutput
        """
        raise NotImplementedError

    @handler("GetBucketPolicy")
    def get_bucket_policy(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketPolicyOutput:
        """Returns the policy of a specified bucket. If you are using an identity
        other than the root user of the Amazon Web Services account that owns
        the bucket, the calling identity must have the ``GetBucketPolicy``
        permissions on the specified bucket and belong to the bucket owner's
        account in order to use this operation.

        If you don't have ``GetBucketPolicy`` permissions, Amazon S3 returns a
        ``403 Access Denied`` error. If you have the correct permissions, but
        you're not using an identity that belongs to the bucket owner's account,
        Amazon S3 returns a ``405 Method Not Allowed`` error.

        As a security precaution, the root user of the Amazon Web Services
        account that owns a bucket can always use this operation, even if the
        policy explicitly denies the root user the ability to perform this
        action.

        For more information about bucket policies, see `Using Bucket Policies
        and User
        Policies <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html>`__.

        The following action is related to ``GetBucketPolicy``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        :param bucket: The bucket name for which to get the bucket policy.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketPolicyOutput
        """
        raise NotImplementedError

    @handler("GetBucketPolicyStatus")
    def get_bucket_policy_status(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketPolicyStatusOutput:
        """Retrieves the policy status for an Amazon S3 bucket, indicating whether
        the bucket is public. In order to use this operation, you must have the
        ``s3:GetBucketPolicyStatus`` permission. For more information about
        Amazon S3 permissions, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__.

        For more information about when Amazon S3 considers a bucket public, see
        `The Meaning of
        "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`__.

        The following operations are related to ``GetBucketPolicyStatus``:

        -  `Using Amazon S3 Block Public
           Access <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html>`__

        -  `GetPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html>`__

        -  `PutPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html>`__

        -  `DeletePublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeletePublicAccessBlock.html>`__

        :param bucket: The name of the Amazon S3 bucket whose policy status you want to
        retrieve.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketPolicyStatusOutput
        """
        raise NotImplementedError

    @handler("GetBucketReplication")
    def get_bucket_replication(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketReplicationOutput:
        """Returns the replication configuration of a bucket.

        It can take a while to propagate the put or delete a replication
        configuration to all Amazon S3 systems. Therefore, a get request soon
        after put or delete can return a wrong result.

        For information about replication configuration, see
        `Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html>`__
        in the *Amazon S3 User Guide*.

        This action requires permissions for the
        ``s3:GetReplicationConfiguration`` action. For more information about
        permissions, see `Using Bucket Policies and User
        Policies <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html>`__.

        If you include the ``Filter`` element in a replication configuration,
        you must also include the ``DeleteMarkerReplication`` and ``Priority``
        elements. The response also returns those elements.

        For information about ``GetBucketReplication`` errors, see `List of
        replication-related error
        codes <https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ReplicationErrorCodeList>`__

        The following operations are related to ``GetBucketReplication``:

        -  `PutBucketReplication <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html>`__

        -  `DeleteBucketReplication <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html>`__

        :param bucket: The bucket name for which to get the replication information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketReplicationOutput
        """
        raise NotImplementedError

    @handler("GetBucketRequestPayment")
    def get_bucket_request_payment(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketRequestPaymentOutput:
        """Returns the request payment configuration of a bucket. To use this
        version of the operation, you must be the bucket owner. For more
        information, see `Requester Pays
        Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html>`__.

        The following operations are related to ``GetBucketRequestPayment``:

        -  `ListObjects <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html>`__

        :param bucket: The name of the bucket for which to get the payment request
        configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketRequestPaymentOutput
        """
        raise NotImplementedError

    @handler("GetBucketTagging")
    def get_bucket_tagging(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketTaggingOutput:
        """Returns the tag set associated with the bucket.

        To use this operation, you must have permission to perform the
        ``s3:GetBucketTagging`` action. By default, the bucket owner has this
        permission and can grant this permission to others.

        ``GetBucketTagging`` has the following special error:

        -  Error code: ``NoSuchTagSet``

           -  Description: There is no tag set associated with the bucket.

        The following operations are related to ``GetBucketTagging``:

        -  `PutBucketTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html>`__

        -  `DeleteBucketTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html>`__

        :param bucket: The name of the bucket for which to get the tagging information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketTaggingOutput
        """
        raise NotImplementedError

    @handler("GetBucketVersioning")
    def get_bucket_versioning(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketVersioningOutput:
        """Returns the versioning state of a bucket.

        To retrieve the versioning state of a bucket, you must be the bucket
        owner.

        This implementation also returns the MFA Delete status of the versioning
        state. If the MFA Delete status is ``enabled``, the bucket owner must
        use an authentication device to change the versioning state of the
        bucket.

        The following operations are related to ``GetBucketVersioning``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `DeleteObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>`__

        :param bucket: The name of the bucket for which to get the versioning information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketVersioningOutput
        """
        raise NotImplementedError

    @handler("GetBucketWebsite")
    def get_bucket_website(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetBucketWebsiteOutput:
        """Returns the website configuration for a bucket. To host website on
        Amazon S3, you can configure a bucket as website by adding a website
        configuration. For more information about hosting websites, see `Hosting
        Websites on Amazon
        S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`__.

        This GET action requires the ``S3:GetBucketWebsite`` permission. By
        default, only the bucket owner can read the bucket website
        configuration. However, bucket owners can allow other users to read the
        website configuration by writing a bucket policy granting them the
        ``S3:GetBucketWebsite`` permission.

        The following operations are related to ``DeleteBucketWebsite``:

        -  `DeleteBucketWebsite <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketWebsite.html>`__

        -  `PutBucketWebsite <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html>`__

        :param bucket: The bucket name for which to get the website configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetBucketWebsiteOutput
        """
        raise NotImplementedError

    @handler("GetObject")
    def get_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        if_match: IfMatch = None,
        if_modified_since: IfModifiedSince = None,
        if_none_match: IfNoneMatch = None,
        if_unmodified_since: IfUnmodifiedSince = None,
        range: Range = None,
        response_cache_control: ResponseCacheControl = None,
        response_content_disposition: ResponseContentDisposition = None,
        response_content_encoding: ResponseContentEncoding = None,
        response_content_language: ResponseContentLanguage = None,
        response_content_type: ResponseContentType = None,
        response_expires: ResponseExpires = None,
        version_id: ObjectVersionId = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        part_number: PartNumber = None,
        expected_bucket_owner: AccountId = None,
        checksum_mode: ChecksumMode = None,
    ) -> GetObjectOutput:
        """Retrieves objects from Amazon S3. To use ``GET``, you must have ``READ``
        access to the object. If you grant ``READ`` access to the anonymous
        user, you can return the object without using an authorization header.

        An Amazon S3 bucket has no directory hierarchy such as you would find in
        a typical computer file system. You can, however, create a logical
        hierarchy by using object key names that imply a folder structure. For
        example, instead of naming an object ``sample.jpg``, you can name it
        ``photos/2006/February/sample.jpg``.

        To get an object from such a logical hierarchy, specify the full key
        name for the object in the ``GET`` operation. For a virtual hosted-style
        request example, if you have the object
        ``photos/2006/February/sample.jpg``, specify the resource as
        ``/photos/2006/February/sample.jpg``. For a path-style request example,
        if you have the object ``photos/2006/February/sample.jpg`` in the bucket
        named ``examplebucket``, specify the resource as
        ``/examplebucket/photos/2006/February/sample.jpg``. For more information
        about request types, see `HTTP Host Header Bucket
        Specification <https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket>`__.

        For more information about returning the ACL of an object, see
        `GetObjectAcl <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html>`__.

        If the object you are retrieving is stored in the S3 Glacier or S3
        Glacier Deep Archive storage class, or S3 Intelligent-Tiering Archive or
        S3 Intelligent-Tiering Deep Archive tiers, before you can retrieve the
        object you must first restore a copy using
        `RestoreObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html>`__.
        Otherwise, this action returns an ``InvalidObjectStateError`` error. For
        information about restoring archived objects, see `Restoring Archived
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html>`__.

        Encryption request headers, like ``x-amz-server-side-encryption``,
        should not be sent for GET requests if your object uses server-side
        encryption with KMS keys (SSE-KMS) or server-side encryption with Amazon
        S3–managed encryption keys (SSE-S3). If your object does use these types
        of keys, you’ll get an HTTP 400 BadRequest error.

        If you encrypt an object by using server-side encryption with
        customer-provided encryption keys (SSE-C) when you store the object in
        Amazon S3, then when you GET the object, you must use the following
        headers:

        -  x-amz-server-side-encryption-customer-algorithm

        -  x-amz-server-side-encryption-customer-key

        -  x-amz-server-side-encryption-customer-key-MD5

        For more information about SSE-C, see `Server-Side Encryption (Using
        Customer-Provided Encryption
        Keys) <https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html>`__.

        Assuming you have the relevant permission to read object tags, the
        response also returns the ``x-amz-tagging-count`` header that provides
        the count of number of tags associated with the object. You can use
        `GetObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html>`__
        to retrieve the tag set associated with an object.

        **Permissions**

        You need the relevant read object (or version) permission for this
        operation. For more information, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__.
        If the object you request does not exist, the error Amazon S3 returns
        depends on whether you also have the ``s3:ListBucket`` permission.

        -  If you have the ``s3:ListBucket`` permission on the bucket, Amazon S3
           will return an HTTP status code 404 ("no such key") error.

        -  If you don’t have the ``s3:ListBucket`` permission, Amazon S3 will
           return an HTTP status code 403 ("access denied") error.

        **Versioning**

        By default, the GET action returns the current version of an object. To
        return a different version, use the ``versionId`` subresource.

        -  If you supply a ``versionId``, you need the ``s3:GetObjectVersion``
           permission to access a specific version of an object. If you request
           a specific version, you do not need to have the ``s3:GetObject``
           permission.

        -  If the current version of the object is a delete marker, Amazon S3
           behaves as if the object was deleted and includes
           ``x-amz-delete-marker: true`` in the response.

        For more information about versioning, see
        `PutBucketVersioning <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html>`__.

        **Overriding Response Header Values**

        There are times when you want to override certain response header values
        in a GET response. For example, you might override the
        ``Content-Disposition`` response header value in your GET request.

        You can override values for a set of response headers using the
        following query parameters. These response header values are sent only
        on a successful request, that is, when status code 200 OK is returned.
        The set of headers you can override using these parameters is a subset
        of the headers that Amazon S3 accepts when you create an object. The
        response headers that you can override for the GET response are
        ``Content-Type``, ``Content-Language``, ``Expires``, ``Cache-Control``,
        ``Content-Disposition``, and ``Content-Encoding``. To override these
        header values in the GET response, you use the following request
        parameters.

        You must sign the request, either using an Authorization header or a
        presigned URL, when using these parameters. They cannot be used with an
        unsigned (anonymous) request.

        -  ``response-content-type``

        -  ``response-content-language``

        -  ``response-expires``

        -  ``response-cache-control``

        -  ``response-content-disposition``

        -  ``response-content-encoding``

        **Additional Considerations about Request Headers**

        If both of the ``If-Match`` and ``If-Unmodified-Since`` headers are
        present in the request as follows: ``If-Match`` condition evaluates to
        ``true``, and; ``If-Unmodified-Since`` condition evaluates to ``false``;
        then, S3 returns 200 OK and the data requested.

        If both of the ``If-None-Match`` and ``If-Modified-Since`` headers are
        present in the request as follows:``If-None-Match`` condition evaluates
        to ``false``, and; ``If-Modified-Since`` condition evaluates to
        ``true``; then, S3 returns 304 Not Modified response code.

        For more information about conditional requests, see `RFC
        7232 <https://tools.ietf.org/html/rfc7232>`__.

        The following operations are related to ``GetObject``:

        -  `ListBuckets <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html>`__

        -  `GetObjectAcl <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html>`__

        :param bucket: The bucket name containing the object.
        :param key: Key of the object to get.
        :param if_match: Return the object only if its entity tag (ETag) is the same as the one
        specified; otherwise, return a 412 (precondition failed) error.
        :param if_modified_since: Return the object only if it has been modified since the specified time;
        otherwise, return a 304 (not modified) error.
        :param if_none_match: Return the object only if its entity tag (ETag) is different from the
        one specified; otherwise, return a 304 (not modified) error.
        :param if_unmodified_since: Return the object only if it has not been modified since the specified
        time; otherwise, return a 412 (precondition failed) error.
        :param range: Downloads the specified range bytes of an object.
        :param response_cache_control: Sets the ``Cache-Control`` header of the response.
        :param response_content_disposition: Sets the ``Content-Disposition`` header of the response.
        :param response_content_encoding: Sets the ``Content-Encoding`` header of the response.
        :param response_content_language: Sets the ``Content-Language`` header of the response.
        :param response_content_type: Sets the ``Content-Type`` header of the response.
        :param response_expires: Sets the ``Expires`` header of the response.
        :param version_id: VersionId used to reference a specific version of the object.
        :param sse_customer_algorithm: Specifies the algorithm to use to when decrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 used to
        encrypt the data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param part_number: Part number of the object being read.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param checksum_mode: To retrieve the checksum, this mode must be enabled.
        :returns: GetObjectOutput
        :raises NoSuchKey:
        :raises InvalidObjectState:
        """
        raise NotImplementedError

    @handler("GetObjectAcl")
    def get_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectAclOutput:
        """Returns the access control list (ACL) of an object. To use this
        operation, you must have ``s3:GetObjectAcl`` permissions or ``READ_ACP``
        access to the object. For more information, see `Mapping of ACL
        permissions and access policy
        permissions <https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#acl-access-policy-permission-mapping>`__
        in the *Amazon S3 User Guide*

        This action is not supported by Amazon S3 on Outposts.

        **Versioning**

        By default, GET returns ACL information about the current version of an
        object. To return ACL information about a different version, use the
        versionId subresource.

        If your bucket uses the bucket owner enforced setting for S3 Object
        Ownership, requests to read ACLs are still supported and return the
        ``bucket-owner-full-control`` ACL with the owner being the account that
        created the bucket. For more information, see `Controlling object
        ownership and disabling
        ACLs <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        The following operations are related to ``GetObjectAcl``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        -  `DeleteObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>`__

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        :param bucket: The bucket name that contains the object for which to get the ACL
        information.
        :param key: The key of the object for which to get the ACL information.
        :param version_id: VersionId used to reference a specific version of the object.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetObjectAclOutput
        :raises NoSuchKey:
        """
        raise NotImplementedError

    @handler("GetObjectAttributes")
    def get_object_attributes(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        object_attributes: ObjectAttributesList,
        version_id: ObjectVersionId = None,
        max_parts: MaxParts = None,
        part_number_marker: PartNumberMarker = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectAttributesOutput:
        """Retrieves all the metadata from an object without returning the object
        itself. This action is useful if you're interested only in an object's
        metadata. To use ``GetObjectAttributes``, you must have READ access to
        the object.

        ``GetObjectAttributes`` combines the functionality of ``GetObjectAcl``,
        ``GetObjectLegalHold``, ``GetObjectLockConfiguration``,
        ``GetObjectRetention``, ``GetObjectTagging``, ``HeadObject``, and
        ``ListParts``. All of the data returned with each of those individual
        calls can be returned with a single call to ``GetObjectAttributes``.

        If you encrypt an object by using server-side encryption with
        customer-provided encryption keys (SSE-C) when you store the object in
        Amazon S3, then when you retrieve the metadata from the object, you must
        use the following headers:

        -  ``x-amz-server-side-encryption-customer-algorithm``

        -  ``x-amz-server-side-encryption-customer-key``

        -  ``x-amz-server-side-encryption-customer-key-MD5``

        For more information about SSE-C, see `Server-Side Encryption (Using
        Customer-Provided Encryption
        Keys) <https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html>`__
        in the *Amazon S3 User Guide*.

        -  Encryption request headers, such as ``x-amz-server-side-encryption``,
           should not be sent for GET requests if your object uses server-side
           encryption with Amazon Web Services KMS keys stored in Amazon Web
           Services Key Management Service (SSE-KMS) or server-side encryption
           with Amazon S3 managed encryption keys (SSE-S3). If your object does
           use these types of keys, you'll get an HTTP ``400 Bad Request``
           error.

        -  The last modified property in this case is the creation date of the
           object.

        Consider the following when using request headers:

        -  If both of the ``If-Match`` and ``If-Unmodified-Since`` headers are
           present in the request as follows, then Amazon S3 returns the HTTP
           status code ``200 OK`` and the data requested:

           -  ``If-Match`` condition evaluates to ``true``.

           -  ``If-Unmodified-Since`` condition evaluates to ``false``.

        -  If both of the ``If-None-Match`` and ``If-Modified-Since`` headers
           are present in the request as follows, then Amazon S3 returns the
           HTTP status code ``304 Not Modified``:

           -  ``If-None-Match`` condition evaluates to ``false``.

           -  ``If-Modified-Since`` condition evaluates to ``true``.

        For more information about conditional requests, see `RFC
        7232 <https://tools.ietf.org/html/rfc7232>`__.

        **Permissions**

        The permissions that you need to use this operation depend on whether
        the bucket is versioned. If the bucket is versioned, you need both the
        ``s3:GetObjectVersion`` and ``s3:GetObjectVersionAttributes``
        permissions for this operation. If the bucket is not versioned, you need
        the ``s3:GetObject`` and ``s3:GetObjectAttributes`` permissions. For
        more information, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__
        in the *Amazon S3 User Guide*. If the object that you request does not
        exist, the error Amazon S3 returns depends on whether you also have the
        ``s3:ListBucket`` permission.

        -  If you have the ``s3:ListBucket`` permission on the bucket, Amazon S3
           returns an HTTP status code ``404 Not Found`` ("no such key") error.

        -  If you don't have the ``s3:ListBucket`` permission, Amazon S3 returns
           an HTTP status code ``403 Forbidden`` ("access denied") error.

        The following actions are related to ``GetObjectAttributes``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `GetObjectAcl <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html>`__

        -  `GetObjectLegalHold <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLegalHold.html>`__

        -  `GetObjectLockConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html>`__

        -  `GetObjectRetention <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html>`__

        -  `GetObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html>`__

        -  `HeadObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        :param bucket: The name of the bucket that contains the object.
        :param key: The object key.
        :param object_attributes: An XML header that specifies the fields at the root level that you want
        returned in the response.
        :param version_id: The version ID used to reference a specific version of the object.
        :param max_parts: Sets the maximum number of parts to return.
        :param part_number_marker: Specifies the part after which listing should begin.
        :param sse_customer_algorithm: Specifies the algorithm to use when encrypting the object (for example,
        AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetObjectAttributesOutput
        :raises NoSuchKey:
        """
        raise NotImplementedError

    @handler("GetObjectLegalHold")
    def get_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectLegalHoldOutput:
        """Gets an object's current legal hold status. For more information, see
        `Locking
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`__.

        This action is not supported by Amazon S3 on Outposts.

        The following action is related to ``GetObjectLegalHold``:

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        :param bucket: The bucket name containing the object whose legal hold status you want
        to retrieve.
        :param key: The key name for the object whose legal hold status you want to
        retrieve.
        :param version_id: The version ID of the object whose legal hold status you want to
        retrieve.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetObjectLegalHoldOutput
        """
        raise NotImplementedError

    @handler("GetObjectLockConfiguration")
    def get_object_lock_configuration(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetObjectLockConfigurationOutput:
        """Gets the Object Lock configuration for a bucket. The rule specified in
        the Object Lock configuration will be applied by default to every new
        object placed in the specified bucket. For more information, see
        `Locking
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`__.

        The following action is related to ``GetObjectLockConfiguration``:

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        :param bucket: The bucket whose Object Lock configuration you want to retrieve.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetObjectLockConfigurationOutput
        """
        raise NotImplementedError

    @handler("GetObjectRetention")
    def get_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectRetentionOutput:
        """Retrieves an object's retention settings. For more information, see
        `Locking
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`__.

        This action is not supported by Amazon S3 on Outposts.

        The following action is related to ``GetObjectRetention``:

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        :param bucket: The bucket name containing the object whose retention settings you want
        to retrieve.
        :param key: The key name for the object whose retention settings you want to
        retrieve.
        :param version_id: The version ID for the object whose retention settings you want to
        retrieve.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetObjectRetentionOutput
        """
        raise NotImplementedError

    @handler("GetObjectTagging")
    def get_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> GetObjectTaggingOutput:
        """Returns the tag-set of an object. You send the GET request against the
        tagging subresource associated with the object.

        To use this operation, you must have permission to perform the
        ``s3:GetObjectTagging`` action. By default, the GET action returns
        information about current version of an object. For a versioned bucket,
        you can have multiple versions of an object in your bucket. To retrieve
        tags of any other version, use the versionId query parameter. You also
        need permission for the ``s3:GetObjectVersionTagging`` action.

        By default, the bucket owner has this permission and can grant this
        permission to others.

        For information about the Amazon S3 object tagging feature, see `Object
        Tagging <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-tagging.html>`__.

        The following actions are related to ``GetObjectTagging``:

        -  `DeleteObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html>`__

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        -  `PutObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html>`__

        :param bucket: The bucket name containing the object for which to get the tagging
        information.
        :param key: Object key for which to get the tagging information.
        :param version_id: The versionId of the object for which to get the tagging information.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :returns: GetObjectTaggingOutput
        """
        raise NotImplementedError

    @handler("GetObjectTorrent")
    def get_object_torrent(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectTorrentOutput:
        """Returns torrent files from a bucket. BitTorrent can save you bandwidth
        when you're distributing large files. For more information about
        BitTorrent, see `Using BitTorrent with Amazon
        S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html>`__.

        You can get torrent only for objects that are less than 5 GB in size,
        and that are not encrypted using server-side encryption with a
        customer-provided encryption key.

        To use GET, you must have READ access to the object.

        This action is not supported by Amazon S3 on Outposts.

        The following action is related to ``GetObjectTorrent``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        :param bucket: The name of the bucket containing the object for which to get the
        torrent files.
        :param key: The object key for which to get the information.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetObjectTorrentOutput
        """
        raise NotImplementedError

    @handler("GetPublicAccessBlock")
    def get_public_access_block(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> GetPublicAccessBlockOutput:
        """Retrieves the ``PublicAccessBlock`` configuration for an Amazon S3
        bucket. To use this operation, you must have the
        ``s3:GetBucketPublicAccessBlock`` permission. For more information about
        Amazon S3 permissions, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__.

        When Amazon S3 evaluates the ``PublicAccessBlock`` configuration for a
        bucket or an object, it checks the ``PublicAccessBlock`` configuration
        for both the bucket (or the bucket that contains the object) and the
        bucket owner's account. If the ``PublicAccessBlock`` settings are
        different between the bucket and the account, Amazon S3 uses the most
        restrictive combination of the bucket-level and account-level settings.

        For more information about when Amazon S3 considers a bucket or an
        object public, see `The Meaning of
        "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`__.

        The following operations are related to ``GetPublicAccessBlock``:

        -  `Using Amazon S3 Block Public
           Access <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html>`__

        -  `PutPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html>`__

        -  `GetPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html>`__

        -  `DeletePublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeletePublicAccessBlock.html>`__

        :param bucket: The name of the Amazon S3 bucket whose ``PublicAccessBlock``
        configuration you want to retrieve.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: GetPublicAccessBlockOutput
        """
        raise NotImplementedError

    @handler("HeadBucket")
    def head_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        """This action is useful to determine if a bucket exists and you have
        permission to access it. The action returns a ``200 OK`` if the bucket
        exists and you have permission to access it.

        If the bucket does not exist or you do not have permission to access it,
        the ``HEAD`` request returns a generic ``404 Not Found`` or
        ``403 Forbidden`` code. A message body is not included, so you cannot
        determine the exception beyond these error codes.

        To use this operation, you must have permissions to perform the
        ``s3:ListBucket`` action. The bucket owner has this permission by
        default and can grant this permission to others. For more information
        about permissions, see `Permissions Related to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        To use this API against an access point, you must provide the alias of
        the access point in place of the bucket name or specify the access point
        ARN. When using the access point ARN, you must direct requests to the
        access point hostname. The access point hostname takes the form
        AccessPointName-AccountId.s3-accesspoint.Region.amazonaws.com. When
        using the Amazon Web Services SDKs, you provide the ARN in place of the
        bucket name. For more information see, `Using access
        points <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-access-points.html>`__.

        :param bucket: The bucket name.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :raises NoSuchBucket:
        """
        raise NotImplementedError

    @handler("HeadObject")
    def head_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        if_match: IfMatch = None,
        if_modified_since: IfModifiedSince = None,
        if_none_match: IfNoneMatch = None,
        if_unmodified_since: IfUnmodifiedSince = None,
        range: Range = None,
        version_id: ObjectVersionId = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        part_number: PartNumber = None,
        expected_bucket_owner: AccountId = None,
        checksum_mode: ChecksumMode = None,
    ) -> HeadObjectOutput:
        """The HEAD action retrieves metadata from an object without returning the
        object itself. This action is useful if you're only interested in an
        object's metadata. To use HEAD, you must have READ access to the object.

        A ``HEAD`` request has the same options as a ``GET`` action on an
        object. The response is identical to the ``GET`` response except that
        there is no response body. Because of this, if the ``HEAD`` request
        generates an error, it returns a generic ``404 Not Found`` or
        ``403 Forbidden`` code. It is not possible to retrieve the exact
        exception beyond these error codes.

        If you encrypt an object by using server-side encryption with
        customer-provided encryption keys (SSE-C) when you store the object in
        Amazon S3, then when you retrieve the metadata from the object, you must
        use the following headers:

        -  x-amz-server-side-encryption-customer-algorithm

        -  x-amz-server-side-encryption-customer-key

        -  x-amz-server-side-encryption-customer-key-MD5

        For more information about SSE-C, see `Server-Side Encryption (Using
        Customer-Provided Encryption
        Keys) <https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html>`__.

        -  Encryption request headers, like ``x-amz-server-side-encryption``,
           should not be sent for GET requests if your object uses server-side
           encryption with KMS keys (SSE-KMS) or server-side encryption with
           Amazon S3–managed encryption keys (SSE-S3). If your object does use
           these types of keys, you’ll get an HTTP 400 BadRequest error.

        -  The last modified property in this case is the creation date of the
           object.

        Request headers are limited to 8 KB in size. For more information, see
        `Common Request
        Headers <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTCommonRequestHeaders.html>`__.

        Consider the following when using request headers:

        -  Consideration 1 – If both of the ``If-Match`` and
           ``If-Unmodified-Since`` headers are present in the request as
           follows:

           -  ``If-Match`` condition evaluates to ``true``, and;

           -  ``If-Unmodified-Since`` condition evaluates to ``false``;

           Then Amazon S3 returns ``200 OK`` and the data requested.

        -  Consideration 2 – If both of the ``If-None-Match`` and
           ``If-Modified-Since`` headers are present in the request as follows:

           -  ``If-None-Match`` condition evaluates to ``false``, and;

           -  ``If-Modified-Since`` condition evaluates to ``true``;

           Then Amazon S3 returns the ``304 Not Modified`` response code.

        For more information about conditional requests, see `RFC
        7232 <https://tools.ietf.org/html/rfc7232>`__.

        **Permissions**

        You need the relevant read object (or version) permission for this
        operation. For more information, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__.
        If the object you request does not exist, the error Amazon S3 returns
        depends on whether you also have the s3:ListBucket permission.

        -  If you have the ``s3:ListBucket`` permission on the bucket, Amazon S3
           returns an HTTP status code 404 ("no such key") error.

        -  If you don’t have the ``s3:ListBucket`` permission, Amazon S3 returns
           an HTTP status code 403 ("access denied") error.

        The following actions are related to ``HeadObject``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        :param bucket: The name of the bucket containing the object.
        :param key: The object key.
        :param if_match: Return the object only if its entity tag (ETag) is the same as the one
        specified; otherwise, return a 412 (precondition failed) error.
        :param if_modified_since: Return the object only if it has been modified since the specified time;
        otherwise, return a 304 (not modified) error.
        :param if_none_match: Return the object only if its entity tag (ETag) is different from the
        one specified; otherwise, return a 304 (not modified) error.
        :param if_unmodified_since: Return the object only if it has not been modified since the specified
        time; otherwise, return a 412 (precondition failed) error.
        :param range: Because ``HeadObject`` returns only the metadata for an object, this
        parameter has no effect.
        :param version_id: VersionId used to reference a specific version of the object.
        :param sse_customer_algorithm: Specifies the algorithm to use to when encrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param part_number: Part number of the object being read.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param checksum_mode: To retrieve the checksum, this parameter must be enabled.
        :returns: HeadObjectOutput
        :raises NoSuchKey:
        """
        raise NotImplementedError

    @handler("ListBucketAnalyticsConfigurations")
    def list_bucket_analytics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketAnalyticsConfigurationsOutput:
        """Lists the analytics configurations for the bucket. You can have up to
        1,000 analytics configurations per bucket.

        This action supports list pagination and does not return more than 100
        configurations at a time. You should always check the ``IsTruncated``
        element in the response. If there are no more configurations to list,
        ``IsTruncated`` is set to false. If there are more configurations to
        list, ``IsTruncated`` is set to true, and there will be a value in
        ``NextContinuationToken``. You use the ``NextContinuationToken`` value
        to continue the pagination of the list by passing the value in
        continuation-token in the request to ``GET`` the next page.

        To use this operation, you must have permissions to perform the
        ``s3:GetAnalyticsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about Amazon S3 analytics feature, see `Amazon S3
        Analytics – Storage Class
        Analysis <https://docs.aws.amazon.com/AmazonS3/latest/dev/analytics-storage-class.html>`__.

        The following operations are related to
        ``ListBucketAnalyticsConfigurations``:

        -  `GetBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAnalyticsConfiguration.html>`__

        -  `DeleteBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketAnalyticsConfiguration.html>`__

        -  `PutBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAnalyticsConfiguration.html>`__

        :param bucket: The name of the bucket from which analytics configurations are
        retrieved.
        :param continuation_token: The ContinuationToken that represents a placeholder from where this
        request should begin.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListBucketAnalyticsConfigurationsOutput
        """
        raise NotImplementedError

    @handler("ListBucketIntelligentTieringConfigurations")
    def list_bucket_intelligent_tiering_configurations(
        self, context: RequestContext, bucket: BucketName, continuation_token: Token = None
    ) -> ListBucketIntelligentTieringConfigurationsOutput:
        """Lists the S3 Intelligent-Tiering configuration from the specified
        bucket.

        The S3 Intelligent-Tiering storage class is designed to optimize storage
        costs by automatically moving data to the most cost-effective storage
        access tier, without performance impact or operational overhead. S3
        Intelligent-Tiering delivers automatic cost savings in three low latency
        and high throughput access tiers. To get the lowest storage cost on data
        that can be accessed in minutes to hours, you can choose to activate
        additional archiving capabilities.

        The S3 Intelligent-Tiering storage class is the ideal storage class for
        data with unknown, changing, or unpredictable access patterns,
        independent of object size or retention period. If the size of an object
        is less than 128 KB, it is not monitored and not eligible for
        auto-tiering. Smaller objects can be stored, but they are always charged
        at the Frequent Access tier rates in the S3 Intelligent-Tiering storage
        class.

        For more information, see `Storage class for automatically optimizing
        frequently and infrequently accessed
        objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`__.

        Operations related to ``ListBucketIntelligentTieringConfigurations``
        include:

        -  `DeleteBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketIntelligentTieringConfiguration.html>`__

        -  `PutBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketIntelligentTieringConfiguration.html>`__

        -  `GetBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketIntelligentTieringConfiguration.html>`__

        :param bucket: The name of the Amazon S3 bucket whose configuration you want to modify
        or retrieve.
        :param continuation_token: The ``ContinuationToken`` that represents a placeholder from where this
        request should begin.
        :returns: ListBucketIntelligentTieringConfigurationsOutput
        """
        raise NotImplementedError

    @handler("ListBucketInventoryConfigurations")
    def list_bucket_inventory_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketInventoryConfigurationsOutput:
        """Returns a list of inventory configurations for the bucket. You can have
        up to 1,000 analytics configurations per bucket.

        This action supports list pagination and does not return more than 100
        configurations at a time. Always check the ``IsTruncated`` element in
        the response. If there are no more configurations to list,
        ``IsTruncated`` is set to false. If there are more configurations to
        list, ``IsTruncated`` is set to true, and there is a value in
        ``NextContinuationToken``. You use the ``NextContinuationToken`` value
        to continue the pagination of the list by passing the value in
        continuation-token in the request to ``GET`` the next page.

        To use this operation, you must have permissions to perform the
        ``s3:GetInventoryConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about the Amazon S3 inventory feature, see `Amazon S3
        Inventory <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html>`__

        The following operations are related to
        ``ListBucketInventoryConfigurations``:

        -  `GetBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketInventoryConfiguration.html>`__

        -  `DeleteBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketInventoryConfiguration.html>`__

        -  `PutBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketInventoryConfiguration.html>`__

        :param bucket: The name of the bucket containing the inventory configurations to
        retrieve.
        :param continuation_token: The marker used to continue an inventory configuration listing that has
        been truncated.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListBucketInventoryConfigurationsOutput
        """
        raise NotImplementedError

    @handler("ListBucketMetricsConfigurations")
    def list_bucket_metrics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketMetricsConfigurationsOutput:
        """Lists the metrics configurations for the bucket. The metrics
        configurations are only for the request metrics of the bucket and do not
        provide information on daily storage metrics. You can have up to 1,000
        configurations per bucket.

        This action supports list pagination and does not return more than 100
        configurations at a time. Always check the ``IsTruncated`` element in
        the response. If there are no more configurations to list,
        ``IsTruncated`` is set to false. If there are more configurations to
        list, ``IsTruncated`` is set to true, and there is a value in
        ``NextContinuationToken``. You use the ``NextContinuationToken`` value
        to continue the pagination of the list by passing the value in
        ``continuation-token`` in the request to ``GET`` the next page.

        To use this operation, you must have permissions to perform the
        ``s3:GetMetricsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For more information about metrics configurations and CloudWatch request
        metrics, see `Monitoring Metrics with Amazon
        CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudwatch-monitoring.html>`__.

        The following operations are related to
        ``ListBucketMetricsConfigurations``:

        -  `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketMetricsConfiguration.html>`__

        -  `GetBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketMetricsConfiguration.html>`__

        -  `DeleteBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketMetricsConfiguration.html>`__

        :param bucket: The name of the bucket containing the metrics configurations to
        retrieve.
        :param continuation_token: The marker that is used to continue a metrics configuration listing that
        has been truncated.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListBucketMetricsConfigurationsOutput
        """
        raise NotImplementedError

    @handler("ListBuckets")
    def list_buckets(
        self,
        context: RequestContext,
    ) -> ListBucketsOutput:
        """Returns a list of all buckets owned by the authenticated sender of the
        request. To use this operation, you must have the
        ``s3:ListAllMyBuckets`` permission.

        :returns: ListBucketsOutput
        """
        raise NotImplementedError

    @handler("ListMultipartUploads")
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
    ) -> ListMultipartUploadsOutput:
        """This action lists in-progress multipart uploads. An in-progress
        multipart upload is a multipart upload that has been initiated using the
        Initiate Multipart Upload request, but has not yet been completed or
        aborted.

        This action returns at most 1,000 multipart uploads in the response.
        1,000 multipart uploads is the maximum number of uploads a response can
        include, which is also the default value. You can further limit the
        number of uploads in a response by specifying the ``max-uploads``
        parameter in the response. If additional multipart uploads satisfy the
        list criteria, the response will contain an ``IsTruncated`` element with
        the value true. To list the additional multipart uploads, use the
        ``key-marker`` and ``upload-id-marker`` request parameters.

        In the response, the uploads are sorted by key. If your application has
        initiated more than one multipart upload using the same object key, then
        uploads in the response are first sorted by key. Additionally, uploads
        are sorted in ascending order within each key by the upload initiation
        time.

        For more information on multipart uploads, see `Uploading Objects Using
        Multipart
        Upload <https://docs.aws.amazon.com/AmazonS3/latest/dev/uploadobjusingmpu.html>`__.

        For information on permissions required to use the multipart upload API,
        see `Multipart Upload and
        Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__.

        The following operations are related to ``ListMultipartUploads``:

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        :param bucket: The name of the bucket to which the multipart upload was initiated.
        :param delimiter: Character you use to group keys.
        :param encoding_type: Requests Amazon S3 to encode the object keys in the response and
        specifies the encoding method to use.
        :param key_marker: Together with upload-id-marker, this parameter specifies the multipart
        upload after which listing should begin.
        :param max_uploads: Sets the maximum number of multipart uploads, from 1 to 1,000, to return
        in the response body.
        :param prefix: Lists in-progress uploads only for those keys that begin with the
        specified prefix.
        :param upload_id_marker: Together with key-marker, specifies the multipart upload after which
        listing should begin.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListMultipartUploadsOutput
        """
        raise NotImplementedError

    @handler("ListObjectVersions")
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
    ) -> ListObjectVersionsOutput:
        """Returns metadata about all versions of the objects in a bucket. You can
        also use request parameters as selection criteria to return metadata
        about a subset of all the object versions.

        To use this operation, you must have permissions to perform the
        ``s3:ListBucketVersions`` action. Be aware of the name difference.

        A 200 OK response can contain valid or invalid XML. Make sure to design
        your application to parse the contents of the response and handle it
        appropriately.

        To use this operation, you must have READ access to the bucket.

        This action is not supported by Amazon S3 on Outposts.

        The following operations are related to ``ListObjectVersions``:

        -  `ListObjectsV2 <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html>`__

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `DeleteObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>`__

        :param bucket: The bucket name that contains the objects.
        :param delimiter: A delimiter is a character that you specify to group keys.
        :param encoding_type: Requests Amazon S3 to encode the object keys in the response and
        specifies the encoding method to use.
        :param key_marker: Specifies the key to start with when listing objects in a bucket.
        :param max_keys: Sets the maximum number of keys returned in the response.
        :param prefix: Use this parameter to select only those keys that begin with the
        specified prefix.
        :param version_id_marker: Specifies the object version you want to start listing from.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListObjectVersionsOutput
        """
        raise NotImplementedError

    @handler("ListObjects")
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
    ) -> ListObjectsOutput:
        """Returns some or all (up to 1,000) of the objects in a bucket. You can
        use the request parameters as selection criteria to return a subset of
        the objects in a bucket. A 200 OK response can contain valid or invalid
        XML. Be sure to design your application to parse the contents of the
        response and handle it appropriately.

        This action has been revised. We recommend that you use the newer
        version,
        `ListObjectsV2 <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html>`__,
        when developing applications. For backward compatibility, Amazon S3
        continues to support ``ListObjects``.

        The following operations are related to ``ListObjects``:

        -  `ListObjectsV2 <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html>`__

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `ListBuckets <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html>`__

        :param bucket: The name of the bucket containing the objects.
        :param delimiter: A delimiter is a character you use to group keys.
        :param encoding_type: Requests Amazon S3 to encode the object keys in the response and
        specifies the encoding method to use.
        :param marker: Marker is where you want Amazon S3 to start listing from.
        :param max_keys: Sets the maximum number of keys returned in the response.
        :param prefix: Limits the response to keys that begin with the specified prefix.
        :param request_payer: Confirms that the requester knows that she or he will be charged for the
        list objects request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListObjectsOutput
        :raises NoSuchBucket:
        """
        raise NotImplementedError

    @handler("ListObjectsV2")
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
    ) -> ListObjectsV2Output:
        """Returns some or all (up to 1,000) of the objects in a bucket with each
        request. You can use the request parameters as selection criteria to
        return a subset of the objects in a bucket. A ``200 OK`` response can
        contain valid or invalid XML. Make sure to design your application to
        parse the contents of the response and handle it appropriately. Objects
        are returned sorted in an ascending order of the respective key names in
        the list. For more information about listing objects, see `Listing
        object keys
        programmatically <https://docs.aws.amazon.com/AmazonS3/latest/userguide/ListingKeysUsingAPIs.html>`__

        To use this operation, you must have READ access to the bucket.

        To use this action in an Identity and Access Management (IAM) policy,
        you must have permissions to perform the ``s3:ListBucket`` action. The
        bucket owner has this permission by default and can grant this
        permission to others. For more information about permissions, see
        `Permissions Related to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        This section describes the latest revision of this action. We recommend
        that you use this revised API for application development. For backward
        compatibility, Amazon S3 continues to support the prior version of this
        API,
        `ListObjects <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html>`__.

        To get a list of your buckets, see
        `ListBuckets <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html>`__.

        The following operations are related to ``ListObjectsV2``:

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        :param bucket: Bucket name to list.
        :param delimiter: A delimiter is a character you use to group keys.
        :param encoding_type: Encoding type used by Amazon S3 to encode object keys in the response.
        :param max_keys: Sets the maximum number of keys returned in the response.
        :param prefix: Limits the response to keys that begin with the specified prefix.
        :param continuation_token: ContinuationToken indicates Amazon S3 that the list is being continued
        on this bucket with a token.
        :param fetch_owner: The owner field is not present in listV2 by default, if you want to
        return owner field with each key in the result then set the fetch owner
        field to true.
        :param start_after: StartAfter is where you want Amazon S3 to start listing from.
        :param request_payer: Confirms that the requester knows that she or he will be charged for the
        list objects request in V2 style.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: ListObjectsV2Output
        :raises NoSuchBucket:
        """
        raise NotImplementedError

    @handler("ListParts")
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
        """Lists the parts that have been uploaded for a specific multipart upload.
        This operation must include the upload ID, which you obtain by sending
        the initiate multipart upload request (see
        `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__).
        This request returns a maximum of 1,000 uploaded parts. The default
        number of parts returned is 1,000 parts. You can restrict the number of
        parts returned by specifying the ``max-parts`` request parameter. If
        your multipart upload consists of more than 1,000 parts, the response
        returns an ``IsTruncated`` field with the value of true, and a
        ``NextPartNumberMarker`` element. In subsequent ``ListParts`` requests
        you can include the part-number-marker query string parameter and set
        its value to the ``NextPartNumberMarker`` field value from the previous
        response.

        If the upload was created using a checksum algorithm, you will need to
        have permission to the ``kms:Decrypt`` action for the request to
        succeed.

        For more information on multipart uploads, see `Uploading Objects Using
        Multipart
        Upload <https://docs.aws.amazon.com/AmazonS3/latest/dev/uploadobjusingmpu.html>`__.

        For information on permissions required to use the multipart upload API,
        see `Multipart Upload and
        Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__.

        The following operations are related to ``ListParts``:

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        -  `GetObjectAttributes <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html>`__

        -  `ListMultipartUploads <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html>`__

        :param bucket: The name of the bucket to which the parts are being uploaded.
        :param key: Object key for which the multipart upload was initiated.
        :param upload_id: Upload ID identifying the multipart upload whose parts are being listed.
        :param max_parts: Sets the maximum number of parts to return.
        :param part_number_marker: Specifies the part after which listing should begin.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param sse_customer_algorithm: The server-side encryption (SSE) algorithm used to encrypt the object.
        :param sse_customer_key: The server-side encryption (SSE) customer managed key.
        :param sse_customer_key_md5: The MD5 server-side encryption (SSE) customer managed key.
        :returns: ListPartsOutput
        """
        raise NotImplementedError

    @handler("PutBucketAccelerateConfiguration")
    def put_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        accelerate_configuration: AccelerateConfiguration,
        expected_bucket_owner: AccountId = None,
        checksum_algorithm: ChecksumAlgorithm = None,
    ) -> None:
        """Sets the accelerate configuration of an existing bucket. Amazon S3
        Transfer Acceleration is a bucket-level feature that enables you to
        perform faster data transfers to Amazon S3.

        To use this operation, you must have permission to perform the
        ``s3:PutAccelerateConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        The Transfer Acceleration state of a bucket can be set to one of the
        following two values:

        -  Enabled – Enables accelerated data transfers to the bucket.

        -  Suspended – Disables accelerated data transfers to the bucket.

        The
        `GetBucketAccelerateConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAccelerateConfiguration.html>`__
        action returns the transfer acceleration state of a bucket.

        After setting the Transfer Acceleration state of a bucket to Enabled, it
        might take up to thirty minutes before the data transfer rates to the
        bucket increase.

        The name of the bucket used for Transfer Acceleration must be
        DNS-compliant and must not contain periods (".").

        For more information about transfer acceleration, see `Transfer
        Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`__.

        The following operations are related to
        ``PutBucketAccelerateConfiguration``:

        -  `GetBucketAccelerateConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAccelerateConfiguration.html>`__

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        :param bucket: The name of the bucket for which the accelerate configuration is set.
        :param accelerate_configuration: Container for setting the transfer acceleration state.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        """
        raise NotImplementedError

    @handler("PutBucketAcl")
    def put_bucket_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL = None,
        access_control_policy: AccessControlPolicy = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets the permissions on an existing bucket using access control lists
        (ACL). For more information, see `Using
        ACLs <https://docs.aws.amazon.com/AmazonS3/latest/dev/S3_ACLs_UsingACLs.html>`__.
        To set the ACL of a bucket, you must have ``WRITE_ACP`` permission.

        You can use one of the following two ways to set a bucket's permissions:

        -  Specify the ACL in the request body

        -  Specify permissions using request headers

        You cannot specify access permission using both the body and the request
        headers.

        Depending on your application needs, you may choose to set the ACL on a
        bucket using either the request body or the headers. For example, if you
        have an existing application that updates a bucket ACL using the request
        body, then you can continue to use that approach.

        If your bucket uses the bucket owner enforced setting for S3 Object
        Ownership, ACLs are disabled and no longer affect permissions. You must
        use policies to grant access to your bucket and the objects in it.
        Requests to set ACLs or update ACLs fail and return the
        ``AccessControlListNotSupported`` error code. Requests to read ACLs are
        still supported. For more information, see `Controlling object
        ownership <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        **Access Permissions**

        You can set access permissions using one of the following methods:

        -  Specify a canned ACL with the ``x-amz-acl`` request header. Amazon S3
           supports a set of predefined ACLs, known as *canned ACLs*. Each
           canned ACL has a predefined set of grantees and permissions. Specify
           the canned ACL name as the value of ``x-amz-acl``. If you use this
           header, you cannot use other access control-specific headers in your
           request. For more information, see `Canned
           ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#CannedACL>`__.

        -  Specify access permissions explicitly with the ``x-amz-grant-read``,
           ``x-amz-grant-read-acp``, ``x-amz-grant-write-acp``, and
           ``x-amz-grant-full-control`` headers. When using these headers, you
           specify explicit access permissions and grantees (Amazon Web Services
           accounts or Amazon S3 groups) who will receive the permission. If you
           use these ACL-specific headers, you cannot use the ``x-amz-acl``
           header to set a canned ACL. These parameters map to the set of
           permissions that Amazon S3 supports in an ACL. For more information,
           see `Access Control List (ACL)
           Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__.

           You specify each grantee as a type=value pair, where the type is one
           of the following:

           -  ``id`` – if the value specified is the canonical user ID of an
              Amazon Web Services account

           -  ``uri`` – if you are granting permissions to a predefined group

           -  ``emailAddress`` – if the value specified is the email address of
              an Amazon Web Services account

              Using email addresses to specify a grantee is only supported in
              the following Amazon Web Services Regions:

              -  US East (N. Virginia)

              -  US West (N. California)

              -  US West (Oregon)

              -  Asia Pacific (Singapore)

              -  Asia Pacific (Sydney)

              -  Asia Pacific (Tokyo)

              -  Europe (Ireland)

              -  South America (São Paulo)

              For a list of all the Amazon S3 supported Regions and endpoints,
              see `Regions and
              Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region>`__
              in the Amazon Web Services General Reference.

           For example, the following ``x-amz-grant-write`` header grants
           create, overwrite, and delete objects permission to LogDelivery group
           predefined by Amazon S3 and two Amazon Web Services accounts
           identified by their email addresses.

           ``x-amz-grant-write: uri="http://acs.amazonaws.com/groups/s3/LogDelivery", id="111122223333", id="555566667777"``

        You can use either a canned ACL or specify access permissions
        explicitly. You cannot do both.

        **Grantee Values**

        You can specify the person (grantee) to whom you're assigning access
        rights (using request elements) in the following ways:

        -  By the person's ID:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID><>ID<></ID><DisplayName><>GranteesEmail<></DisplayName> </Grantee>``

           DisplayName is optional and ignored in the request

        -  By URI:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI><>http://acs.amazonaws.com/groups/global/AuthenticatedUsers<></URI></Grantee>``

        -  By Email address:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="AmazonCustomerByEmail"><EmailAddress><>Grantees@email.com<></EmailAddress>lt;/Grantee>``

           The grantee is resolved to the CanonicalUser and, in a response to a
           GET Object acl request, appears as the CanonicalUser.

           Using email addresses to specify a grantee is only supported in the
           following Amazon Web Services Regions:

           -  US East (N. Virginia)

           -  US West (N. California)

           -  US West (Oregon)

           -  Asia Pacific (Singapore)

           -  Asia Pacific (Sydney)

           -  Asia Pacific (Tokyo)

           -  Europe (Ireland)

           -  South America (São Paulo)

           For a list of all the Amazon S3 supported Regions and endpoints, see
           `Regions and
           Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region>`__
           in the Amazon Web Services General Reference.

        **Related Resources**

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `DeleteBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html>`__

        -  `GetObjectAcl <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html>`__

        :param bucket: The bucket to which to apply the ACL.
        :param acl: The canned ACL to apply to the bucket.
        :param access_control_policy: Contains the elements that set the ACL permissions for an object per
        grantee.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param grant_full_control: Allows grantee the read, write, read ACP, and write ACP permissions on
        the bucket.
        :param grant_read: Allows grantee to list the objects in the bucket.
        :param grant_read_acp: Allows grantee to read the bucket ACL.
        :param grant_write: Allows grantee to create new objects in the bucket.
        :param grant_write_acp: Allows grantee to write the ACL for the applicable bucket.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketAnalyticsConfiguration")
    def put_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        analytics_configuration: AnalyticsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets an analytics configuration for the bucket (specified by the
        analytics configuration ID). You can have up to 1,000 analytics
        configurations per bucket.

        You can choose to have storage class analysis export analysis reports
        sent to a comma-separated values (CSV) flat file. See the ``DataExport``
        request element. Reports are updated daily and are based on the object
        filters that you configure. When selecting data export, you specify a
        destination bucket and an optional destination prefix where the file is
        written. You can export the data to a destination bucket in a different
        account. However, the destination bucket must be in the same Region as
        the bucket that you are making the PUT analytics configuration to. For
        more information, see `Amazon S3 Analytics – Storage Class
        Analysis <https://docs.aws.amazon.com/AmazonS3/latest/dev/analytics-storage-class.html>`__.

        You must create a bucket policy on the destination bucket where the
        exported file is written to grant permissions to Amazon S3 to write
        objects to the bucket. For an example policy, see `Granting Permissions
        for Amazon S3 Inventory and Storage Class
        Analysis <https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html#example-bucket-policies-use-case-9>`__.

        To use this operation, you must have permissions to perform the
        ``s3:PutAnalyticsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        **Special Errors**

        -

           -  *HTTP Error: HTTP 400 Bad Request*

           -  *Code: InvalidArgument*

           -  *Cause: Invalid argument.*

        -

           -  *HTTP Error: HTTP 400 Bad Request*

           -  *Code: TooManyConfigurations*

           -  *Cause: You are attempting to create a new configuration but have
              already reached the 1,000-configuration limit.*

        -

           -  *HTTP Error: HTTP 403 Forbidden*

           -  *Code: AccessDenied*

           -  *Cause: You are not the owner of the specified bucket, or you do
              not have the s3:PutAnalyticsConfiguration bucket permission to set
              the configuration on the bucket.*

        **Related Resources**

        -  `GetBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAnalyticsConfiguration.html>`__

        -  `DeleteBucketAnalyticsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketAnalyticsConfiguration.html>`__

        -  `ListBucketAnalyticsConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketAnalyticsConfigurations.html>`__

        :param bucket: The name of the bucket to which an analytics configuration is stored.
        :param id: The ID that identifies the analytics configuration.
        :param analytics_configuration: The configuration and any analyses for the analytics filter.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketCors")
    def put_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        cors_configuration: CORSConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets the ``cors`` configuration for your bucket. If the configuration
        exists, Amazon S3 replaces it.

        To use this operation, you must be allowed to perform the
        ``s3:PutBucketCORS`` action. By default, the bucket owner has this
        permission and can grant it to others.

        You set this configuration on a bucket so that the bucket can service
        cross-origin requests. For example, you might want to enable a request
        whose origin is ``http://www.example.com`` to access your Amazon S3
        bucket at ``my.example.bucket.com`` by using the browser's
        ``XMLHttpRequest`` capability.

        To enable cross-origin resource sharing (CORS) on a bucket, you add the
        ``cors`` subresource to the bucket. The ``cors`` subresource is an XML
        document in which you configure rules that identify origins and the HTTP
        methods that can be executed on your bucket. The document is limited to
        64 KB in size.

        When Amazon S3 receives a cross-origin request (or a pre-flight OPTIONS
        request) against a bucket, it evaluates the ``cors`` configuration on
        the bucket and uses the first ``CORSRule`` rule that matches the
        incoming browser request to enable a cross-origin request. For a rule to
        match, the following conditions must be met:

        -  The request's ``Origin`` header must match ``AllowedOrigin``
           elements.

        -  The request method (for example, GET, PUT, HEAD, and so on) or the
           ``Access-Control-Request-Method`` header in case of a pre-flight
           ``OPTIONS`` request must be one of the ``AllowedMethod`` elements.

        -  Every header specified in the ``Access-Control-Request-Headers``
           request header of a pre-flight request must match an
           ``AllowedHeader`` element.

        For more information about CORS, go to `Enabling Cross-Origin Resource
        Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`__
        in the *Amazon S3 User Guide*.

        **Related Resources**

        -  `GetBucketCors <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html>`__

        -  `DeleteBucketCors <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html>`__

        -  `RESTOPTIONSobject <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTOPTIONSobject.html>`__

        :param bucket: Specifies the bucket impacted by the ``cors`` configuration.
        :param cors_configuration: Describes the cross-origin access configuration for objects in an Amazon
        S3 bucket.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketEncryption")
    def put_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        server_side_encryption_configuration: ServerSideEncryptionConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """This action uses the ``encryption`` subresource to configure default
        encryption and Amazon S3 Bucket Key for an existing bucket.

        Default encryption for a bucket can use server-side encryption with
        Amazon S3-managed keys (SSE-S3) or customer managed keys (SSE-KMS). If
        you specify default encryption using SSE-KMS, you can also configure
        Amazon S3 Bucket Key. When the default encryption is SSE-KMS, if you
        upload an object to the bucket and do not specify the KMS key to use for
        encryption, Amazon S3 uses the default Amazon Web Services managed KMS
        key for your account. For information about default encryption, see
        `Amazon S3 default bucket
        encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`__
        in the *Amazon S3 User Guide*. For more information about S3 Bucket
        Keys, see `Amazon S3 Bucket
        Keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-key.html>`__
        in the *Amazon S3 User Guide*.

        This action requires Amazon Web Services Signature Version 4. For more
        information, see `Authenticating Requests (Amazon Web Services Signature
        Version
        4) <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html>`__.

        To use this operation, you must have permissions to perform the
        ``s3:PutEncryptionConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the Amazon S3 User Guide.

        **Related Resources**

        -  `GetBucketEncryption <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html>`__

        -  `DeleteBucketEncryption <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html>`__

        :param bucket: Specifies default encryption for a bucket using server-side encryption
        with Amazon S3-managed keys (SSE-S3) or customer managed keys (SSE-KMS).
        :param server_side_encryption_configuration: Specifies the default server-side-encryption configuration.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the server-side encryption
        configuration.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketIntelligentTieringConfiguration")
    def put_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        intelligent_tiering_configuration: IntelligentTieringConfiguration,
    ) -> None:
        """Puts a S3 Intelligent-Tiering configuration to the specified bucket. You
        can have up to 1,000 S3 Intelligent-Tiering configurations per bucket.

        The S3 Intelligent-Tiering storage class is designed to optimize storage
        costs by automatically moving data to the most cost-effective storage
        access tier, without performance impact or operational overhead. S3
        Intelligent-Tiering delivers automatic cost savings in three low latency
        and high throughput access tiers. To get the lowest storage cost on data
        that can be accessed in minutes to hours, you can choose to activate
        additional archiving capabilities.

        The S3 Intelligent-Tiering storage class is the ideal storage class for
        data with unknown, changing, or unpredictable access patterns,
        independent of object size or retention period. If the size of an object
        is less than 128 KB, it is not monitored and not eligible for
        auto-tiering. Smaller objects can be stored, but they are always charged
        at the Frequent Access tier rates in the S3 Intelligent-Tiering storage
        class.

        For more information, see `Storage class for automatically optimizing
        frequently and infrequently accessed
        objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`__.

        Operations related to ``PutBucketIntelligentTieringConfiguration``
        include:

        -  `DeleteBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketIntelligentTieringConfiguration.html>`__

        -  `GetBucketIntelligentTieringConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketIntelligentTieringConfiguration.html>`__

        -  `ListBucketIntelligentTieringConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketIntelligentTieringConfigurations.html>`__

        You only need S3 Intelligent-Tiering enabled on a bucket if you want to
        automatically move objects stored in the S3 Intelligent-Tiering storage
        class to the Archive Access or Deep Archive Access tier.

        **Special Errors**

        -  **HTTP 400 Bad Request Error**

           -  *Code:* InvalidArgument

           -  *Cause:* Invalid Argument

        -  **HTTP 400 Bad Request Error**

           -  *Code:* TooManyConfigurations

           -  *Cause:* You are attempting to create a new configuration but have
              already reached the 1,000-configuration limit.

        -  **HTTP 403 Forbidden Error**

           -  *Code:* AccessDenied

           -  *Cause:* You are not the owner of the specified bucket, or you do
              not have the ``s3:PutIntelligentTieringConfiguration`` bucket
              permission to set the configuration on the bucket.

        :param bucket: The name of the Amazon S3 bucket whose configuration you want to modify
        or retrieve.
        :param id: The ID used to identify the S3 Intelligent-Tiering configuration.
        :param intelligent_tiering_configuration: Container for S3 Intelligent-Tiering configuration.
        """
        raise NotImplementedError

    @handler("PutBucketInventoryConfiguration")
    def put_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        inventory_configuration: InventoryConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """This implementation of the ``PUT`` action adds an inventory
        configuration (identified by the inventory ID) to the bucket. You can
        have up to 1,000 inventory configurations per bucket.

        Amazon S3 inventory generates inventories of the objects in the bucket
        on a daily or weekly basis, and the results are published to a flat
        file. The bucket that is inventoried is called the *source* bucket, and
        the bucket where the inventory flat file is stored is called the
        *destination* bucket. The *destination* bucket must be in the same
        Amazon Web Services Region as the *source* bucket.

        When you configure an inventory for a *source* bucket, you specify the
        *destination* bucket where you want the inventory to be stored, and
        whether to generate the inventory daily or weekly. You can also
        configure what object metadata to include and whether to inventory all
        object versions or only current versions. For more information, see
        `Amazon S3
        Inventory <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html>`__
        in the Amazon S3 User Guide.

        You must create a bucket policy on the *destination* bucket to grant
        permissions to Amazon S3 to write objects to the bucket in the defined
        location. For an example policy, see `Granting Permissions for Amazon S3
        Inventory and Storage Class
        Analysis <https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html#example-bucket-policies-use-case-9>`__.

        To use this operation, you must have permissions to perform the
        ``s3:PutInventoryConfiguration`` action. The bucket owner has this
        permission by default and can grant this permission to others. For more
        information about permissions, see `Permissions Related to Bucket
        Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the Amazon S3 User Guide.

        **Special Errors**

        -  **HTTP 400 Bad Request Error**

           -  *Code:* InvalidArgument

           -  *Cause:* Invalid Argument

        -  **HTTP 400 Bad Request Error**

           -  *Code:* TooManyConfigurations

           -  *Cause:* You are attempting to create a new configuration but have
              already reached the 1,000-configuration limit.

        -  **HTTP 403 Forbidden Error**

           -  *Code:* AccessDenied

           -  *Cause:* You are not the owner of the specified bucket, or you do
              not have the ``s3:PutInventoryConfiguration`` bucket permission to
              set the configuration on the bucket.

        **Related Resources**

        -  `GetBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketInventoryConfiguration.html>`__

        -  `DeleteBucketInventoryConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketInventoryConfiguration.html>`__

        -  `ListBucketInventoryConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketInventoryConfigurations.html>`__

        :param bucket: The name of the bucket where the inventory configuration will be stored.
        :param id: The ID used to identify the inventory configuration.
        :param inventory_configuration: Specifies the inventory configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketLifecycle")
    def put_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        lifecycle_configuration: LifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """For an updated version of this API, see
        `PutBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html>`__.
        This version has been deprecated. Existing lifecycle configurations will
        work. For new lifecycle configurations, use the updated API.

        Creates a new lifecycle configuration for the bucket or replaces an
        existing lifecycle configuration. For information about lifecycle
        configuration, see `Object Lifecycle
        Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`__
        in the *Amazon S3 User Guide*.

        By default, all Amazon S3 resources, including buckets, objects, and
        related subresources (for example, lifecycle configuration and website
        configuration) are private. Only the resource owner, the Amazon Web
        Services account that created the resource, can access it. The resource
        owner can optionally grant access permissions to others by writing an
        access policy. For this operation, users must get the
        ``s3:PutLifecycleConfiguration`` permission.

        You can also explicitly deny permissions. Explicit denial also
        supersedes any other permissions. If you want to prevent users or
        accounts from removing or deleting objects from your bucket, you must
        deny them permissions for the following actions:

        -  ``s3:DeleteObject``

        -  ``s3:DeleteObjectVersion``

        -  ``s3:PutLifecycleConfiguration``

        For more information about permissions, see `Managing Access Permissions
        to your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the *Amazon S3 User Guide*.

        For more examples of transitioning objects to storage classes such as
        STANDARD_IA or ONEZONE_IA, see `Examples of Lifecycle
        Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html#lifecycle-configuration-examples>`__.

        **Related Resources**

        -  `GetBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html>`__ (Deprecated)

        -  `GetBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html>`__

        -  `RestoreObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html>`__

        -  By default, a resource owner—in this case, a bucket owner, which is
           the Amazon Web Services account that created the bucket—can perform
           any of the operations. A resource owner can also grant others
           permission to perform the operation. For more information, see the
           following topics in the Amazon S3 User Guide:

           -  `Specifying Permissions in a
              Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__

           -  `Managing Access Permissions to your Amazon S3
              Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__

        :param bucket: .
        :param content_md5: For requests made using the Amazon Web Services Command Line Interface
        (CLI) or Amazon Web Services SDKs, this field is calculated
        automatically.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param lifecycle_configuration: .
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketLifecycleConfiguration")
    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        checksum_algorithm: ChecksumAlgorithm = None,
        lifecycle_configuration: BucketLifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Creates a new lifecycle configuration for the bucket or replaces an
        existing lifecycle configuration. Keep in mind that this will overwrite
        an existing lifecycle configuration, so if you want to retain any
        configuration details, they must be included in the new lifecycle
        configuration. For information about lifecycle configuration, see
        `Managing your storage
        lifecycle <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html>`__.

        Bucket lifecycle configuration now supports specifying a lifecycle rule
        using an object key name prefix, one or more object tags, or a
        combination of both. Accordingly, this section describes the latest API.
        The previous version of the API supported filtering based only on an
        object key name prefix, which is supported for backward compatibility.
        For the related API description, see
        `PutBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycle.html>`__.

        **Rules**

        You specify the lifecycle configuration in your request body. The
        lifecycle configuration is specified as XML consisting of one or more
        rules. An Amazon S3 Lifecycle configuration can have up to 1,000 rules.
        This limit is not adjustable. Each rule consists of the following:

        -  Filter identifying a subset of objects to which the rule applies. The
           filter can be based on a key name prefix, object tags, or a
           combination of both.

        -  Status whether the rule is in effect.

        -  One or more lifecycle transition and expiration actions that you want
           Amazon S3 to perform on the objects identified by the filter. If the
           state of your bucket is versioning-enabled or versioning-suspended,
           you can have many versions of the same object (one current version
           and zero or more noncurrent versions). Amazon S3 provides predefined
           actions that you can specify for current and noncurrent object
           versions.

        For more information, see `Object Lifecycle
        Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`__
        and `Lifecycle Configuration
        Elements <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html>`__.

        **Permissions**

        By default, all Amazon S3 resources are private, including buckets,
        objects, and related subresources (for example, lifecycle configuration
        and website configuration). Only the resource owner (that is, the Amazon
        Web Services account that created it) can access the resource. The
        resource owner can optionally grant access permissions to others by
        writing an access policy. For this operation, a user must get the
        ``s3:PutLifecycleConfiguration`` permission.

        You can also explicitly deny permissions. Explicit deny also supersedes
        any other permissions. If you want to block users or accounts from
        removing or deleting objects from your bucket, you must deny them
        permissions for the following actions:

        -  ``s3:DeleteObject``

        -  ``s3:DeleteObjectVersion``

        -  ``s3:PutLifecycleConfiguration``

        For more information about permissions, see `Managing Access Permissions
        to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        The following are related to ``PutBucketLifecycleConfiguration``:

        -  `Examples of Lifecycle
           Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/lifecycle-configuration-examples.html>`__

        -  `GetBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html>`__

        -  `DeleteBucketLifecycle <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html>`__

        :param bucket: The name of the bucket for which to set the configuration.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param lifecycle_configuration: Container for lifecycle rules.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketLogging")
    def put_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        bucket_logging_status: BucketLoggingStatus,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Set the logging parameters for a bucket and to specify permissions for
        who can view and modify the logging parameters. All logs are saved to
        buckets in the same Amazon Web Services Region as the source bucket. To
        set the logging status of a bucket, you must be the bucket owner.

        The bucket owner is automatically granted FULL_CONTROL to all logs. You
        use the ``Grantee`` request element to grant access to other people. The
        ``Permissions`` request element specifies the kind of access the grantee
        has to the logs.

        If the target bucket for log delivery uses the bucket owner enforced
        setting for S3 Object Ownership, you can't use the ``Grantee`` request
        element to grant access to others. Permissions can only be granted using
        policies. For more information, see `Permissions for server access log
        delivery <https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html#grant-log-delivery-permissions-general>`__
        in the *Amazon S3 User Guide*.

        **Grantee Values**

        You can specify the person (grantee) to whom you're assigning access
        rights (using request elements) in the following ways:

        -  By the person's ID:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID><>ID<></ID><DisplayName><>GranteesEmail<></DisplayName> </Grantee>``

           DisplayName is optional and ignored in the request.

        -  By Email address:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="AmazonCustomerByEmail"><EmailAddress><>Grantees@email.com<></EmailAddress></Grantee>``

           The grantee is resolved to the CanonicalUser and, in a response to a
           GET Object acl request, appears as the CanonicalUser.

        -  By URI:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI><>http://acs.amazonaws.com/groups/global/AuthenticatedUsers<></URI></Grantee>``

        To enable logging, you use LoggingEnabled and its children request
        elements. To disable logging, you use an empty BucketLoggingStatus
        request element:

        ``<BucketLoggingStatus xmlns="http://doc.s3.amazonaws.com/2006-03-01" />``

        For more information about server access logging, see `Server Access
        Logging <https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html>`__
        in the *Amazon S3 User Guide*.

        For more information about creating a bucket, see
        `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__.
        For more information about returning the logging status of a bucket, see
        `GetBucketLogging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html>`__.

        The following operations are related to ``PutBucketLogging``:

        -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

        -  `DeleteBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html>`__

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `GetBucketLogging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html>`__

        :param bucket: The name of the bucket for which to set the logging parameters.
        :param bucket_logging_status: Container for logging status information.
        :param content_md5: The MD5 hash of the ``PutBucketLogging`` request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketMetricsConfiguration")
    def put_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        metrics_configuration: MetricsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets a metrics configuration (specified by the metrics configuration ID)
        for the bucket. You can have up to 1,000 metrics configurations per
        bucket. If you're updating an existing metrics configuration, note that
        this is a full replacement of the existing metrics configuration. If you
        don't include the elements you want to keep, they are erased.

        To use this operation, you must have permissions to perform the
        ``s3:PutMetricsConfiguration`` action. The bucket owner has this
        permission by default. The bucket owner can grant this permission to
        others. For more information about permissions, see `Permissions Related
        to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        For information about CloudWatch request metrics for Amazon S3, see
        `Monitoring Metrics with Amazon
        CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudwatch-monitoring.html>`__.

        The following operations are related to
        ``PutBucketMetricsConfiguration``:

        -  `DeleteBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketMetricsConfiguration.html>`__

        -  `GetBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketMetricsConfiguration.html>`__

        -  `ListBucketMetricsConfigurations <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketMetricsConfigurations.html>`__

        ``GetBucketLifecycle`` has the following special error:

        -  Error code: ``TooManyConfigurations``

           -  Description: You are attempting to create a new configuration but
              have already reached the 1,000-configuration limit.

           -  HTTP Status Code: HTTP 400 Bad Request

        :param bucket: The name of the bucket for which the metrics configuration is set.
        :param id: The ID used to identify the metrics configuration.
        :param metrics_configuration: Specifies the metrics configuration.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketNotification")
    def put_bucket_notification(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfigurationDeprecated,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """No longer used, see the
        `PutBucketNotificationConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html>`__
        operation.

        :param bucket: The name of the bucket.
        :param notification_configuration: The container for the configuration.
        :param content_md5: The MD5 hash of the ``PutPublicAccessBlock`` request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketNotificationConfiguration")
    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId = None,
        skip_destination_validation: SkipValidation = None,
    ) -> None:
        """Enables notifications of specified events for a bucket. For more
        information about event notifications, see `Configuring Event
        Notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`__.

        Using this API, you can replace an existing notification configuration.
        The configuration is an XML file that defines the event types that you
        want Amazon S3 to publish and the destination where you want Amazon S3
        to publish an event notification when it detects an event of the
        specified type.

        By default, your bucket has no event notifications configured. That is,
        the notification configuration will be an empty
        ``NotificationConfiguration``.

        ``<NotificationConfiguration>``

        ``</NotificationConfiguration>``

        This action replaces the existing notification configuration with the
        configuration you include in the request body.

        After Amazon S3 receives this request, it first verifies that any Amazon
        Simple Notification Service (Amazon SNS) or Amazon Simple Queue Service
        (Amazon SQS) destination exists, and that the bucket owner has
        permission to publish to it by sending a test notification. In the case
        of Lambda destinations, Amazon S3 verifies that the Lambda function
        permissions grant Amazon S3 permission to invoke the function from the
        Amazon S3 bucket. For more information, see `Configuring Notifications
        for Amazon S3
        Events <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`__.

        You can disable notifications by adding the empty
        NotificationConfiguration element.

        For more information about the number of event notification
        configurations that you can create per bucket, see `Amazon S3 service
        quotas <https://docs.aws.amazon.com/general/latest/gr/s3.html#limits_s3>`__
        in *Amazon Web Services General Reference*.

        By default, only the bucket owner can configure notifications on a
        bucket. However, bucket owners can use a bucket policy to grant
        permission to other users to set this configuration with
        ``s3:PutBucketNotification`` permission.

        The PUT notification is an atomic operation. For example, suppose your
        notification configuration includes SNS topic, SQS queue, and Lambda
        function configurations. When you send a PUT request with this
        configuration, Amazon S3 sends test messages to your SNS topic. If the
        message fails, the entire PUT action will fail, and Amazon S3 will not
        add the configuration to your bucket.

        **Responses**

        If the configuration in the request body includes only one
        ``TopicConfiguration`` specifying only the
        ``s3:ReducedRedundancyLostObject`` event type, the response will also
        include the ``x-amz-sns-test-message-id`` header containing the message
        ID of the test notification sent to the topic.

        The following action is related to
        ``PutBucketNotificationConfiguration``:

        -  `GetBucketNotificationConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketNotificationConfiguration.html>`__

        :param bucket: The name of the bucket.
        :param notification_configuration: A container for specifying the notification configuration of the bucket.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param skip_destination_validation: Skips validation of Amazon SQS, Amazon SNS, and Lambda destinations.
        """
        raise NotImplementedError

    @handler("PutBucketOwnershipControls")
    def put_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        ownership_controls: OwnershipControls,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Creates or modifies ``OwnershipControls`` for an Amazon S3 bucket. To
        use this operation, you must have the ``s3:PutBucketOwnershipControls``
        permission. For more information about Amazon S3 permissions, see
        `Specifying permissions in a
        policy <https://docs.aws.amazon.com/AmazonS3/latest/user-guide/using-with-s3-actions.html>`__.

        For information about Amazon S3 Object Ownership, see `Using object
        ownership <https://docs.aws.amazon.com/AmazonS3/latest/user-guide/about-object-ownership.html>`__.

        The following operations are related to ``PutBucketOwnershipControls``:

        -  GetBucketOwnershipControls

        -  DeleteBucketOwnershipControls

        :param bucket: The name of the Amazon S3 bucket whose ``OwnershipControls`` you want to
        set.
        :param ownership_controls: The ``OwnershipControls`` (BucketOwnerEnforced, BucketOwnerPreferred, or
        ObjectWriter) that you want to apply to this Amazon S3 bucket.
        :param content_md5: The MD5 hash of the ``OwnershipControls`` request body.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketPolicy")
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
        """Applies an Amazon S3 bucket policy to an Amazon S3 bucket. If you are
        using an identity other than the root user of the Amazon Web Services
        account that owns the bucket, the calling identity must have the
        ``PutBucketPolicy`` permissions on the specified bucket and belong to
        the bucket owner's account in order to use this operation.

        If you don't have ``PutBucketPolicy`` permissions, Amazon S3 returns a
        ``403 Access Denied`` error. If you have the correct permissions, but
        you're not using an identity that belongs to the bucket owner's account,
        Amazon S3 returns a ``405 Method Not Allowed`` error.

        As a security precaution, the root user of the Amazon Web Services
        account that owns a bucket can always use this operation, even if the
        policy explicitly denies the root user the ability to perform this
        action.

        For more information, see `Bucket policy
        examples <https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html>`__.

        The following operations are related to ``PutBucketPolicy``:

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `DeleteBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html>`__

        :param bucket: The name of the bucket.
        :param policy: The bucket policy as a JSON document.
        :param content_md5: The MD5 hash of the request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param confirm_remove_self_bucket_access: Set this parameter to true to confirm that you want to remove your
        permissions to change this bucket policy in the future.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketReplication")
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
        """Creates a replication configuration or replaces an existing one. For
        more information, see
        `Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html>`__
        in the *Amazon S3 User Guide*.

        Specify the replication configuration in the request body. In the
        replication configuration, you provide the name of the destination
        bucket or buckets where you want Amazon S3 to replicate objects, the IAM
        role that Amazon S3 can assume to replicate objects on your behalf, and
        other relevant information.

        A replication configuration must include at least one rule, and can
        contain a maximum of 1,000. Each rule identifies a subset of objects to
        replicate by filtering the objects in the source bucket. To choose
        additional subsets of objects to replicate, add a rule for each subset.

        To specify a subset of the objects in the source bucket to apply a
        replication rule to, add the Filter element as a child of the Rule
        element. You can filter objects based on an object key prefix, one or
        more object tags, or both. When you add the Filter element in the
        configuration, you must also add the following elements:
        ``DeleteMarkerReplication``, ``Status``, and ``Priority``.

        If you are using an earlier version of the replication configuration,
        Amazon S3 handles replication of delete markers differently. For more
        information, see `Backward
        Compatibility <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-backward-compat-considerations>`__.

        For information about enabling versioning on a bucket, see `Using
        Versioning <https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html>`__.

        **Handling Replication of Encrypted Objects**

        By default, Amazon S3 doesn't replicate objects that are stored at rest
        using server-side encryption with KMS keys. To replicate Amazon Web
        Services KMS-encrypted objects, add the following:
        ``SourceSelectionCriteria``, ``SseKmsEncryptedObjects``, ``Status``,
        ``EncryptionConfiguration``, and ``ReplicaKmsKeyID``. For information
        about replication configuration, see `Replicating Objects Created with
        SSE Using KMS
        keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-config-for-kms-objects.html>`__.

        For information on ``PutBucketReplication`` errors, see `List of
        replication-related error
        codes <https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ReplicationErrorCodeList>`__

        **Permissions**

        To create a ``PutBucketReplication`` request, you must have
        ``s3:PutReplicationConfiguration`` permissions for the bucket.

        By default, a resource owner, in this case the Amazon Web Services
        account that created the bucket, can perform this operation. The
        resource owner can also grant others permissions to perform the
        operation. For more information about permissions, see `Specifying
        Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        To perform this operation, the user or role performing the action must
        have the
        `iam:PassRole <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>`__
        permission.

        The following operations are related to ``PutBucketReplication``:

        -  `GetBucketReplication <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketReplication.html>`__

        -  `DeleteBucketReplication <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html>`__

        :param bucket: The name of the bucket.
        :param replication_configuration: A container for replication rules.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param token: A token to allow Object Lock to be enabled for an existing bucket.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketRequestPayment")
    def put_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        request_payment_configuration: RequestPaymentConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets the request payment configuration for a bucket. By default, the
        bucket owner pays for downloads from the bucket. This configuration
        parameter enables the bucket owner (only) to specify that the person
        requesting the download will be charged for the download. For more
        information, see `Requester Pays
        Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html>`__.

        The following operations are related to ``PutBucketRequestPayment``:

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `GetBucketRequestPayment <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketRequestPayment.html>`__

        :param bucket: The bucket name.
        :param request_payment_configuration: Container for Payer.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketTagging")
    def put_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        tagging: Tagging,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets the tags for a bucket.

        Use tags to organize your Amazon Web Services bill to reflect your own
        cost structure. To do this, sign up to get your Amazon Web Services
        account bill with tag key values included. Then, to see the cost of
        combined resources, organize your billing information according to
        resources with the same tag key values. For example, you can tag several
        resources with a specific application name, and then organize your
        billing information to see the total cost of that application across
        several services. For more information, see `Cost Allocation and
        Tagging <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`__
        and `Using Cost Allocation in Amazon S3 Bucket
        Tags <https://docs.aws.amazon.com/AmazonS3/latest/dev/CostAllocTagging.html>`__.

        When this operation sets the tags for a bucket, it will overwrite any
        current tags the bucket already has. You cannot use this operation to
        add tags to an existing list of tags.

        To use this operation, you must have permissions to perform the
        ``s3:PutBucketTagging`` action. The bucket owner has this permission by
        default and can grant this permission to others. For more information
        about permissions, see `Permissions Related to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__.

        ``PutBucketTagging`` has the following special errors:

        -  Error code: ``InvalidTagError``

           -  Description: The tag provided was not a valid tag. This error can
              occur if the tag did not pass input validation. For information
              about tag restrictions, see `User-Defined Tag
              Restrictions <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/allocation-tag-restrictions.html>`__
              and `Amazon Web Services-Generated Cost Allocation Tag
              Restrictions <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/aws-tag-restrictions.html>`__.

        -  Error code: ``MalformedXMLError``

           -  Description: The XML provided does not match the schema.

        -  Error code: ``OperationAbortedError``

           -  Description: A conflicting conditional action is currently in
              progress against this resource. Please try again.

        -  Error code: ``InternalError``

           -  Description: The service was unable to apply the provided tag to
              the bucket.

        The following operations are related to ``PutBucketTagging``:

        -  `GetBucketTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html>`__

        -  `DeleteBucketTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html>`__

        :param bucket: The bucket name.
        :param tagging: Container for the ``TagSet`` and ``Tag`` elements.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketVersioning")
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
        """Sets the versioning state of an existing bucket.

        You can set the versioning state with one of the following values:

        **Enabled**—Enables versioning for the objects in the bucket. All
        objects added to the bucket receive a unique version ID.

        **Suspended**—Disables versioning for the objects in the bucket. All
        objects added to the bucket receive the version ID null.

        If the versioning state has never been set on a bucket, it has no
        versioning state; a
        `GetBucketVersioning <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html>`__
        request does not return a versioning state value.

        In order to enable MFA Delete, you must be the bucket owner. If you are
        the bucket owner and want to enable MFA Delete in the bucket versioning
        configuration, you must include the ``x-amz-mfa request`` header and the
        ``Status`` and the ``MfaDelete`` request elements in a request to set
        the versioning state of the bucket.

        If you have an object expiration lifecycle policy in your non-versioned
        bucket and you want to maintain the same permanent delete behavior when
        you enable versioning, you must add a noncurrent expiration policy. The
        noncurrent expiration lifecycle policy will manage the deletes of the
        noncurrent object versions in the version-enabled bucket. (A
        version-enabled bucket maintains one current and zero or more noncurrent
        object versions.) For more information, see `Lifecycle and
        Versioning <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html#lifecycle-and-other-bucket-config>`__.

        **Related Resources**

        -  `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`__

        -  `DeleteBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html>`__

        -  `GetBucketVersioning <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html>`__

        :param bucket: The bucket name.
        :param versioning_configuration: Container for setting the versioning state.
        :param content_md5: >The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param mfa: The concatenation of the authentication device's serial number, a space,
        and the value that is displayed on your authentication device.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutBucketWebsite")
    def put_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        website_configuration: WebsiteConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Sets the configuration of the website that is specified in the
        ``website`` subresource. To configure a bucket as a website, you can add
        this subresource on the bucket with website configuration information
        such as the file name of the index document and any redirect rules. For
        more information, see `Hosting Websites on Amazon
        S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`__.

        This PUT action requires the ``S3:PutBucketWebsite`` permission. By
        default, only the bucket owner can configure the website attached to a
        bucket; however, bucket owners can allow other users to set the website
        configuration by writing a bucket policy that grants them the
        ``S3:PutBucketWebsite`` permission.

        To redirect all website requests sent to the bucket's website endpoint,
        you add a website configuration with the following elements. Because all
        requests are sent to another website, you don't need to provide index
        document name for the bucket.

        -  ``WebsiteConfiguration``

        -  ``RedirectAllRequestsTo``

        -  ``HostName``

        -  ``Protocol``

        If you want granular control over redirects, you can use the following
        elements to add routing rules that describe conditions for redirecting
        requests and information about the redirect destination. In this case,
        the website configuration must provide an index document for the bucket,
        because some requests might not be redirected.

        -  ``WebsiteConfiguration``

        -  ``IndexDocument``

        -  ``Suffix``

        -  ``ErrorDocument``

        -  ``Key``

        -  ``RoutingRules``

        -  ``RoutingRule``

        -  ``Condition``

        -  ``HttpErrorCodeReturnedEquals``

        -  ``KeyPrefixEquals``

        -  ``Redirect``

        -  ``Protocol``

        -  ``HostName``

        -  ``ReplaceKeyPrefixWith``

        -  ``ReplaceKeyWith``

        -  ``HttpRedirectCode``

        Amazon S3 has a limitation of 50 routing rules per website
        configuration. If you require more than 50 routing rules, you can use
        object redirect. For more information, see `Configuring an Object
        Redirect <https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-page-redirect.html>`__
        in the *Amazon S3 User Guide*.

        :param bucket: The bucket name.
        :param website_configuration: Container for the request.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("PutObject")
    def put_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        body: IO[Body] = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_length: ContentLength = None,
        content_md5: ContentMD5 = None,
        content_type: ContentType = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        checksum_crc32: ChecksumCRC32 = None,
        checksum_crc32_c: ChecksumCRC32C = None,
        checksum_sha1: ChecksumSHA1 = None,
        checksum_sha256: ChecksumSHA256 = None,
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
        """Adds an object to a bucket. You must have WRITE permissions on a bucket
        to add an object to it.

        Amazon S3 never adds partial objects; if you receive a success response,
        Amazon S3 added the entire object to the bucket.

        Amazon S3 is a distributed system. If it receives multiple write
        requests for the same object simultaneously, it overwrites all but the
        last object written. Amazon S3 does not provide object locking; if you
        need this, make sure to build it into your application layer or use
        versioning instead.

        To ensure that data is not corrupted traversing the network, use the
        ``Content-MD5`` header. When you use this header, Amazon S3 checks the
        object against the provided MD5 value and, if they do not match, returns
        an error. Additionally, you can calculate the MD5 while putting an
        object to Amazon S3 and compare the returned ETag to the calculated MD5
        value.

        -  To successfully complete the ``PutObject`` request, you must have the
           ``s3:PutObject`` in your IAM permissions.

        -  To successfully change the objects acl of your ``PutObject`` request,
           you must have the ``s3:PutObjectAcl`` in your IAM permissions.

        -  The ``Content-MD5`` header is required for any request to upload an
           object with a retention period configured using Amazon S3 Object
           Lock. For more information about Amazon S3 Object Lock, see `Amazon
           S3 Object Lock
           Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-overview.html>`__
           in the *Amazon S3 User Guide*.

        **Server-side Encryption**

        You can optionally request server-side encryption. With server-side
        encryption, Amazon S3 encrypts your data as it writes it to disks in its
        data centers and decrypts the data when you access it. You have the
        option to provide your own encryption key or use Amazon Web Services
        managed encryption keys (SSE-S3 or SSE-KMS). For more information, see
        `Using Server-Side
        Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html>`__.

        If you request server-side encryption using Amazon Web Services Key
        Management Service (SSE-KMS), you can enable an S3 Bucket Key at the
        object-level. For more information, see `Amazon S3 Bucket
        Keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-key.html>`__
        in the *Amazon S3 User Guide*.

        **Access Control List (ACL)-Specific Request Headers**

        You can use headers to grant ACL- based permissions. By default, all
        objects are private. Only the owner has full access control. When adding
        a new object, you can grant permissions to individual Amazon Web
        Services accounts or to predefined groups defined by Amazon S3. These
        permissions are then added to the ACL on the object. For more
        information, see `Access Control List (ACL)
        Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__
        and `Managing ACLs Using the REST
        API <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-using-rest-api.html>`__.

        If the bucket that you're uploading objects to uses the bucket owner
        enforced setting for S3 Object Ownership, ACLs are disabled and no
        longer affect permissions. Buckets that use this setting only accept PUT
        requests that don't specify an ACL or PUT requests that specify bucket
        owner full control ACLs, such as the ``bucket-owner-full-control``
        canned ACL or an equivalent form of this ACL expressed in the XML
        format. PUT requests that contain other ACLs (for example, custom grants
        to certain Amazon Web Services accounts) fail and return a ``400`` error
        with the error code ``AccessControlListNotSupported``.

        For more information, see `Controlling ownership of objects and
        disabling
        ACLs <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        If your bucket uses the bucket owner enforced setting for Object
        Ownership, all objects written to the bucket by any account will be
        owned by the bucket owner.

        **Storage Class Options**

        By default, Amazon S3 uses the STANDARD Storage Class to store newly
        created objects. The STANDARD storage class provides high durability and
        high availability. Depending on performance needs, you can specify a
        different Storage Class. Amazon S3 on Outposts only uses the OUTPOSTS
        Storage Class. For more information, see `Storage
        Classes <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html>`__
        in the *Amazon S3 User Guide*.

        **Versioning**

        If you enable versioning for a bucket, Amazon S3 automatically generates
        a unique version ID for the object being stored. Amazon S3 returns this
        ID in the response. When you enable versioning for a bucket, if Amazon
        S3 receives multiple write requests for the same object simultaneously,
        it stores all of the objects.

        For more information about versioning, see `Adding Objects to Versioning
        Enabled
        Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/AddingObjectstoVersioningEnabledBuckets.html>`__.
        For information about returning the versioning state of a bucket, see
        `GetBucketVersioning <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html>`__.

        **Related Resources**

        -  `CopyObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html>`__

        -  `DeleteObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html>`__

        :param bucket: The bucket name to which the PUT action was initiated.
        :param key: Object key for which the PUT action was initiated.
        :param acl: The canned ACL to apply to the object.
        :param body: Object data.
        :param cache_control: Can be used to specify caching behavior along the request/reply chain.
        :param content_disposition: Specifies presentational information for the object.
        :param content_encoding: Specifies what content encodings have been applied to the object and
        thus what decoding mechanisms must be applied to obtain the media-type
        referenced by the Content-Type header field.
        :param content_language: The language the content is in.
        :param content_length: Size of the body in bytes.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the message (without the
        headers) according to RFC 1864.
        :param content_type: A standard MIME type describing the format of the contents.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param checksum_crc32: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_crc32_c: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha1: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha256: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param expires: The date and time at which the object is no longer cacheable.
        :param grant_full_control: Gives the grantee READ, READ_ACP, and WRITE_ACP permissions on the
        object.
        :param grant_read: Allows grantee to read the object data and its metadata.
        :param grant_read_acp: Allows grantee to read the object ACL.
        :param grant_write_acp: Allows grantee to write the ACL for the applicable object.
        :param metadata: A map of metadata to store with the object in S3.
        :param server_side_encryption: The server-side encryption algorithm used when storing this object in
        Amazon S3 (for example, AES256, aws:kms).
        :param storage_class: By default, Amazon S3 uses the STANDARD Storage Class to store newly
        created objects.
        :param website_redirect_location: If the bucket is configured as a website, redirects requests for this
        object to another object in the same bucket or to an external URL.
        :param sse_customer_algorithm: Specifies the algorithm to use to when encrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param ssekms_key_id: If ``x-amz-server-side-encryption`` is present and has the value of
        ``aws:kms``, this header specifies the ID of the Amazon Web Services Key
        Management Service (Amazon Web Services KMS) symmetrical customer
        managed key that was used for the object.
        :param ssekms_encryption_context: Specifies the Amazon Web Services KMS Encryption Context to use for
        object encryption.
        :param bucket_key_enabled: Specifies whether Amazon S3 should use an S3 Bucket Key for object
        encryption with server-side encryption using AWS KMS (SSE-KMS).
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param tagging: The tag-set for the object.
        :param object_lock_mode: The Object Lock mode that you want to apply to this object.
        :param object_lock_retain_until_date: The date and time when you want this object's Object Lock to expire.
        :param object_lock_legal_hold_status: Specifies whether a legal hold will be applied to this object.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: PutObjectOutput
        """
        raise NotImplementedError

    @handler("PutObjectAcl")
    def put_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        access_control_policy: AccessControlPolicy = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectAclOutput:
        """Uses the ``acl`` subresource to set the access control list (ACL)
        permissions for a new or existing object in an S3 bucket. You must have
        ``WRITE_ACP`` permission to set the ACL of an object. For more
        information, see `What permissions can I
        grant? <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#permissions>`__
        in the *Amazon S3 User Guide*.

        This action is not supported by Amazon S3 on Outposts.

        Depending on your application needs, you can choose to set the ACL on an
        object using either the request body or the headers. For example, if you
        have an existing application that updates a bucket ACL using the request
        body, you can continue to use that approach. For more information, see
        `Access Control List (ACL)
        Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__
        in the *Amazon S3 User Guide*.

        If your bucket uses the bucket owner enforced setting for S3 Object
        Ownership, ACLs are disabled and no longer affect permissions. You must
        use policies to grant access to your bucket and the objects in it.
        Requests to set ACLs or update ACLs fail and return the
        ``AccessControlListNotSupported`` error code. Requests to read ACLs are
        still supported. For more information, see `Controlling object
        ownership <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`__
        in the *Amazon S3 User Guide*.

        **Access Permissions**

        You can set access permissions using one of the following methods:

        -  Specify a canned ACL with the ``x-amz-acl`` request header. Amazon S3
           supports a set of predefined ACLs, known as canned ACLs. Each canned
           ACL has a predefined set of grantees and permissions. Specify the
           canned ACL name as the value of ``x-amz-ac`` l. If you use this
           header, you cannot use other access control-specific headers in your
           request. For more information, see `Canned
           ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#CannedACL>`__.

        -  Specify access permissions explicitly with the ``x-amz-grant-read``,
           ``x-amz-grant-read-acp``, ``x-amz-grant-write-acp``, and
           ``x-amz-grant-full-control`` headers. When using these headers, you
           specify explicit access permissions and grantees (Amazon Web Services
           accounts or Amazon S3 groups) who will receive the permission. If you
           use these ACL-specific headers, you cannot use ``x-amz-acl`` header
           to set a canned ACL. These parameters map to the set of permissions
           that Amazon S3 supports in an ACL. For more information, see `Access
           Control List (ACL)
           Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html>`__.

           You specify each grantee as a type=value pair, where the type is one
           of the following:

           -  ``id`` – if the value specified is the canonical user ID of an
              Amazon Web Services account

           -  ``uri`` – if you are granting permissions to a predefined group

           -  ``emailAddress`` – if the value specified is the email address of
              an Amazon Web Services account

              Using email addresses to specify a grantee is only supported in
              the following Amazon Web Services Regions:

              -  US East (N. Virginia)

              -  US West (N. California)

              -  US West (Oregon)

              -  Asia Pacific (Singapore)

              -  Asia Pacific (Sydney)

              -  Asia Pacific (Tokyo)

              -  Europe (Ireland)

              -  South America (São Paulo)

              For a list of all the Amazon S3 supported Regions and endpoints,
              see `Regions and
              Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region>`__
              in the Amazon Web Services General Reference.

           For example, the following ``x-amz-grant-read`` header grants list
           objects permission to the two Amazon Web Services accounts identified
           by their email addresses.

           ``x-amz-grant-read: emailAddress="xyz@amazon.com", emailAddress="abc@amazon.com"``

        You can use either a canned ACL or specify access permissions
        explicitly. You cannot do both.

        **Grantee Values**

        You can specify the person (grantee) to whom you're assigning access
        rights (using request elements) in the following ways:

        -  By the person's ID:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID><>ID<></ID><DisplayName><>GranteesEmail<></DisplayName> </Grantee>``

           DisplayName is optional and ignored in the request.

        -  By URI:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI><>http://acs.amazonaws.com/groups/global/AuthenticatedUsers<></URI></Grantee>``

        -  By Email address:

           ``<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="AmazonCustomerByEmail"><EmailAddress><>Grantees@email.com<></EmailAddress>lt;/Grantee>``

           The grantee is resolved to the CanonicalUser and, in a response to a
           GET Object acl request, appears as the CanonicalUser.

           Using email addresses to specify a grantee is only supported in the
           following Amazon Web Services Regions:

           -  US East (N. Virginia)

           -  US West (N. California)

           -  US West (Oregon)

           -  Asia Pacific (Singapore)

           -  Asia Pacific (Sydney)

           -  Asia Pacific (Tokyo)

           -  Europe (Ireland)

           -  South America (São Paulo)

           For a list of all the Amazon S3 supported Regions and endpoints, see
           `Regions and
           Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region>`__
           in the Amazon Web Services General Reference.

        **Versioning**

        The ACL of an object is set at the object version level. By default, PUT
        sets the ACL of the current version of an object. To set the ACL of a
        different version, use the ``versionId`` subresource.

        **Related Resources**

        -  `CopyObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html>`__

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        :param bucket: The bucket name that contains the object to which you want to attach the
        ACL.
        :param key: Key for which the PUT action was initiated.
        :param acl: The canned ACL to apply to the object.
        :param access_control_policy: Contains the elements that set the ACL permissions for an object per
        grantee.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param grant_full_control: Allows grantee the read, write, read ACP, and write ACP permissions on
        the bucket.
        :param grant_read: Allows grantee to list the objects in the bucket.
        :param grant_read_acp: Allows grantee to read the bucket ACL.
        :param grant_write: Allows grantee to create new objects in the bucket.
        :param grant_write_acp: Allows grantee to write the ACL for the applicable bucket.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param version_id: VersionId used to reference a specific version of the object.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: PutObjectAclOutput
        :raises NoSuchKey:
        """
        raise NotImplementedError

    @handler("PutObjectLegalHold")
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
        """Applies a legal hold configuration to the specified object. For more
        information, see `Locking
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`__.

        This action is not supported by Amazon S3 on Outposts.

        :param bucket: The bucket name containing the object that you want to place a legal
        hold on.
        :param key: The key name for the object that you want to place a legal hold on.
        :param legal_hold: Container element for the legal hold configuration you want to apply to
        the specified object.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param version_id: The version ID of the object that you want to place a legal hold on.
        :param content_md5: The MD5 hash for the request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: PutObjectLegalHoldOutput
        """
        raise NotImplementedError

    @handler("PutObjectLockConfiguration")
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
        """Places an Object Lock configuration on the specified bucket. The rule
        specified in the Object Lock configuration will be applied by default to
        every new object placed in the specified bucket. For more information,
        see `Locking
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`__.

        -  The ``DefaultRetention`` settings require both a mode and a period.

        -  The ``DefaultRetention`` period can be either ``Days`` or ``Years``
           but you must select one. You cannot specify ``Days`` and ``Years`` at
           the same time.

        -  You can only enable Object Lock for new buckets. If you want to turn
           on Object Lock for an existing bucket, contact Amazon Web Services
           Support.

        :param bucket: The bucket whose Object Lock configuration you want to create or
        replace.
        :param object_lock_configuration: The Object Lock configuration that you want to apply to the specified
        bucket.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param token: A token to allow Object Lock to be enabled for an existing bucket.
        :param content_md5: The MD5 hash for the request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: PutObjectLockConfigurationOutput
        """
        raise NotImplementedError

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
        """Places an Object Retention configuration on an object. For more
        information, see `Locking
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`__.
        Users or accounts require the ``s3:PutObjectRetention`` permission in
        order to place an Object Retention configuration on objects. Bypassing a
        Governance Retention configuration requires the
        ``s3:BypassGovernanceRetention`` permission.

        This action is not supported by Amazon S3 on Outposts.

        :param bucket: The bucket name that contains the object you want to apply this Object
        Retention configuration to.
        :param key: The key name for the object that you want to apply this Object Retention
        configuration to.
        :param retention: The container element for the Object Retention configuration.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param version_id: The version ID for the object that you want to apply this Object
        Retention configuration to.
        :param bypass_governance_retention: Indicates whether this action should bypass Governance-mode
        restrictions.
        :param content_md5: The MD5 hash for the request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: PutObjectRetentionOutput
        """
        raise NotImplementedError

    @handler("PutObjectTagging")
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
        """Sets the supplied tag-set to an object that already exists in a bucket.

        A tag is a key-value pair. You can associate tags with an object by
        sending a PUT request against the tagging subresource that is associated
        with the object. You can retrieve tags by sending a GET request. For
        more information, see
        `GetObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html>`__.

        For tagging-related restrictions related to characters and encodings,
        see `Tag
        Restrictions <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/allocation-tag-restrictions.html>`__.
        Note that Amazon S3 limits the maximum number of tags to 10 tags per
        object.

        To use this operation, you must have permission to perform the
        ``s3:PutObjectTagging`` action. By default, the bucket owner has this
        permission and can grant this permission to others.

        To put tags of any other version, use the ``versionId`` query parameter.
        You also need permission for the ``s3:PutObjectVersionTagging`` action.

        For information about the Amazon S3 object tagging feature, see `Object
        Tagging <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-tagging.html>`__.

        **Special Errors**

        -

           -  *Code: InvalidTagError*

           -  *Cause: The tag provided was not a valid tag. This error can occur
              if the tag did not pass input validation. For more information,
              see* `Object
              Tagging <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-tagging.html>`__ *.*

        -

           -  *Code: MalformedXMLError*

           -  *Cause: The XML provided does not match the schema.*

        -

           -  *Code: OperationAbortedError*

           -  *Cause: A conflicting conditional action is currently in progress
              against this resource. Please try again.*

        -

           -  *Code: InternalError*

           -  *Cause: The service was unable to apply the provided tag to the
              object.*

        **Related Resources**

        -  `GetObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html>`__

        -  `DeleteObjectTagging <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html>`__

        :param bucket: The bucket name containing the object.
        :param key: Name of the object key.
        :param tagging: Container for the ``TagSet`` and ``Tag`` elements.
        :param version_id: The versionId of the object that the tag-set will be added to.
        :param content_md5: The MD5 hash for the request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :returns: PutObjectTaggingOutput
        """
        raise NotImplementedError

    @handler("PutPublicAccessBlock")
    def put_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        """Creates or modifies the ``PublicAccessBlock`` configuration for an
        Amazon S3 bucket. To use this operation, you must have the
        ``s3:PutBucketPublicAccessBlock`` permission. For more information about
        Amazon S3 permissions, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__.

        When Amazon S3 evaluates the ``PublicAccessBlock`` configuration for a
        bucket or an object, it checks the ``PublicAccessBlock`` configuration
        for both the bucket (or the bucket that contains the object) and the
        bucket owner's account. If the ``PublicAccessBlock`` configurations are
        different between the bucket and the account, Amazon S3 uses the most
        restrictive combination of the bucket-level and account-level settings.

        For more information about when Amazon S3 considers a bucket or an
        object public, see `The Meaning of
        "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`__.

        **Related Resources**

        -  `GetPublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html>`__

        -  `DeletePublicAccessBlock <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeletePublicAccessBlock.html>`__

        -  `GetBucketPolicyStatus <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html>`__

        -  `Using Amazon S3 Block Public
           Access <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html>`__

        :param bucket: The name of the Amazon S3 bucket whose ``PublicAccessBlock``
        configuration you want to set.
        :param public_access_block_configuration: The ``PublicAccessBlock`` configuration that you want to apply to this
        Amazon S3 bucket.
        :param content_md5: The MD5 hash of the ``PutPublicAccessBlock`` request body.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        """
        raise NotImplementedError

    @handler("RestoreObject")
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
        """Restores an archived copy of an object back into Amazon S3

        This action is not supported by Amazon S3 on Outposts.

        This action performs the following types of requests:

        -  ``select`` - Perform a select query on an archived object

        -  ``restore an archive`` - Restore an archived object

        To use this operation, you must have permissions to perform the
        ``s3:RestoreObject`` action. The bucket owner has this permission by
        default and can grant this permission to others. For more information
        about permissions, see `Permissions Related to Bucket Subresource
        Operations <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html#using-with-s3-actions-related-to-bucket-subresources>`__
        and `Managing Access Permissions to Your Amazon S3
        Resources <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-access-control.html>`__
        in the *Amazon S3 User Guide*.

        **Querying Archives with Select Requests**

        You use a select type of request to perform SQL queries on archived
        objects. The archived objects that are being queried by the select
        request must be formatted as uncompressed comma-separated values (CSV)
        files. You can run queries and custom analytics on your archived data
        without having to restore your data to a hotter Amazon S3 tier. For an
        overview about select requests, see `Querying Archived
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/querying-glacier-archives.html>`__
        in the *Amazon S3 User Guide*.

        When making a select request, do the following:

        -  Define an output location for the select query's output. This must be
           an Amazon S3 bucket in the same Amazon Web Services Region as the
           bucket that contains the archive object that is being queried. The
           Amazon Web Services account that initiates the job must have
           permissions to write to the S3 bucket. You can specify the storage
           class and encryption for the output objects stored in the bucket. For
           more information about output, see `Querying Archived
           Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/querying-glacier-archives.html>`__
           in the *Amazon S3 User Guide*.

           For more information about the ``S3`` structure in the request body,
           see the following:

           -  `PutObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>`__

           -  `Managing Access with
              ACLs <https://docs.aws.amazon.com/AmazonS3/latest/dev/S3_ACLs_UsingACLs.html>`__
              in the *Amazon S3 User Guide*

           -  `Protecting Data Using Server-Side
              Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html>`__
              in the *Amazon S3 User Guide*

        -  Define the SQL expression for the ``SELECT`` type of restoration for
           your query in the request body's ``SelectParameters`` structure. You
           can use expressions like the following examples.

           -  The following expression returns all records from the specified
              object.

              ``SELECT * FROM Object``

           -  Assuming that you are not using any headers for data stored in the
              object, you can specify columns with positional headers.

              ``SELECT s._1, s._2 FROM Object s WHERE s._3 > 100``

           -  If you have headers and you set the ``fileHeaderInfo`` in the
              ``CSV`` structure in the request body to ``USE``, you can specify
              headers in the query. (If you set the ``fileHeaderInfo`` field to
              ``IGNORE``, the first row is skipped for the query.) You cannot
              mix ordinal positions with header column names.

              ``SELECT s.Id, s.FirstName, s.SSN FROM S3Object s``

        For more information about using SQL with S3 Glacier Select restore, see
        `SQL Reference for Amazon S3 Select and S3 Glacier
        Select <https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-glacier-select-sql-reference.html>`__
        in the *Amazon S3 User Guide*.

        When making a select request, you can also do the following:

        -  To expedite your queries, specify the ``Expedited`` tier. For more
           information about tiers, see "Restoring Archives," later in this
           topic.

        -  Specify details about the data serialization format of both the input
           object that is being queried and the serialization of the CSV-encoded
           query results.

        The following are additional important facts about the select feature:

        -  The output results are new Amazon S3 objects. Unlike archive
           retrievals, they are stored until explicitly deleted-manually or
           through a lifecycle policy.

        -  You can issue more than one select request on the same Amazon S3
           object. Amazon S3 doesn't deduplicate requests, so avoid issuing
           duplicate requests.

        -  Amazon S3 accepts a select request even if the object has already
           been restored. A select request doesn’t return error response
           ``409``.

        **Restoring objects**

        Objects that you archive to the S3 Glacier or S3 Glacier Deep Archive
        storage class, and S3 Intelligent-Tiering Archive or S3
        Intelligent-Tiering Deep Archive tiers are not accessible in real time.
        For objects in Archive Access or Deep Archive Access tiers you must
        first initiate a restore request, and then wait until the object is
        moved into the Frequent Access tier. For objects in S3 Glacier or S3
        Glacier Deep Archive storage classes you must first initiate a restore
        request, and then wait until a temporary copy of the object is
        available. To access an archived object, you must restore the object for
        the duration (number of days) that you specify.

        To restore a specific object version, you can provide a version ID. If
        you don't provide a version ID, Amazon S3 restores the current version.

        When restoring an archived object (or using a select request), you can
        specify one of the following data access tier options in the ``Tier``
        element of the request body:

        -  ``Expedited`` - Expedited retrievals allow you to quickly access your
           data stored in the S3 Glacier storage class or S3 Intelligent-Tiering
           Archive tier when occasional urgent requests for a subset of archives
           are required. For all but the largest archived objects (250 MB+),
           data accessed using Expedited retrievals is typically made available
           within 1–5 minutes. Provisioned capacity ensures that retrieval
           capacity for Expedited retrievals is available when you need it.
           Expedited retrievals and provisioned capacity are not available for
           objects stored in the S3 Glacier Deep Archive storage class or S3
           Intelligent-Tiering Deep Archive tier.

        -  ``Standard`` - Standard retrievals allow you to access any of your
           archived objects within several hours. This is the default option for
           retrieval requests that do not specify the retrieval option. Standard
           retrievals typically finish within 3–5 hours for objects stored in
           the S3 Glacier storage class or S3 Intelligent-Tiering Archive tier.
           They typically finish within 12 hours for objects stored in the S3
           Glacier Deep Archive storage class or S3 Intelligent-Tiering Deep
           Archive tier. Standard retrievals are free for objects stored in S3
           Intelligent-Tiering.

        -  ``Bulk`` - Bulk retrievals are the lowest-cost retrieval option in S3
           Glacier, enabling you to retrieve large amounts, even petabytes, of
           data inexpensively. Bulk retrievals typically finish within 5–12
           hours for objects stored in the S3 Glacier storage class or S3
           Intelligent-Tiering Archive tier. They typically finish within 48
           hours for objects stored in the S3 Glacier Deep Archive storage class
           or S3 Intelligent-Tiering Deep Archive tier. Bulk retrievals are free
           for objects stored in S3 Intelligent-Tiering.

        For more information about archive retrieval options and provisioned
        capacity for ``Expedited`` data access, see `Restoring Archived
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html>`__
        in the *Amazon S3 User Guide*.

        You can use Amazon S3 restore speed upgrade to change the restore speed
        to a faster speed while it is in progress. For more information, see
        `Upgrading the speed of an in-progress
        restore <https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html#restoring-objects-upgrade-tier.title.html>`__
        in the *Amazon S3 User Guide*.

        To get the status of object restoration, you can send a ``HEAD``
        request. Operations return the ``x-amz-restore`` header, which provides
        information about the restoration status, in the response. You can use
        Amazon S3 event notifications to notify you when a restore is initiated
        or completed. For more information, see `Configuring Amazon S3 Event
        Notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`__
        in the *Amazon S3 User Guide*.

        After restoring an archived object, you can update the restoration
        period by reissuing the request with a new period. Amazon S3 updates the
        restoration period relative to the current time and charges only for the
        request-there are no data transfer charges. You cannot update the
        restoration period when Amazon S3 is actively processing your current
        restore request for the object.

        If your bucket has a lifecycle configuration with a rule that includes
        an expiration action, the object expiration overrides the life span that
        you specify in a restore request. For example, if you restore an object
        copy for 10 days, but the object is scheduled to expire in 3 days,
        Amazon S3 deletes the object in 3 days. For more information about
        lifecycle configuration, see
        `PutBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html>`__
        and `Object Lifecycle
        Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`__
        in *Amazon S3 User Guide*.

        **Responses**

        A successful action returns either the ``200 OK`` or ``202 Accepted``
        status code.

        -  If the object is not previously restored, then Amazon S3 returns
           ``202 Accepted`` in the response.

        -  If the object is previously restored, Amazon S3 returns ``200 OK`` in
           the response.

        **Special Errors**

        -

           -  *Code: RestoreAlreadyInProgress*

           -  *Cause: Object restore is already in progress. (This error does
              not apply to SELECT type requests.)*

           -  *HTTP Status Code: 409 Conflict*

           -  *SOAP Fault Code Prefix: Client*

        -

           -  *Code: GlacierExpeditedRetrievalNotAvailable*

           -  *Cause: expedited retrievals are currently not available. Try
              again later. (Returned if there is insufficient capacity to
              process the Expedited request. This error applies only to
              Expedited retrievals and not to S3 Standard or Bulk retrievals.)*

           -  *HTTP Status Code: 503*

           -  *SOAP Fault Code Prefix: N/A*

        **Related Resources**

        -  `PutBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html>`__

        -  `GetBucketNotificationConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketNotificationConfiguration.html>`__

        -  `SQL Reference for Amazon S3 Select and S3 Glacier
           Select <https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-glacier-select-sql-reference.html>`__
           in the *Amazon S3 User Guide*

        :param bucket: The bucket name containing the object to restore.
        :param key: Object key for which the action was initiated.
        :param version_id: VersionId used to reference a specific version of the object.
        :param restore_request: Container for restore job parameters.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: RestoreObjectOutput
        :raises ObjectAlreadyInActiveTierError:
        """
        raise NotImplementedError

    @handler("SelectObjectContent")
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
        """This action filters the contents of an Amazon S3 object based on a
        simple structured query language (SQL) statement. In the request, along
        with the SQL expression, you must also specify a data serialization
        format (JSON, CSV, or Apache Parquet) of the object. Amazon S3 uses this
        format to parse object data into records, and returns only records that
        match the specified SQL expression. You must also specify the data
        serialization format for the response.

        This action is not supported by Amazon S3 on Outposts.

        For more information about Amazon S3 Select, see `Selecting Content from
        Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/selecting-content-from-objects.html>`__
        and `SELECT
        Command <https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-glacier-select-sql-reference-select.html>`__
        in the *Amazon S3 User Guide*.

        For more information about using SQL with Amazon S3 Select, see `SQL
        Reference for Amazon S3 Select and S3 Glacier
        Select <https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-glacier-select-sql-reference.html>`__
        in the *Amazon S3 User Guide*.

        **Permissions**

        You must have ``s3:GetObject`` permission for this operation. Amazon S3
        Select does not support anonymous access. For more information about
        permissions, see `Specifying Permissions in a
        Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html>`__
        in the *Amazon S3 User Guide*.

        *Object Data Formats*

        You can use Amazon S3 Select to query objects that have the following
        format properties:

        -  *CSV, JSON, and Parquet* - Objects must be in CSV, JSON, or Parquet
           format.

        -  *UTF-8* - UTF-8 is the only encoding type Amazon S3 Select supports.

        -  *GZIP or BZIP2* - CSV and JSON files can be compressed using GZIP or
           BZIP2. GZIP and BZIP2 are the only compression formats that Amazon S3
           Select supports for CSV and JSON files. Amazon S3 Select supports
           columnar compression for Parquet using GZIP or Snappy. Amazon S3
           Select does not support whole-object compression for Parquet objects.

        -  *Server-side encryption* - Amazon S3 Select supports querying objects
           that are protected with server-side encryption.

           For objects that are encrypted with customer-provided encryption keys
           (SSE-C), you must use HTTPS, and you must use the headers that are
           documented in the
           `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__.
           For more information about SSE-C, see `Server-Side Encryption (Using
           Customer-Provided Encryption
           Keys) <https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html>`__
           in the *Amazon S3 User Guide*.

           For objects that are encrypted with Amazon S3 managed encryption keys
           (SSE-S3) and Amazon Web Services KMS keys (SSE-KMS), server-side
           encryption is handled transparently, so you don't need to specify
           anything. For more information about server-side encryption,
           including SSE-S3 and SSE-KMS, see `Protecting Data Using Server-Side
           Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html>`__
           in the *Amazon S3 User Guide*.

        **Working with the Response Body**

        Given the response size is unknown, Amazon S3 Select streams the
        response as a series of messages and includes a ``Transfer-Encoding``
        header with ``chunked`` as its value in the response. For more
        information, see `Appendix: SelectObjectContent
        Response <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTSelectObjectAppendix.html>`__.

        **GetObject Support**

        The ``SelectObjectContent`` action does not support the following
        ``GetObject`` functionality. For more information, see
        `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__.

        -  ``Range``: Although you can specify a scan range for an Amazon S3
           Select request (see `SelectObjectContentRequest -
           ScanRange <https://docs.aws.amazon.com/AmazonS3/latest/API/API_SelectObjectContent.html#AmazonS3-SelectObjectContent-request-ScanRange>`__
           in the request parameters), you cannot specify the range of bytes of
           an object to return.

        -  GLACIER, DEEP_ARCHIVE and REDUCED_REDUNDANCY storage classes: You
           cannot specify the GLACIER, DEEP_ARCHIVE, or ``REDUCED_REDUNDANCY``
           storage classes. For more information, about storage classes see
           `Storage
           Classes <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html#storage-class-intro>`__
           in the *Amazon S3 User Guide*.

        **Special Errors**

        For a list of special errors for this operation, see `List of SELECT
        Object Content Error
        Codes <https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#SelectObjectContentErrorCodeList>`__

        **Related Resources**

        -  `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__

        -  `GetBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html>`__

        -  `PutBucketLifecycleConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html>`__

        :param bucket: The S3 bucket.
        :param key: The object key.
        :param expression: The expression that is used to query the object.
        :param expression_type: The type of the provided expression (for example, SQL).
        :param input_serialization: Describes the format of the data in the object that is being queried.
        :param output_serialization: Describes the format of the data that you want Amazon S3 to return in
        response.
        :param sse_customer_algorithm: The server-side encryption (SSE) algorithm used to encrypt the object.
        :param sse_customer_key: The server-side encryption (SSE) customer managed key.
        :param sse_customer_key_md5: The MD5 server-side encryption (SSE) customer managed key.
        :param request_progress: Specifies if periodic request progress information should be enabled.
        :param scan_range: Specifies the byte range of the object to get the records from.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: SelectObjectContentOutput
        """
        raise NotImplementedError

    @handler("UploadPart")
    def upload_part(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        part_number: PartNumber,
        upload_id: MultipartUploadId,
        body: IO[Body] = None,
        content_length: ContentLength = None,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        checksum_crc32: ChecksumCRC32 = None,
        checksum_crc32_c: ChecksumCRC32C = None,
        checksum_sha1: ChecksumSHA1 = None,
        checksum_sha256: ChecksumSHA256 = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> UploadPartOutput:
        """Uploads a part in a multipart upload.

        In this operation, you provide part data in your request. However, you
        have an option to specify your existing Amazon S3 object as a data
        source for the part you are uploading. To upload a part from an existing
        object, you use the
        `UploadPartCopy <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html>`__
        operation.

        You must initiate a multipart upload (see
        `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__)
        before you can upload any part. In response to your initiate request,
        Amazon S3 returns an upload ID, a unique identifier, that you must
        include in your upload part request.

        Part numbers can be any number from 1 to 10,000, inclusive. A part
        number uniquely identifies a part and also defines its position within
        the object being created. If you upload a new part using the same part
        number that was used with a previous part, the previously uploaded part
        is overwritten.

        For information about maximum and minimum part sizes and other multipart
        upload specifications, see `Multipart upload
        limits <https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html>`__
        in the *Amazon S3 User Guide*.

        To ensure that data is not corrupted when traversing the network,
        specify the ``Content-MD5`` header in the upload part request. Amazon S3
        checks the part data against the provided MD5 value. If they do not
        match, Amazon S3 returns an error.

        If the upload request is signed with Signature Version 4, then Amazon
        Web Services S3 uses the ``x-amz-content-sha256`` header as a checksum
        instead of ``Content-MD5``. For more information see `Authenticating
        Requests: Using the Authorization Header (Amazon Web Services Signature
        Version
        4) <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html>`__.

        **Note:** After you initiate multipart upload and upload one or more
        parts, you must either complete or abort multipart upload in order to
        stop getting charged for storage of the uploaded parts. Only after you
        either complete or abort multipart upload, Amazon S3 frees up the parts
        storage and stops charging you for the parts storage.

        For more information on multipart uploads, go to `Multipart Upload
        Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html>`__
        in the *Amazon S3 User Guide* .

        For information on the permissions required to use the multipart upload
        API, go to `Multipart Upload and
        Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__
        in the *Amazon S3 User Guide*.

        You can optionally request server-side encryption where Amazon S3
        encrypts your data as it writes it to disks in its data centers and
        decrypts it for you when you access it. You have the option of providing
        your own encryption key, or you can use the Amazon Web Services managed
        encryption keys. If you choose to provide your own encryption key, the
        request headers you provide in the request must match the headers you
        used in the request to initiate the upload by using
        `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__.
        For more information, go to `Using Server-Side
        Encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html>`__
        in the *Amazon S3 User Guide*.

        Server-side encryption is supported by the S3 Multipart Upload actions.
        Unless you are using a customer-provided encryption key, you don't need
        to specify the encryption parameters in each UploadPart request.
        Instead, you only need to specify the server-side encryption parameters
        in the initial Initiate Multipart request. For more information, see
        `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__.

        If you requested server-side encryption using a customer-provided
        encryption key in your initiate multipart upload request, you must
        provide identical encryption information in each part upload using the
        following headers.

        -  x-amz-server-side-encryption-customer-algorithm

        -  x-amz-server-side-encryption-customer-key

        -  x-amz-server-side-encryption-customer-key-MD5

        **Special Errors**

        -

           -  *Code: NoSuchUpload*

           -  *Cause: The specified multipart upload does not exist. The upload
              ID might be invalid, or the multipart upload might have been
              aborted or completed.*

           -  *HTTP Status Code: 404 Not Found*

           -  *SOAP Fault Code Prefix: Client*

        **Related Resources**

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `ListMultipartUploads <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html>`__

        :param bucket: The name of the bucket to which the multipart upload was initiated.
        :param key: Object key for which the multipart upload was initiated.
        :param part_number: Part number of part being uploaded.
        :param upload_id: Upload ID identifying the multipart upload whose part is being uploaded.
        :param body: Object data.
        :param content_length: Size of the body in bytes.
        :param content_md5: The base64-encoded 128-bit MD5 digest of the part data.
        :param checksum_algorithm: Indicates the algorithm used to create the checksum for the object when
        using the SDK.
        :param checksum_crc32: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_crc32_c: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha1: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha256: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param sse_customer_algorithm: Specifies the algorithm to use to when encrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected bucket owner.
        :returns: UploadPartOutput
        """
        raise NotImplementedError

    @handler("UploadPartCopy")
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
        """Uploads a part by copying data from an existing object as data source.
        You specify the data source by adding the request header
        ``x-amz-copy-source`` in your request and a byte range by adding the
        request header ``x-amz-copy-source-range`` in your request.

        For information about maximum and minimum part sizes and other multipart
        upload specifications, see `Multipart upload
        limits <https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html>`__
        in the *Amazon S3 User Guide*.

        Instead of using an existing object as part data, you might use the
        `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__
        action and provide data in your request.

        You must initiate a multipart upload before you can upload any part. In
        response to your initiate request. Amazon S3 returns a unique
        identifier, the upload ID, that you must include in your upload part
        request.

        For more information about using the ``UploadPartCopy`` operation, see
        the following:

        -  For conceptual information about multipart uploads, see `Uploading
           Objects Using Multipart
           Upload <https://docs.aws.amazon.com/AmazonS3/latest/dev/uploadobjusingmpu.html>`__
           in the *Amazon S3 User Guide*.

        -  For information about permissions required to use the multipart
           upload API, see `Multipart Upload and
           Permissions <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuAndPermissions.html>`__
           in the *Amazon S3 User Guide*.

        -  For information about copying objects using a single atomic action
           vs. a multipart upload, see `Operations on
           Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectOperations.html>`__
           in the *Amazon S3 User Guide*.

        -  For information about using server-side encryption with
           customer-provided encryption keys with the ``UploadPartCopy``
           operation, see
           `CopyObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html>`__
           and
           `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__.

        Note the following additional considerations about the request headers
        ``x-amz-copy-source-if-match``, ``x-amz-copy-source-if-none-match``,
        ``x-amz-copy-source-if-unmodified-since``, and
        ``x-amz-copy-source-if-modified-since``:

        -  **Consideration 1** - If both of the ``x-amz-copy-source-if-match``
           and ``x-amz-copy-source-if-unmodified-since`` headers are present in
           the request as follows:

           ``x-amz-copy-source-if-match`` condition evaluates to ``true``, and;

           ``x-amz-copy-source-if-unmodified-since`` condition evaluates to
           ``false``;

           Amazon S3 returns ``200 OK`` and copies the data.

        -  **Consideration 2** - If both of the
           ``x-amz-copy-source-if-none-match`` and
           ``x-amz-copy-source-if-modified-since`` headers are present in the
           request as follows:

           ``x-amz-copy-source-if-none-match`` condition evaluates to ``false``,
           and;

           ``x-amz-copy-source-if-modified-since`` condition evaluates to
           ``true``;

           Amazon S3 returns ``412 Precondition Failed`` response code.

        **Versioning**

        If your bucket has versioning enabled, you could have multiple versions
        of the same object. By default, ``x-amz-copy-source`` identifies the
        current version of the object to copy. If the current version is a
        delete marker and you don't specify a versionId in the
        ``x-amz-copy-source``, Amazon S3 returns a 404 error, because the object
        does not exist. If you specify versionId in the ``x-amz-copy-source``
        and the versionId is a delete marker, Amazon S3 returns an HTTP 400
        error, because you are not allowed to specify a delete marker as a
        version for the ``x-amz-copy-source``.

        You can optionally specify a specific version of the source object to
        copy by adding the ``versionId`` subresource as shown in the following
        example:

        ``x-amz-copy-source: /bucket/object?versionId=version id``

        **Special Errors**

        -

           -  *Code: NoSuchUpload*

           -  *Cause: The specified multipart upload does not exist. The upload
              ID might be invalid, or the multipart upload might have been
              aborted or completed.*

           -  *HTTP Status Code: 404 Not Found*

        -

           -  *Code: InvalidRequest*

           -  *Cause: The specified copy source is not supported as a byte-range
              copy source.*

           -  *HTTP Status Code: 400 Bad Request*

        **Related Resources**

        -  `CreateMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html>`__

        -  `UploadPart <https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html>`__

        -  `CompleteMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>`__

        -  `AbortMultipartUpload <https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html>`__

        -  `ListParts <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html>`__

        -  `ListMultipartUploads <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html>`__

        :param bucket: The bucket name.
        :param copy_source: Specifies the source object for the copy operation.
        :param key: Object key for which the multipart upload was initiated.
        :param part_number: Part number of part being copied.
        :param upload_id: Upload ID identifying the multipart upload whose part is being copied.
        :param copy_source_if_match: Copies the object if its entity tag (ETag) matches the specified tag.
        :param copy_source_if_modified_since: Copies the object if it has been modified since the specified time.
        :param copy_source_if_none_match: Copies the object if its entity tag (ETag) is different than the
        specified ETag.
        :param copy_source_if_unmodified_since: Copies the object if it hasn't been modified since the specified time.
        :param copy_source_range: The range of bytes to copy from the source object.
        :param sse_customer_algorithm: Specifies the algorithm to use to when encrypting the object (for
        example, AES256).
        :param sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use in
        encrypting data.
        :param sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param copy_source_sse_customer_algorithm: Specifies the algorithm to use when decrypting the source object (for
        example, AES256).
        :param copy_source_sse_customer_key: Specifies the customer-provided encryption key for Amazon S3 to use to
        decrypt the source object.
        :param copy_source_sse_customer_key_md5: Specifies the 128-bit MD5 digest of the encryption key according to RFC
        1321.
        :param request_payer: Confirms that the requester knows that they will be charged for the
        request.
        :param expected_bucket_owner: The account ID of the expected destination bucket owner.
        :param expected_source_bucket_owner: The account ID of the expected source bucket owner.
        :returns: UploadPartCopyOutput
        """
        raise NotImplementedError

    @handler("WriteGetObjectResponse")
    def write_get_object_response(
        self,
        context: RequestContext,
        request_route: RequestRoute,
        request_token: RequestToken,
        body: IO[Body] = None,
        status_code: GetObjectResponseStatusCode = None,
        error_code: ErrorCode = None,
        error_message: ErrorMessage = None,
        accept_ranges: AcceptRanges = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_length: ContentLength = None,
        content_range: ContentRange = None,
        content_type: ContentType = None,
        checksum_crc32: ChecksumCRC32 = None,
        checksum_crc32_c: ChecksumCRC32C = None,
        checksum_sha1: ChecksumSHA1 = None,
        checksum_sha256: ChecksumSHA256 = None,
        delete_marker: DeleteMarker = None,
        e_tag: ETag = None,
        expires: Expires = None,
        expiration: Expiration = None,
        last_modified: LastModified = None,
        missing_meta: MissingMeta = None,
        metadata: Metadata = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        parts_count: PartsCount = None,
        replication_status: ReplicationStatus = None,
        request_charged: RequestCharged = None,
        restore: Restore = None,
        server_side_encryption: ServerSideEncryption = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        ssekms_key_id: SSEKMSKeyId = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        storage_class: StorageClass = None,
        tag_count: TagCount = None,
        version_id: ObjectVersionId = None,
        bucket_key_enabled: BucketKeyEnabled = None,
    ) -> None:
        """Passes transformed objects to a ``GetObject`` operation when using
        Object Lambda access points. For information about Object Lambda access
        points, see `Transforming objects with Object Lambda access
        points <https://docs.aws.amazon.com/AmazonS3/latest/userguide/transforming-objects.html>`__
        in the *Amazon S3 User Guide*.

        This operation supports metadata that can be returned by
        `GetObject <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>`__,
        in addition to ``RequestRoute``, ``RequestToken``, ``StatusCode``,
        ``ErrorCode``, and ``ErrorMessage``. The ``GetObject`` response metadata
        is supported so that the ``WriteGetObjectResponse`` caller, typically an
        Lambda function, can provide the same metadata when it internally
        invokes ``GetObject``. When ``WriteGetObjectResponse`` is called by a
        customer-owned Lambda function, the metadata returned to the end user
        ``GetObject`` call might differ from what Amazon S3 would normally
        return.

        You can include any number of metadata headers. When including a
        metadata header, it should be prefaced with ``x-amz-meta``. For example,
        ``x-amz-meta-my-custom-header: MyCustomValue``. The primary use case for
        this is to forward ``GetObject`` metadata.

        Amazon Web Services provides some prebuilt Lambda functions that you can
        use with S3 Object Lambda to detect and redact personally identifiable
        information (PII) and decompress S3 objects. These Lambda functions are
        available in the Amazon Web Services Serverless Application Repository,
        and can be selected through the Amazon Web Services Management Console
        when you create your Object Lambda access point.

        Example 1: PII Access Control - This Lambda function uses Amazon
        Comprehend, a natural language processing (NLP) service using machine
        learning to find insights and relationships in text. It automatically
        detects personally identifiable information (PII) such as names,
        addresses, dates, credit card numbers, and social security numbers from
        documents in your Amazon S3 bucket.

        Example 2: PII Redaction - This Lambda function uses Amazon Comprehend,
        a natural language processing (NLP) service using machine learning to
        find insights and relationships in text. It automatically redacts
        personally identifiable information (PII) such as names, addresses,
        dates, credit card numbers, and social security numbers from documents
        in your Amazon S3 bucket.

        Example 3: Decompression - The Lambda function
        S3ObjectLambdaDecompression, is equipped to decompress objects stored in
        S3 in one of six compressed file formats including bzip2, gzip, snappy,
        zlib, zstandard and ZIP.

        For information on how to view and use these functions, see `Using
        Amazon Web Services built Lambda
        functions <https://docs.aws.amazon.com/AmazonS3/latest/userguide/olap-examples.html>`__
        in the *Amazon S3 User Guide*.

        :param request_route: Route prefix to the HTTP URL generated.
        :param request_token: A single use encrypted token that maps ``WriteGetObjectResponse`` to the
        end user ``GetObject`` request.
        :param body: The object data.
        :param status_code: The integer status code for an HTTP response of a corresponding
        ``GetObject`` request.
        :param error_code: A string that uniquely identifies an error condition.
        :param error_message: Contains a generic description of the error condition.
        :param accept_ranges: Indicates that a range of bytes was specified.
        :param cache_control: Specifies caching behavior along the request/reply chain.
        :param content_disposition: Specifies presentational information for the object.
        :param content_encoding: Specifies what content encodings have been applied to the object and
        thus what decoding mechanisms must be applied to obtain the media-type
        referenced by the Content-Type header field.
        :param content_language: The language the content is in.
        :param content_length: The size of the content body in bytes.
        :param content_range: The portion of the object returned in the response.
        :param content_type: A standard MIME type describing the format of the object data.
        :param checksum_crc32: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_crc32_c: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha1: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param checksum_sha256: This header can be used as a data integrity check to verify that the
        data received is the same data that was originally sent.
        :param delete_marker: Specifies whether an object stored in Amazon S3 is (``true``) or is not
        (``false``) a delete marker.
        :param e_tag: An opaque identifier assigned by a web server to a specific version of a
        resource found at a URL.
        :param expires: The date and time at which the object is no longer cacheable.
        :param expiration: If the object expiration is configured (see PUT Bucket lifecycle), the
        response includes this header.
        :param last_modified: The date and time that the object was last modified.
        :param missing_meta: Set to the number of metadata entries not returned in ``x-amz-meta``
        headers.
        :param metadata: A map of metadata to store with the object in S3.
        :param object_lock_mode: Indicates whether an object stored in Amazon S3 has Object Lock enabled.
        :param object_lock_legal_hold_status: Indicates whether an object stored in Amazon S3 has an active legal
        hold.
        :param object_lock_retain_until_date: The date and time when Object Lock is configured to expire.
        :param parts_count: The count of parts this object has.
        :param replication_status: Indicates if request involves bucket that is either a source or
        destination in a Replication rule.
        :param request_charged: If present, indicates that the requester was successfully charged for
        the request.
        :param restore: Provides information about object restoration operation and expiration
        time of the restored object copy.
        :param server_side_encryption: The server-side encryption algorithm used when storing requested object
        in Amazon S3 (for example, AES256, aws:kms).
        :param sse_customer_algorithm: Encryption algorithm used if server-side encryption with a
        customer-provided encryption key was specified for object stored in
        Amazon S3.
        :param ssekms_key_id: If present, specifies the ID of the Amazon Web Services Key Management
        Service (Amazon Web Services KMS) symmetric customer managed key that
        was used for stored in Amazon S3 object.
        :param sse_customer_key_md5: 128-bit MD5 digest of customer-provided encryption key used in Amazon S3
        to encrypt data stored in S3.
        :param storage_class: Provides storage class information of the object.
        :param tag_count: The number of tags, if any, on the object.
        :param version_id: An ID used to reference a specific version of the object.
        :param bucket_key_enabled: Indicates whether the object stored in Amazon S3 uses an S3 bucket key
        for server-side encryption with Amazon Web Services KMS (SSE-KMS).
        """
        raise NotImplementedError
