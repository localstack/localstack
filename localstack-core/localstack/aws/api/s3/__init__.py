from collections.abc import Iterable, Iterator
from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AbortRuleId = str
AcceptRanges = str
AccessKeyIdValue = str
AccessPointAlias = bool
AccessPointArn = str
AccountId = str
AllowQuotedRecordDelimiter = bool
AllowedHeader = str
AllowedMethod = str
AllowedOrigin = str
AnalyticsId = str
BucketKeyEnabled = bool
BucketLocationName = str
BucketName = str
BucketRegion = str
BypassGovernanceRetention = bool
CacheControl = str
ChecksumCRC32 = str
ChecksumCRC32C = str
ChecksumCRC64NVME = str
ChecksumSHA1 = str
ChecksumSHA256 = str
ClientToken = str
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
DirectoryBucketToken = str
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
IsRestoreInProgress = bool
IsTruncated = bool
KMSContext = str
KeyCount = int
KeyMarker = str
KeyPrefixEquals = str
KmsKeyArn = str
LambdaFunctionArn = str
Location = str
LocationNameAsString = str
LocationPrefix = str
MFA = str
Marker = str
MaxAgeSeconds = int
MaxBuckets = int
MaxDirectoryBuckets = int
MaxKeys = int
MaxParts = int
MaxUploads = int
Message = str
MetadataKey = str
MetadataTableStatus = str
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
RecordExpirationDays = int
Region = str
RenameSource = str
RenameSourceIfMatch = str
RenameSourceIfNoneMatch = str
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
S3RegionalOrS3ExpressBucketArnString = str
S3TablesArn = str
S3TablesBucketArn = str
S3TablesName = str
S3TablesNamespace = str
SSECustomerAlgorithm = str
SSECustomerKey = str
SSECustomerKeyMD5 = str
SSEKMSEncryptionContext = str
SSEKMSKeyId = str
SessionCredentialValue = str
Setting = bool
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
BucketContentType = str
IfCondition = str
RestoreObjectOutputStatusCode = int
ArgumentName = str
ArgumentValue = str
AWSAccessKeyId = str
HostId = str
HeadersNotSigned = str
SignatureProvided = str
StringToSign = str
StringToSignBytes = str
CanonicalRequest = str
CanonicalRequestBytes = str
X_Amz_Expires = int
HttpMethod = str
ResourceType = str
MissingHeaderName = str
KeyLength = str
Header = str
additionalMessage = str


class AnalyticsS3ExportFileFormat(StrEnum):
    CSV = "CSV"


class ArchiveStatus(StrEnum):
    ARCHIVE_ACCESS = "ARCHIVE_ACCESS"
    DEEP_ARCHIVE_ACCESS = "DEEP_ARCHIVE_ACCESS"


class BucketAbacStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class BucketAccelerateStatus(StrEnum):
    Enabled = "Enabled"
    Suspended = "Suspended"


class BucketCannedACL(StrEnum):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    authenticated_read = "authenticated-read"
    log_delivery_write = "log-delivery-write"


class BucketLocationConstraint(StrEnum):
    af_south_1 = "af-south-1"
    ap_east_1 = "ap-east-1"
    ap_northeast_1 = "ap-northeast-1"
    ap_northeast_2 = "ap-northeast-2"
    ap_northeast_3 = "ap-northeast-3"
    ap_south_1 = "ap-south-1"
    ap_south_2 = "ap-south-2"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ap_southeast_3 = "ap-southeast-3"
    ap_southeast_4 = "ap-southeast-4"
    ap_southeast_5 = "ap-southeast-5"
    ca_central_1 = "ca-central-1"
    cn_north_1 = "cn-north-1"
    cn_northwest_1 = "cn-northwest-1"
    EU = "EU"
    eu_central_1 = "eu-central-1"
    eu_central_2 = "eu-central-2"
    eu_north_1 = "eu-north-1"
    eu_south_1 = "eu-south-1"
    eu_south_2 = "eu-south-2"
    eu_west_1 = "eu-west-1"
    eu_west_2 = "eu-west-2"
    eu_west_3 = "eu-west-3"
    il_central_1 = "il-central-1"
    me_central_1 = "me-central-1"
    me_south_1 = "me-south-1"
    sa_east_1 = "sa-east-1"
    us_east_2 = "us-east-2"
    us_gov_east_1 = "us-gov-east-1"
    us_gov_west_1 = "us-gov-west-1"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"


class BucketLogsPermission(StrEnum):
    FULL_CONTROL = "FULL_CONTROL"
    READ = "READ"
    WRITE = "WRITE"


class BucketType(StrEnum):
    Directory = "Directory"


class BucketVersioningStatus(StrEnum):
    Enabled = "Enabled"
    Suspended = "Suspended"


class ChecksumAlgorithm(StrEnum):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    CRC64NVME = "CRC64NVME"


class ChecksumMode(StrEnum):
    ENABLED = "ENABLED"


class ChecksumType(StrEnum):
    COMPOSITE = "COMPOSITE"
    FULL_OBJECT = "FULL_OBJECT"


class CompressionType(StrEnum):
    NONE = "NONE"
    GZIP = "GZIP"
    BZIP2 = "BZIP2"


class DataRedundancy(StrEnum):
    SingleAvailabilityZone = "SingleAvailabilityZone"
    SingleLocalZone = "SingleLocalZone"


class DeleteMarkerReplicationStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class EncodingType(StrEnum):
    url = "url"


class EncryptionType(StrEnum):
    NONE = "NONE"
    SSE_C = "SSE-C"


class Event(StrEnum):
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


class ExistingObjectReplicationStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExpirationState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class ExpirationStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExpressionType(StrEnum):
    SQL = "SQL"


class FileHeaderInfo(StrEnum):
    USE = "USE"
    IGNORE = "IGNORE"
    NONE = "NONE"


class FilterRuleName(StrEnum):
    prefix = "prefix"
    suffix = "suffix"


class IntelligentTieringAccessTier(StrEnum):
    ARCHIVE_ACCESS = "ARCHIVE_ACCESS"
    DEEP_ARCHIVE_ACCESS = "DEEP_ARCHIVE_ACCESS"


class IntelligentTieringStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class InventoryConfigurationState(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class InventoryFormat(StrEnum):
    CSV = "CSV"
    ORC = "ORC"
    Parquet = "Parquet"


class InventoryFrequency(StrEnum):
    Daily = "Daily"
    Weekly = "Weekly"


class InventoryIncludedObjectVersions(StrEnum):
    All = "All"
    Current = "Current"


class InventoryOptionalField(StrEnum):
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
    ObjectAccessControlList = "ObjectAccessControlList"
    ObjectOwner = "ObjectOwner"
    LifecycleExpirationDate = "LifecycleExpirationDate"


class JSONType(StrEnum):
    DOCUMENT = "DOCUMENT"
    LINES = "LINES"


class LocationType(StrEnum):
    AvailabilityZone = "AvailabilityZone"
    LocalZone = "LocalZone"


class MFADelete(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MFADeleteStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MetadataDirective(StrEnum):
    COPY = "COPY"
    REPLACE = "REPLACE"


class MetricsStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ObjectAttributes(StrEnum):
    ETag = "ETag"
    Checksum = "Checksum"
    ObjectParts = "ObjectParts"
    StorageClass = "StorageClass"
    ObjectSize = "ObjectSize"


class ObjectCannedACL(StrEnum):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    authenticated_read = "authenticated-read"
    aws_exec_read = "aws-exec-read"
    bucket_owner_read = "bucket-owner-read"
    bucket_owner_full_control = "bucket-owner-full-control"


class ObjectLockEnabled(StrEnum):
    Enabled = "Enabled"


class ObjectLockLegalHoldStatus(StrEnum):
    ON = "ON"
    OFF = "OFF"


class ObjectLockMode(StrEnum):
    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class ObjectLockRetentionMode(StrEnum):
    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class ObjectOwnership(StrEnum):
    BucketOwnerPreferred = "BucketOwnerPreferred"
    ObjectWriter = "ObjectWriter"
    BucketOwnerEnforced = "BucketOwnerEnforced"


class ObjectStorageClass(StrEnum):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    GLACIER = "GLACIER"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"
    SNOW = "SNOW"
    EXPRESS_ONEZONE = "EXPRESS_ONEZONE"
    FSX_OPENZFS = "FSX_OPENZFS"
    FSX_ONTAP = "FSX_ONTAP"


class ObjectVersionStorageClass(StrEnum):
    STANDARD = "STANDARD"


class OptionalObjectAttributes(StrEnum):
    RestoreStatus = "RestoreStatus"


class OwnerOverride(StrEnum):
    Destination = "Destination"


class PartitionDateSource(StrEnum):
    EventTime = "EventTime"
    DeliveryTime = "DeliveryTime"


class Payer(StrEnum):
    Requester = "Requester"
    BucketOwner = "BucketOwner"


class Permission(StrEnum):
    FULL_CONTROL = "FULL_CONTROL"
    WRITE = "WRITE"
    WRITE_ACP = "WRITE_ACP"
    READ = "READ"
    READ_ACP = "READ_ACP"


class Protocol(StrEnum):
    http = "http"
    https = "https"


class QuoteFields(StrEnum):
    ALWAYS = "ALWAYS"
    ASNEEDED = "ASNEEDED"


class ReplicaModificationsStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReplicationRuleStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReplicationStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PENDING = "PENDING"
    FAILED = "FAILED"
    REPLICA = "REPLICA"
    COMPLETED = "COMPLETED"


class ReplicationTimeStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class RequestCharged(StrEnum):
    requester = "requester"


class RequestPayer(StrEnum):
    requester = "requester"


class RestoreRequestType(StrEnum):
    SELECT = "SELECT"


class S3TablesBucketType(StrEnum):
    aws = "aws"
    customer = "customer"


class ServerSideEncryption(StrEnum):
    AES256 = "AES256"
    aws_fsx = "aws:fsx"
    aws_kms = "aws:kms"
    aws_kms_dsse = "aws:kms:dsse"


class SessionMode(StrEnum):
    ReadOnly = "ReadOnly"
    ReadWrite = "ReadWrite"


class SseKmsEncryptedObjectsStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class StorageClass(StrEnum):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"
    SNOW = "SNOW"
    EXPRESS_ONEZONE = "EXPRESS_ONEZONE"
    FSX_OPENZFS = "FSX_OPENZFS"
    FSX_ONTAP = "FSX_ONTAP"


class StorageClassAnalysisSchemaVersion(StrEnum):
    V_1 = "V_1"


class TableSseAlgorithm(StrEnum):
    aws_kms = "aws:kms"
    AES256 = "AES256"


class TaggingDirective(StrEnum):
    COPY = "COPY"
    REPLACE = "REPLACE"


class Tier(StrEnum):
    Standard = "Standard"
    Bulk = "Bulk"
    Expedited = "Expedited"


class TransitionDefaultMinimumObjectSize(StrEnum):
    varies_by_storage_class = "varies_by_storage_class"
    all_storage_classes_128K = "all_storage_classes_128K"


class TransitionStorageClass(StrEnum):
    GLACIER = "GLACIER"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    GLACIER_IR = "GLACIER_IR"


class Type(StrEnum):
    CanonicalUser = "CanonicalUser"
    AmazonCustomerByEmail = "AmazonCustomerByEmail"
    Group = "Group"


class BucketAlreadyExists(ServiceException):
    code: str = "BucketAlreadyExists"
    sender_fault: bool = False
    status_code: int = 409


class BucketAlreadyOwnedByYou(ServiceException):
    code: str = "BucketAlreadyOwnedByYou"
    sender_fault: bool = False
    status_code: int = 409
    BucketName: BucketName | None


class EncryptionTypeMismatch(ServiceException):
    code: str = "EncryptionTypeMismatch"
    sender_fault: bool = False
    status_code: int = 400


class IdempotencyParameterMismatch(ServiceException):
    code: str = "IdempotencyParameterMismatch"
    sender_fault: bool = False
    status_code: int = 400


class InvalidObjectState(ServiceException):
    code: str = "InvalidObjectState"
    sender_fault: bool = False
    status_code: int = 403
    StorageClass: StorageClass | None
    AccessTier: IntelligentTieringAccessTier | None


class InvalidRequest(ServiceException):
    code: str = "InvalidRequest"
    sender_fault: bool = False
    status_code: int = 400


class InvalidWriteOffset(ServiceException):
    code: str = "InvalidWriteOffset"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchBucket(ServiceException):
    code: str = "NoSuchBucket"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class NoSuchKey(ServiceException):
    code: str = "NoSuchKey"
    sender_fault: bool = False
    status_code: int = 404
    Key: ObjectKey | None
    DeleteMarker: DeleteMarker | None
    VersionId: ObjectVersionId | None


class NoSuchUpload(ServiceException):
    code: str = "NoSuchUpload"
    sender_fault: bool = False
    status_code: int = 404
    UploadId: MultipartUploadId | None


class ObjectAlreadyInActiveTierError(ServiceException):
    code: str = "ObjectAlreadyInActiveTierError"
    sender_fault: bool = False
    status_code: int = 403


class ObjectNotInActiveTierError(ServiceException):
    code: str = "ObjectNotInActiveTierError"
    sender_fault: bool = False
    status_code: int = 403


class TooManyParts(ServiceException):
    code: str = "TooManyParts"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchLifecycleConfiguration(ServiceException):
    code: str = "NoSuchLifecycleConfiguration"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class InvalidBucketName(ServiceException):
    code: str = "InvalidBucketName"
    sender_fault: bool = False
    status_code: int = 400
    BucketName: BucketName | None


class NoSuchVersion(ServiceException):
    code: str = "NoSuchVersion"
    sender_fault: bool = False
    status_code: int = 404
    VersionId: ObjectVersionId | None
    Key: ObjectKey | None


class PreconditionFailed(ServiceException):
    code: str = "PreconditionFailed"
    sender_fault: bool = False
    status_code: int = 412
    Condition: IfCondition | None


ObjectSize = int


class InvalidRange(ServiceException):
    code: str = "InvalidRange"
    sender_fault: bool = False
    status_code: int = 416
    ActualObjectSize: ObjectSize | None
    RangeRequested: ContentRange | None


class InvalidArgument(ServiceException):
    code: str = "InvalidArgument"
    sender_fault: bool = False
    status_code: int = 400
    ArgumentName: ArgumentName | None
    ArgumentValue: ArgumentValue | None
    HostId: HostId | None


class SignatureDoesNotMatch(ServiceException):
    code: str = "SignatureDoesNotMatch"
    sender_fault: bool = False
    status_code: int = 403
    AWSAccessKeyId: AWSAccessKeyId | None
    CanonicalRequest: CanonicalRequest | None
    CanonicalRequestBytes: CanonicalRequestBytes | None
    HostId: HostId | None
    SignatureProvided: SignatureProvided | None
    StringToSign: StringToSign | None
    StringToSignBytes: StringToSignBytes | None


ServerTime = datetime
Expires = datetime


class AccessDenied(ServiceException):
    code: str = "AccessDenied"
    sender_fault: bool = False
    status_code: int = 403
    Expires: Expires | None
    ServerTime: ServerTime | None
    X_Amz_Expires: X_Amz_Expires | None
    HostId: HostId | None
    HeadersNotSigned: HeadersNotSigned | None


class AuthorizationQueryParametersError(ServiceException):
    code: str = "AuthorizationQueryParametersError"
    sender_fault: bool = False
    status_code: int = 400
    HostId: HostId | None


class NoSuchWebsiteConfiguration(ServiceException):
    code: str = "NoSuchWebsiteConfiguration"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class ReplicationConfigurationNotFoundError(ServiceException):
    code: str = "ReplicationConfigurationNotFoundError"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class BadRequest(ServiceException):
    code: str = "BadRequest"
    sender_fault: bool = False
    status_code: int = 400
    HostId: HostId | None


class AccessForbidden(ServiceException):
    code: str = "AccessForbidden"
    sender_fault: bool = False
    status_code: int = 403
    HostId: HostId | None
    Method: HttpMethod | None
    ResourceType: ResourceType | None


class NoSuchCORSConfiguration(ServiceException):
    code: str = "NoSuchCORSConfiguration"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class MissingSecurityHeader(ServiceException):
    code: str = "MissingSecurityHeader"
    sender_fault: bool = False
    status_code: int = 400
    MissingHeaderName: MissingHeaderName | None


class InvalidPartOrder(ServiceException):
    code: str = "InvalidPartOrder"
    sender_fault: bool = False
    status_code: int = 400
    UploadId: MultipartUploadId | None


class InvalidStorageClass(ServiceException):
    code: str = "InvalidStorageClass"
    sender_fault: bool = False
    status_code: int = 400
    StorageClassRequested: StorageClass | None


class MethodNotAllowed(ServiceException):
    code: str = "MethodNotAllowed"
    sender_fault: bool = False
    status_code: int = 405
    Method: HttpMethod | None
    ResourceType: ResourceType | None
    DeleteMarker: DeleteMarker | None
    VersionId: ObjectVersionId | None
    Allow: HttpMethod | None


class CrossLocationLoggingProhibitted(ServiceException):
    code: str = "CrossLocationLoggingProhibitted"
    sender_fault: bool = False
    status_code: int = 403
    TargetBucketLocation: BucketRegion | None
    SourceBucketLocation: BucketRegion | None


class InvalidTargetBucketForLogging(ServiceException):
    code: str = "InvalidTargetBucketForLogging"
    sender_fault: bool = False
    status_code: int = 400
    TargetBucket: BucketName | None


class BucketNotEmpty(ServiceException):
    code: str = "BucketNotEmpty"
    sender_fault: bool = False
    status_code: int = 409
    BucketName: BucketName | None


ProposedSize = int
MinSizeAllowed = int


class EntityTooSmall(ServiceException):
    code: str = "EntityTooSmall"
    sender_fault: bool = False
    status_code: int = 400
    ETag: ETag | None
    MinSizeAllowed: MinSizeAllowed | None
    PartNumber: PartNumber | None
    ProposedSize: ProposedSize | None


class InvalidPart(ServiceException):
    code: str = "InvalidPart"
    sender_fault: bool = False
    status_code: int = 400
    ETag: ETag | None
    UploadId: MultipartUploadId | None
    PartNumber: PartNumber | None


class NoSuchTagSet(ServiceException):
    code: str = "NoSuchTagSet"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class InvalidTag(ServiceException):
    code: str = "InvalidTag"
    sender_fault: bool = False
    status_code: int = 400
    TagKey: ObjectKey | None
    TagValue: Value | None


class ObjectLockConfigurationNotFoundError(ServiceException):
    code: str = "ObjectLockConfigurationNotFoundError"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class InvalidPartNumber(ServiceException):
    code: str = "InvalidPartNumber"
    sender_fault: bool = False
    status_code: int = 416
    PartNumberRequested: PartNumber | None
    ActualPartCount: PartNumber | None


class OwnershipControlsNotFoundError(ServiceException):
    code: str = "OwnershipControlsNotFoundError"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class NoSuchPublicAccessBlockConfiguration(ServiceException):
    code: str = "NoSuchPublicAccessBlockConfiguration"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class NoSuchBucketPolicy(ServiceException):
    code: str = "NoSuchBucketPolicy"
    sender_fault: bool = False
    status_code: int = 404
    BucketName: BucketName | None


class InvalidDigest(ServiceException):
    code: str = "InvalidDigest"
    sender_fault: bool = False
    status_code: int = 400
    Content_MD5: ContentMD5 | None


class KeyTooLongError(ServiceException):
    code: str = "KeyTooLongError"
    sender_fault: bool = False
    status_code: int = 400
    MaxSizeAllowed: KeyLength | None
    Size: KeyLength | None


class InvalidLocationConstraint(ServiceException):
    code: str = "InvalidLocationConstraint"
    sender_fault: bool = False
    status_code: int = 400
    LocationConstraint: BucketRegion | None


class EntityTooLarge(ServiceException):
    code: str = "EntityTooLarge"
    sender_fault: bool = False
    status_code: int = 400
    MaxSizeAllowed: KeyLength | None
    HostId: HostId | None
    ProposedSize: ProposedSize | None


class InvalidEncryptionAlgorithmError(ServiceException):
    code: str = "InvalidEncryptionAlgorithmError"
    sender_fault: bool = False
    status_code: int = 400
    ArgumentName: ArgumentName | None
    ArgumentValue: ArgumentValue | None


class NotImplemented(ServiceException):
    code: str = "NotImplemented"
    sender_fault: bool = False
    status_code: int = 501
    Header: Header | None
    additionalMessage: additionalMessage | None


class ConditionalRequestConflict(ServiceException):
    code: str = "ConditionalRequestConflict"
    sender_fault: bool = False
    status_code: int = 409
    Condition: IfCondition | None
    Key: ObjectKey | None


class BadDigest(ServiceException):
    code: str = "BadDigest"
    sender_fault: bool = False
    status_code: int = 400
    ExpectedDigest: ContentMD5 | None
    CalculatedDigest: ContentMD5 | None


class AuthorizationHeaderMalformed(ServiceException):
    code: str = "AuthorizationHeaderMalformed"
    sender_fault: bool = False
    status_code: int = 400
    Region: BucketRegion | None
    HostId: HostId | None


class AbacStatus(TypedDict, total=False):
    Status: BucketAbacStatus | None


AbortDate = datetime


class AbortIncompleteMultipartUpload(TypedDict, total=False):
    DaysAfterInitiation: DaysAfterInitiation | None


class AbortMultipartUploadOutput(TypedDict, total=False):
    RequestCharged: RequestCharged | None


IfMatchInitiatedTime = datetime


class AbortMultipartUploadRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    UploadId: MultipartUploadId
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    IfMatchInitiatedTime: IfMatchInitiatedTime | None


class AccelerateConfiguration(TypedDict, total=False):
    Status: BucketAccelerateStatus | None


class Owner(TypedDict, total=False):
    DisplayName: DisplayName | None
    ID: ID | None


class Grantee(TypedDict, total=False):
    DisplayName: DisplayName | None
    EmailAddress: EmailAddress | None
    ID: ID | None
    Type: Type
    URI: URI | None


class Grant(TypedDict, total=False):
    Grantee: Grantee | None
    Permission: Permission | None


Grants = list[Grant]


class AccessControlPolicy(TypedDict, total=False):
    Grants: Grants | None
    Owner: Owner | None


class AccessControlTranslation(TypedDict, total=False):
    Owner: OwnerOverride


AllowedHeaders = list[AllowedHeader]
AllowedMethods = list[AllowedMethod]
AllowedOrigins = list[AllowedOrigin]


class Tag(TypedDict, total=False):
    Key: ObjectKey
    Value: Value


TagSet = list[Tag]


class AnalyticsAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: TagSet | None


class AnalyticsS3BucketDestination(TypedDict, total=False):
    Format: AnalyticsS3ExportFileFormat
    BucketAccountId: AccountId | None
    Bucket: BucketName
    Prefix: Prefix | None


class AnalyticsExportDestination(TypedDict, total=False):
    S3BucketDestination: AnalyticsS3BucketDestination


class StorageClassAnalysisDataExport(TypedDict, total=False):
    OutputSchemaVersion: StorageClassAnalysisSchemaVersion
    Destination: AnalyticsExportDestination


class StorageClassAnalysis(TypedDict, total=False):
    DataExport: StorageClassAnalysisDataExport | None


class AnalyticsFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: Tag | None
    And: AnalyticsAndOperator | None


class AnalyticsConfiguration(TypedDict, total=False):
    Id: AnalyticsId
    Filter: AnalyticsFilter | None
    StorageClassAnalysis: StorageClassAnalysis


AnalyticsConfigurationList = list[AnalyticsConfiguration]
EncryptionTypeList = list[EncryptionType]


class BlockedEncryptionTypes(TypedDict, total=False):
    EncryptionType: EncryptionTypeList | None


Body = bytes
CreationDate = datetime


class Bucket(TypedDict, total=False):
    Name: BucketName | None
    CreationDate: CreationDate | None
    BucketRegion: BucketRegion | None
    BucketArn: S3RegionalOrS3ExpressBucketArnString | None


class BucketInfo(TypedDict, total=False):
    DataRedundancy: DataRedundancy | None
    Type: BucketType | None


class NoncurrentVersionExpiration(TypedDict, total=False):
    NoncurrentDays: Days | None
    NewerNoncurrentVersions: VersionCount | None


class NoncurrentVersionTransition(TypedDict, total=False):
    NoncurrentDays: Days | None
    StorageClass: TransitionStorageClass | None
    NewerNoncurrentVersions: VersionCount | None


NoncurrentVersionTransitionList = list[NoncurrentVersionTransition]
Date = datetime


class Transition(TypedDict, total=False):
    Date: Date | None
    Days: Days | None
    StorageClass: TransitionStorageClass | None


TransitionList = list[Transition]
ObjectSizeLessThanBytes = int
ObjectSizeGreaterThanBytes = int


class LifecycleRuleAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: TagSet | None
    ObjectSizeGreaterThan: ObjectSizeGreaterThanBytes | None
    ObjectSizeLessThan: ObjectSizeLessThanBytes | None


class LifecycleRuleFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: Tag | None
    ObjectSizeGreaterThan: ObjectSizeGreaterThanBytes | None
    ObjectSizeLessThan: ObjectSizeLessThanBytes | None
    And: LifecycleRuleAndOperator | None


class LifecycleExpiration(TypedDict, total=False):
    Date: Date | None
    Days: Days | None
    ExpiredObjectDeleteMarker: ExpiredObjectDeleteMarker | None


class LifecycleRule(TypedDict, total=False):
    Expiration: LifecycleExpiration | None
    ID: ID | None
    Prefix: Prefix | None
    Filter: LifecycleRuleFilter | None
    Status: ExpirationStatus
    Transitions: TransitionList | None
    NoncurrentVersionTransitions: NoncurrentVersionTransitionList | None
    NoncurrentVersionExpiration: NoncurrentVersionExpiration | None
    AbortIncompleteMultipartUpload: AbortIncompleteMultipartUpload | None


LifecycleRules = list[LifecycleRule]


class BucketLifecycleConfiguration(TypedDict, total=False):
    Rules: LifecycleRules


class PartitionedPrefix(TypedDict, total=False):
    PartitionDateSource: PartitionDateSource | None


class SimplePrefix(TypedDict, total=False):
    pass


class TargetObjectKeyFormat(TypedDict, total=False):
    SimplePrefix: SimplePrefix | None
    PartitionedPrefix: PartitionedPrefix | None


class TargetGrant(TypedDict, total=False):
    Grantee: Grantee | None
    Permission: BucketLogsPermission | None


TargetGrants = list[TargetGrant]


class LoggingEnabled(TypedDict, total=False):
    TargetBucket: TargetBucket
    TargetGrants: TargetGrants | None
    TargetPrefix: TargetPrefix
    TargetObjectKeyFormat: TargetObjectKeyFormat | None


class BucketLoggingStatus(TypedDict, total=False):
    LoggingEnabled: LoggingEnabled | None


Buckets = list[Bucket]
BytesProcessed = int
BytesReturned = int
BytesScanned = int
ExposeHeaders = list[ExposeHeader]


class CORSRule(TypedDict, total=False):
    ID: ID | None
    AllowedHeaders: AllowedHeaders | None
    AllowedMethods: AllowedMethods
    AllowedOrigins: AllowedOrigins
    ExposeHeaders: ExposeHeaders | None
    MaxAgeSeconds: MaxAgeSeconds | None


CORSRules = list[CORSRule]


class CORSConfiguration(TypedDict, total=False):
    CORSRules: CORSRules


class CSVInput(TypedDict, total=False):
    FileHeaderInfo: FileHeaderInfo | None
    Comments: Comments | None
    QuoteEscapeCharacter: QuoteEscapeCharacter | None
    RecordDelimiter: RecordDelimiter | None
    FieldDelimiter: FieldDelimiter | None
    QuoteCharacter: QuoteCharacter | None
    AllowQuotedRecordDelimiter: AllowQuotedRecordDelimiter | None


class CSVOutput(TypedDict, total=False):
    QuoteFields: QuoteFields | None
    QuoteEscapeCharacter: QuoteEscapeCharacter | None
    RecordDelimiter: RecordDelimiter | None
    FieldDelimiter: FieldDelimiter | None
    QuoteCharacter: QuoteCharacter | None


class Checksum(TypedDict, total=False):
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None


ChecksumAlgorithmList = list[ChecksumAlgorithm]
EventList = list[Event]


class CloudFunctionConfiguration(TypedDict, total=False):
    Id: NotificationId | None
    Event: Event | None
    Events: EventList | None
    CloudFunction: CloudFunction | None
    InvocationRole: CloudFunctionInvocationRole | None


class CommonPrefix(TypedDict, total=False):
    Prefix: Prefix | None


CommonPrefixList = list[CommonPrefix]


class CompleteMultipartUploadOutput(TypedDict, total=False):
    Location: Location | None
    Bucket: BucketName | None
    Key: ObjectKey | None
    Expiration: Expiration | None
    ETag: ETag | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None
    ServerSideEncryption: ServerSideEncryption | None
    VersionId: ObjectVersionId | None
    SSEKMSKeyId: SSEKMSKeyId | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestCharged: RequestCharged | None


MpuObjectSize = int


class CompletedPart(TypedDict, total=False):
    ETag: ETag | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    PartNumber: PartNumber | None


CompletedPartList = list[CompletedPart]


class CompletedMultipartUpload(TypedDict, total=False):
    Parts: CompletedPartList | None


class CompleteMultipartUploadRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    MultipartUpload: CompletedMultipartUpload | None
    UploadId: MultipartUploadId
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None
    MpuObjectSize: MpuObjectSize | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    IfMatch: IfMatch | None
    IfNoneMatch: IfNoneMatch | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None


class Condition(TypedDict, total=False):
    HttpErrorCodeReturnedEquals: HttpErrorCodeReturnedEquals | None
    KeyPrefixEquals: KeyPrefixEquals | None


ContentLength = int


class ContinuationEvent(TypedDict, total=False):
    pass


LastModified = datetime


class CopyObjectResult(TypedDict, total=False):
    ETag: ETag | None
    LastModified: LastModified | None
    ChecksumType: ChecksumType | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None


class CopyObjectOutput(TypedDict, total=False):
    CopyObjectResult: CopyObjectResult | None
    Expiration: Expiration | None
    CopySourceVersionId: CopySourceVersionId | None
    VersionId: ObjectVersionId | None
    ServerSideEncryption: ServerSideEncryption | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestCharged: RequestCharged | None


ObjectLockRetainUntilDate = datetime
Metadata = dict[MetadataKey, MetadataValue]
CopySourceIfUnmodifiedSince = datetime
CopySourceIfModifiedSince = datetime


class CopyObjectRequest(ServiceRequest):
    ACL: ObjectCannedACL | None
    Bucket: BucketName
    CacheControl: CacheControl | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ContentDisposition: ContentDisposition | None
    ContentEncoding: ContentEncoding | None
    ContentLanguage: ContentLanguage | None
    ContentType: ContentType | None
    CopySource: CopySource
    CopySourceIfMatch: CopySourceIfMatch | None
    CopySourceIfModifiedSince: CopySourceIfModifiedSince | None
    CopySourceIfNoneMatch: CopySourceIfNoneMatch | None
    CopySourceIfUnmodifiedSince: CopySourceIfUnmodifiedSince | None
    Expires: Expires | None
    GrantFullControl: GrantFullControl | None
    GrantRead: GrantRead | None
    GrantReadACP: GrantReadACP | None
    GrantWriteACP: GrantWriteACP | None
    IfMatch: IfMatch | None
    IfNoneMatch: IfNoneMatch | None
    Key: ObjectKey
    Metadata: Metadata | None
    MetadataDirective: MetadataDirective | None
    TaggingDirective: TaggingDirective | None
    ServerSideEncryption: ServerSideEncryption | None
    StorageClass: StorageClass | None
    WebsiteRedirectLocation: WebsiteRedirectLocation | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    CopySourceSSECustomerAlgorithm: CopySourceSSECustomerAlgorithm | None
    CopySourceSSECustomerKey: CopySourceSSECustomerKey | None
    CopySourceSSECustomerKeyMD5: CopySourceSSECustomerKeyMD5 | None
    RequestPayer: RequestPayer | None
    Tagging: TaggingHeader | None
    ObjectLockMode: ObjectLockMode | None
    ObjectLockRetainUntilDate: ObjectLockRetainUntilDate | None
    ObjectLockLegalHoldStatus: ObjectLockLegalHoldStatus | None
    ExpectedBucketOwner: AccountId | None
    ExpectedSourceBucketOwner: AccountId | None


class CopyPartResult(TypedDict, total=False):
    ETag: ETag | None
    LastModified: LastModified | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None


class LocationInfo(TypedDict, total=False):
    Type: LocationType | None
    Name: LocationNameAsString | None


class CreateBucketConfiguration(TypedDict, total=False):
    LocationConstraint: BucketLocationConstraint | None
    Location: LocationInfo | None
    Bucket: BucketInfo | None
    Tags: TagSet | None


class MetadataTableEncryptionConfiguration(TypedDict, total=False):
    SseAlgorithm: TableSseAlgorithm
    KmsKeyArn: KmsKeyArn | None


class InventoryTableConfiguration(TypedDict, total=False):
    ConfigurationState: InventoryConfigurationState
    EncryptionConfiguration: MetadataTableEncryptionConfiguration | None


class RecordExpiration(TypedDict, total=False):
    Expiration: ExpirationState
    Days: RecordExpirationDays | None


class JournalTableConfiguration(TypedDict, total=False):
    RecordExpiration: RecordExpiration
    EncryptionConfiguration: MetadataTableEncryptionConfiguration | None


class MetadataConfiguration(TypedDict, total=False):
    JournalTableConfiguration: JournalTableConfiguration
    InventoryTableConfiguration: InventoryTableConfiguration | None


class CreateBucketMetadataConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    MetadataConfiguration: MetadataConfiguration
    ExpectedBucketOwner: AccountId | None


class S3TablesDestination(TypedDict, total=False):
    TableBucketArn: S3TablesBucketArn
    TableName: S3TablesName


class MetadataTableConfiguration(TypedDict, total=False):
    S3TablesDestination: S3TablesDestination


class CreateBucketMetadataTableConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    MetadataTableConfiguration: MetadataTableConfiguration
    ExpectedBucketOwner: AccountId | None


class CreateBucketOutput(TypedDict, total=False):
    Location: Location | None
    BucketArn: S3RegionalOrS3ExpressBucketArnString | None


class CreateBucketRequest(ServiceRequest):
    ACL: BucketCannedACL | None
    Bucket: BucketName
    CreateBucketConfiguration: CreateBucketConfiguration | None
    GrantFullControl: GrantFullControl | None
    GrantRead: GrantRead | None
    GrantReadACP: GrantReadACP | None
    GrantWrite: GrantWrite | None
    GrantWriteACP: GrantWriteACP | None
    ObjectLockEnabledForBucket: ObjectLockEnabledForBucket | None
    ObjectOwnership: ObjectOwnership | None


class CreateMultipartUploadOutput(TypedDict, total=False):
    AbortDate: AbortDate | None
    AbortRuleId: AbortRuleId | None
    Bucket: BucketName | None
    Key: ObjectKey | None
    UploadId: MultipartUploadId | None
    ServerSideEncryption: ServerSideEncryption | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestCharged: RequestCharged | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ChecksumType: ChecksumType | None


class CreateMultipartUploadRequest(ServiceRequest):
    ACL: ObjectCannedACL | None
    Bucket: BucketName
    CacheControl: CacheControl | None
    ContentDisposition: ContentDisposition | None
    ContentEncoding: ContentEncoding | None
    ContentLanguage: ContentLanguage | None
    ContentType: ContentType | None
    Expires: Expires | None
    GrantFullControl: GrantFullControl | None
    GrantRead: GrantRead | None
    GrantReadACP: GrantReadACP | None
    GrantWriteACP: GrantWriteACP | None
    Key: ObjectKey
    Metadata: Metadata | None
    ServerSideEncryption: ServerSideEncryption | None
    StorageClass: StorageClass | None
    WebsiteRedirectLocation: WebsiteRedirectLocation | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestPayer: RequestPayer | None
    Tagging: TaggingHeader | None
    ObjectLockMode: ObjectLockMode | None
    ObjectLockRetainUntilDate: ObjectLockRetainUntilDate | None
    ObjectLockLegalHoldStatus: ObjectLockLegalHoldStatus | None
    ExpectedBucketOwner: AccountId | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ChecksumType: ChecksumType | None


SessionExpiration = datetime


class SessionCredentials(TypedDict, total=False):
    AccessKeyId: AccessKeyIdValue
    SecretAccessKey: SessionCredentialValue
    SessionToken: SessionCredentialValue
    Expiration: SessionExpiration


class CreateSessionOutput(TypedDict, total=False):
    ServerSideEncryption: ServerSideEncryption | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    Credentials: SessionCredentials


class CreateSessionRequest(ServiceRequest):
    SessionMode: SessionMode | None
    Bucket: BucketName
    ServerSideEncryption: ServerSideEncryption | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None


class DefaultRetention(TypedDict, total=False):
    Mode: ObjectLockRetentionMode | None
    Days: Days | None
    Years: Years | None


Size = int
LastModifiedTime = datetime


class ObjectIdentifier(TypedDict, total=False):
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    ETag: ETag | None
    LastModifiedTime: LastModifiedTime | None
    Size: Size | None


ObjectIdentifierList = list[ObjectIdentifier]


class Delete(TypedDict, total=False):
    Objects: ObjectIdentifierList
    Quiet: Quiet | None


class DeleteBucketAnalyticsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: AnalyticsId
    ExpectedBucketOwner: AccountId | None


class DeleteBucketCorsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketEncryptionRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketIntelligentTieringConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: IntelligentTieringId
    ExpectedBucketOwner: AccountId | None


class DeleteBucketInventoryConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: InventoryId
    ExpectedBucketOwner: AccountId | None


class DeleteBucketLifecycleRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketMetadataConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketMetadataTableConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketMetricsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: MetricsId
    ExpectedBucketOwner: AccountId | None


class DeleteBucketOwnershipControlsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketPolicyRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketReplicationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketTaggingRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteBucketWebsiteRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class DeleteMarkerEntry(TypedDict, total=False):
    Owner: Owner | None
    Key: ObjectKey | None
    VersionId: ObjectVersionId | None
    IsLatest: IsLatest | None
    LastModified: LastModified | None


class DeleteMarkerReplication(TypedDict, total=False):
    Status: DeleteMarkerReplicationStatus | None


DeleteMarkers = list[DeleteMarkerEntry]


class DeleteObjectOutput(TypedDict, total=False):
    DeleteMarker: DeleteMarker | None
    VersionId: ObjectVersionId | None
    RequestCharged: RequestCharged | None


IfMatchSize = int
IfMatchLastModifiedTime = datetime


class DeleteObjectRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    MFA: MFA | None
    VersionId: ObjectVersionId | None
    RequestPayer: RequestPayer | None
    BypassGovernanceRetention: BypassGovernanceRetention | None
    ExpectedBucketOwner: AccountId | None
    IfMatch: IfMatch | None
    IfMatchLastModifiedTime: IfMatchLastModifiedTime | None
    IfMatchSize: IfMatchSize | None


class DeleteObjectTaggingOutput(TypedDict, total=False):
    VersionId: ObjectVersionId | None


class DeleteObjectTaggingRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    ExpectedBucketOwner: AccountId | None


class Error(TypedDict, total=False):
    Key: ObjectKey | None
    VersionId: ObjectVersionId | None
    Code: Code | None
    Message: Message | None


Errors = list[Error]


class DeletedObject(TypedDict, total=False):
    Key: ObjectKey | None
    VersionId: ObjectVersionId | None
    DeleteMarker: DeleteMarker | None
    DeleteMarkerVersionId: DeleteMarkerVersionId | None


DeletedObjects = list[DeletedObject]


class DeleteObjectsOutput(TypedDict, total=False):
    Deleted: DeletedObjects | None
    RequestCharged: RequestCharged | None
    Errors: Errors | None


class DeleteObjectsRequest(ServiceRequest):
    Bucket: BucketName
    Delete: Delete
    MFA: MFA | None
    RequestPayer: RequestPayer | None
    BypassGovernanceRetention: BypassGovernanceRetention | None
    ExpectedBucketOwner: AccountId | None
    ChecksumAlgorithm: ChecksumAlgorithm | None


class DeletePublicAccessBlockRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class ReplicationTimeValue(TypedDict, total=False):
    Minutes: Minutes | None


class Metrics(TypedDict, total=False):
    Status: MetricsStatus
    EventThreshold: ReplicationTimeValue | None


class ReplicationTime(TypedDict, total=False):
    Status: ReplicationTimeStatus
    Time: ReplicationTimeValue


class EncryptionConfiguration(TypedDict, total=False):
    ReplicaKmsKeyID: ReplicaKmsKeyID | None


class Destination(TypedDict, total=False):
    Bucket: BucketName
    Account: AccountId | None
    StorageClass: StorageClass | None
    AccessControlTranslation: AccessControlTranslation | None
    EncryptionConfiguration: EncryptionConfiguration | None
    ReplicationTime: ReplicationTime | None
    Metrics: Metrics | None


class DestinationResult(TypedDict, total=False):
    TableBucketType: S3TablesBucketType | None
    TableBucketArn: S3TablesBucketArn | None
    TableNamespace: S3TablesNamespace | None


class Encryption(TypedDict, total=False):
    EncryptionType: ServerSideEncryption
    KMSKeyId: SSEKMSKeyId | None
    KMSContext: KMSContext | None


End = int


class EndEvent(TypedDict, total=False):
    pass


class ErrorDetails(TypedDict, total=False):
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


class ErrorDocument(TypedDict, total=False):
    Key: ObjectKey


class EventBridgeConfiguration(TypedDict, total=False):
    pass


class ExistingObjectReplication(TypedDict, total=False):
    Status: ExistingObjectReplicationStatus


class FilterRule(TypedDict, total=False):
    Name: FilterRuleName | None
    Value: FilterRuleValue | None


FilterRuleList = list[FilterRule]


class GetBucketAbacOutput(TypedDict, total=False):
    AbacStatus: AbacStatus | None


class GetBucketAbacRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketAccelerateConfigurationOutput(TypedDict, total=False):
    Status: BucketAccelerateStatus | None
    RequestCharged: RequestCharged | None


class GetBucketAccelerateConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None
    RequestPayer: RequestPayer | None


class GetBucketAclOutput(TypedDict, total=False):
    Owner: Owner | None
    Grants: Grants | None


class GetBucketAclRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketAnalyticsConfigurationOutput(TypedDict, total=False):
    AnalyticsConfiguration: AnalyticsConfiguration | None


class GetBucketAnalyticsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: AnalyticsId
    ExpectedBucketOwner: AccountId | None


class GetBucketCorsOutput(TypedDict, total=False):
    CORSRules: CORSRules | None


class GetBucketCorsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class ServerSideEncryptionByDefault(TypedDict, total=False):
    SSEAlgorithm: ServerSideEncryption
    KMSMasterKeyID: SSEKMSKeyId | None


class ServerSideEncryptionRule(TypedDict, total=False):
    ApplyServerSideEncryptionByDefault: ServerSideEncryptionByDefault | None
    BucketKeyEnabled: BucketKeyEnabled | None
    BlockedEncryptionTypes: BlockedEncryptionTypes | None


ServerSideEncryptionRules = list[ServerSideEncryptionRule]


class ServerSideEncryptionConfiguration(TypedDict, total=False):
    Rules: ServerSideEncryptionRules


class GetBucketEncryptionOutput(TypedDict, total=False):
    ServerSideEncryptionConfiguration: ServerSideEncryptionConfiguration | None


class GetBucketEncryptionRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class Tiering(TypedDict, total=False):
    Days: IntelligentTieringDays
    AccessTier: IntelligentTieringAccessTier


TieringList = list[Tiering]


class IntelligentTieringAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: TagSet | None


class IntelligentTieringFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: Tag | None
    And: IntelligentTieringAndOperator | None


class IntelligentTieringConfiguration(TypedDict, total=False):
    Id: IntelligentTieringId
    Filter: IntelligentTieringFilter | None
    Status: IntelligentTieringStatus
    Tierings: TieringList


class GetBucketIntelligentTieringConfigurationOutput(TypedDict, total=False):
    IntelligentTieringConfiguration: IntelligentTieringConfiguration | None


class GetBucketIntelligentTieringConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: IntelligentTieringId
    ExpectedBucketOwner: AccountId | None


class InventorySchedule(TypedDict, total=False):
    Frequency: InventoryFrequency


InventoryOptionalFields = list[InventoryOptionalField]


class InventoryFilter(TypedDict, total=False):
    Prefix: Prefix


class SSEKMS(TypedDict, total=False):
    KeyId: SSEKMSKeyId


class SSES3(TypedDict, total=False):
    pass


class InventoryEncryption(TypedDict, total=False):
    SSES3: SSES3 | None
    SSEKMS: SSEKMS | None


class InventoryS3BucketDestination(TypedDict, total=False):
    AccountId: AccountId | None
    Bucket: BucketName
    Format: InventoryFormat
    Prefix: Prefix | None
    Encryption: InventoryEncryption | None


class InventoryDestination(TypedDict, total=False):
    S3BucketDestination: InventoryS3BucketDestination


class InventoryConfiguration(TypedDict, total=False):
    Destination: InventoryDestination
    IsEnabled: IsEnabled
    Filter: InventoryFilter | None
    Id: InventoryId
    IncludedObjectVersions: InventoryIncludedObjectVersions
    OptionalFields: InventoryOptionalFields | None
    Schedule: InventorySchedule


class GetBucketInventoryConfigurationOutput(TypedDict, total=False):
    InventoryConfiguration: InventoryConfiguration | None


class GetBucketInventoryConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: InventoryId
    ExpectedBucketOwner: AccountId | None


class GetBucketLifecycleConfigurationOutput(TypedDict, total=False):
    Rules: LifecycleRules | None
    TransitionDefaultMinimumObjectSize: TransitionDefaultMinimumObjectSize | None


class GetBucketLifecycleConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class Rule(TypedDict, total=False):
    Expiration: LifecycleExpiration | None
    ID: ID | None
    Prefix: Prefix
    Status: ExpirationStatus
    Transition: Transition | None
    NoncurrentVersionTransition: NoncurrentVersionTransition | None
    NoncurrentVersionExpiration: NoncurrentVersionExpiration | None
    AbortIncompleteMultipartUpload: AbortIncompleteMultipartUpload | None


Rules = list[Rule]


class GetBucketLifecycleOutput(TypedDict, total=False):
    Rules: Rules | None


class GetBucketLifecycleRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketLocationOutput(TypedDict, total=False):
    LocationConstraint: BucketLocationConstraint | None


class GetBucketLocationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketLoggingOutput(TypedDict, total=False):
    LoggingEnabled: LoggingEnabled | None


class GetBucketLoggingRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class InventoryTableConfigurationResult(TypedDict, total=False):
    ConfigurationState: InventoryConfigurationState
    TableStatus: MetadataTableStatus | None
    Error: ErrorDetails | None
    TableName: S3TablesName | None
    TableArn: S3TablesArn | None


class JournalTableConfigurationResult(TypedDict, total=False):
    TableStatus: MetadataTableStatus
    Error: ErrorDetails | None
    TableName: S3TablesName
    TableArn: S3TablesArn | None
    RecordExpiration: RecordExpiration


class MetadataConfigurationResult(TypedDict, total=False):
    DestinationResult: DestinationResult
    JournalTableConfigurationResult: JournalTableConfigurationResult | None
    InventoryTableConfigurationResult: InventoryTableConfigurationResult | None


class GetBucketMetadataConfigurationResult(TypedDict, total=False):
    MetadataConfigurationResult: MetadataConfigurationResult


class GetBucketMetadataConfigurationOutput(TypedDict, total=False):
    GetBucketMetadataConfigurationResult: GetBucketMetadataConfigurationResult | None


class GetBucketMetadataConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class S3TablesDestinationResult(TypedDict, total=False):
    TableBucketArn: S3TablesBucketArn
    TableName: S3TablesName
    TableArn: S3TablesArn
    TableNamespace: S3TablesNamespace


class MetadataTableConfigurationResult(TypedDict, total=False):
    S3TablesDestinationResult: S3TablesDestinationResult


class GetBucketMetadataTableConfigurationResult(TypedDict, total=False):
    MetadataTableConfigurationResult: MetadataTableConfigurationResult
    Status: MetadataTableStatus
    Error: ErrorDetails | None


class GetBucketMetadataTableConfigurationOutput(TypedDict, total=False):
    GetBucketMetadataTableConfigurationResult: GetBucketMetadataTableConfigurationResult | None


class GetBucketMetadataTableConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class MetricsAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: TagSet | None
    AccessPointArn: AccessPointArn | None


class MetricsFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: Tag | None
    AccessPointArn: AccessPointArn | None
    And: MetricsAndOperator | None


class MetricsConfiguration(TypedDict, total=False):
    Id: MetricsId
    Filter: MetricsFilter | None


class GetBucketMetricsConfigurationOutput(TypedDict, total=False):
    MetricsConfiguration: MetricsConfiguration | None


class GetBucketMetricsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: MetricsId
    ExpectedBucketOwner: AccountId | None


class GetBucketNotificationConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class OwnershipControlsRule(TypedDict, total=False):
    ObjectOwnership: ObjectOwnership


OwnershipControlsRules = list[OwnershipControlsRule]


class OwnershipControls(TypedDict, total=False):
    Rules: OwnershipControlsRules


class GetBucketOwnershipControlsOutput(TypedDict, total=False):
    OwnershipControls: OwnershipControls | None


class GetBucketOwnershipControlsRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketPolicyOutput(TypedDict, total=False):
    Policy: Policy | None


class GetBucketPolicyRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class PolicyStatus(TypedDict, total=False):
    IsPublic: IsPublic | None


class GetBucketPolicyStatusOutput(TypedDict, total=False):
    PolicyStatus: PolicyStatus | None


class GetBucketPolicyStatusRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class ReplicaModifications(TypedDict, total=False):
    Status: ReplicaModificationsStatus


class SseKmsEncryptedObjects(TypedDict, total=False):
    Status: SseKmsEncryptedObjectsStatus


class SourceSelectionCriteria(TypedDict, total=False):
    SseKmsEncryptedObjects: SseKmsEncryptedObjects | None
    ReplicaModifications: ReplicaModifications | None


class ReplicationRuleAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: TagSet | None


class ReplicationRuleFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: Tag | None
    And: ReplicationRuleAndOperator | None


class ReplicationRule(TypedDict, total=False):
    ID: ID | None
    Priority: Priority | None
    Prefix: Prefix | None
    Filter: ReplicationRuleFilter | None
    Status: ReplicationRuleStatus
    SourceSelectionCriteria: SourceSelectionCriteria | None
    ExistingObjectReplication: ExistingObjectReplication | None
    Destination: Destination
    DeleteMarkerReplication: DeleteMarkerReplication | None


ReplicationRules = list[ReplicationRule]


class ReplicationConfiguration(TypedDict, total=False):
    Role: Role
    Rules: ReplicationRules


class GetBucketReplicationOutput(TypedDict, total=False):
    ReplicationConfiguration: ReplicationConfiguration | None


class GetBucketReplicationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketRequestPaymentOutput(TypedDict, total=False):
    Payer: Payer | None


class GetBucketRequestPaymentRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketTaggingOutput(TypedDict, total=False):
    TagSet: TagSet


class GetBucketTaggingRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetBucketVersioningOutput(TypedDict, total=False):
    Status: BucketVersioningStatus | None
    MFADelete: MFADeleteStatus | None


class GetBucketVersioningRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class Redirect(TypedDict, total=False):
    HostName: HostName | None
    HttpRedirectCode: HttpRedirectCode | None
    Protocol: Protocol | None
    ReplaceKeyPrefixWith: ReplaceKeyPrefixWith | None
    ReplaceKeyWith: ReplaceKeyWith | None


class RoutingRule(TypedDict, total=False):
    Condition: Condition | None
    Redirect: Redirect


RoutingRules = list[RoutingRule]


class IndexDocument(TypedDict, total=False):
    Suffix: Suffix


class RedirectAllRequestsTo(TypedDict, total=False):
    HostName: HostName
    Protocol: Protocol | None


class GetBucketWebsiteOutput(TypedDict, total=False):
    RedirectAllRequestsTo: RedirectAllRequestsTo | None
    IndexDocument: IndexDocument | None
    ErrorDocument: ErrorDocument | None
    RoutingRules: RoutingRules | None


class GetBucketWebsiteRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetObjectAclOutput(TypedDict, total=False):
    Owner: Owner | None
    Grants: Grants | None
    RequestCharged: RequestCharged | None


class GetObjectAclRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None


class ObjectPart(TypedDict, total=False):
    PartNumber: PartNumber | None
    Size: Size | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None


PartsList = list[ObjectPart]


class GetObjectAttributesParts(TypedDict, total=False):
    TotalPartsCount: PartsCount | None
    PartNumberMarker: PartNumberMarker | None
    NextPartNumberMarker: NextPartNumberMarker | None
    MaxParts: MaxParts | None
    IsTruncated: IsTruncated | None
    Parts: PartsList | None


class GetObjectAttributesOutput(TypedDict, total=False):
    DeleteMarker: DeleteMarker | None
    LastModified: LastModified | None
    VersionId: ObjectVersionId | None
    RequestCharged: RequestCharged | None
    ETag: ETag | None
    Checksum: Checksum | None
    ObjectParts: GetObjectAttributesParts | None
    StorageClass: StorageClass | None
    ObjectSize: ObjectSize | None


ObjectAttributesList = list[ObjectAttributes]


class GetObjectAttributesRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    MaxParts: MaxParts | None
    PartNumberMarker: PartNumberMarker | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    ObjectAttributes: ObjectAttributesList


class ObjectLockLegalHold(TypedDict, total=False):
    Status: ObjectLockLegalHoldStatus | None


class GetObjectLegalHoldOutput(TypedDict, total=False):
    LegalHold: ObjectLockLegalHold | None


class GetObjectLegalHoldRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None


class ObjectLockRule(TypedDict, total=False):
    DefaultRetention: DefaultRetention | None


class ObjectLockConfiguration(TypedDict, total=False):
    ObjectLockEnabled: ObjectLockEnabled | None
    Rule: ObjectLockRule | None


class GetObjectLockConfigurationOutput(TypedDict, total=False):
    ObjectLockConfiguration: ObjectLockConfiguration | None


class GetObjectLockConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GetObjectOutput(TypedDict, total=False):
    Body: Body | IO[Body] | Iterable[Body] | None
    DeleteMarker: DeleteMarker | None
    AcceptRanges: AcceptRanges | None
    Expiration: Expiration | None
    Restore: Restore | None
    LastModified: LastModified | None
    ContentLength: ContentLength | None
    ETag: ETag | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None
    MissingMeta: MissingMeta | None
    VersionId: ObjectVersionId | None
    CacheControl: CacheControl | None
    ContentDisposition: ContentDisposition | None
    ContentEncoding: ContentEncoding | None
    ContentLanguage: ContentLanguage | None
    ContentRange: ContentRange | None
    ContentType: ContentType | None
    Expires: Expires | None
    WebsiteRedirectLocation: WebsiteRedirectLocation | None
    ServerSideEncryption: ServerSideEncryption | None
    Metadata: Metadata | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    BucketKeyEnabled: BucketKeyEnabled | None
    StorageClass: StorageClass | None
    RequestCharged: RequestCharged | None
    ReplicationStatus: ReplicationStatus | None
    PartsCount: PartsCount | None
    TagCount: TagCount | None
    ObjectLockMode: ObjectLockMode | None
    ObjectLockRetainUntilDate: ObjectLockRetainUntilDate | None
    ObjectLockLegalHoldStatus: ObjectLockLegalHoldStatus | None
    StatusCode: GetObjectResponseStatusCode | None


ResponseExpires = datetime
IfUnmodifiedSince = datetime
IfModifiedSince = datetime


class GetObjectRequest(ServiceRequest):
    Bucket: BucketName
    IfMatch: IfMatch | None
    IfModifiedSince: IfModifiedSince | None
    IfNoneMatch: IfNoneMatch | None
    IfUnmodifiedSince: IfUnmodifiedSince | None
    Key: ObjectKey
    Range: Range | None
    ResponseCacheControl: ResponseCacheControl | None
    ResponseContentDisposition: ResponseContentDisposition | None
    ResponseContentEncoding: ResponseContentEncoding | None
    ResponseContentLanguage: ResponseContentLanguage | None
    ResponseContentType: ResponseContentType | None
    ResponseExpires: ResponseExpires | None
    VersionId: ObjectVersionId | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    RequestPayer: RequestPayer | None
    PartNumber: PartNumber | None
    ExpectedBucketOwner: AccountId | None
    ChecksumMode: ChecksumMode | None


class ObjectLockRetention(TypedDict, total=False):
    Mode: ObjectLockRetentionMode | None
    RetainUntilDate: Date | None


class GetObjectRetentionOutput(TypedDict, total=False):
    Retention: ObjectLockRetention | None


class GetObjectRetentionRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None


class GetObjectTaggingOutput(TypedDict, total=False):
    VersionId: ObjectVersionId | None
    TagSet: TagSet


class GetObjectTaggingRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    ExpectedBucketOwner: AccountId | None
    RequestPayer: RequestPayer | None


class GetObjectTorrentOutput(TypedDict, total=False):
    Body: Body | IO[Body] | Iterable[Body] | None
    RequestCharged: RequestCharged | None


class GetObjectTorrentRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None


class PublicAccessBlockConfiguration(TypedDict, total=False):
    BlockPublicAcls: Setting | None
    IgnorePublicAcls: Setting | None
    BlockPublicPolicy: Setting | None
    RestrictPublicBuckets: Setting | None


class GetPublicAccessBlockOutput(TypedDict, total=False):
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration | None


class GetPublicAccessBlockRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class GlacierJobParameters(TypedDict, total=False):
    Tier: Tier


class HeadBucketOutput(TypedDict, total=False):
    BucketRegion: BucketRegion | None
    BucketContentType: BucketContentType | None


class HeadBucketRequest(ServiceRequest):
    Bucket: BucketName
    ExpectedBucketOwner: AccountId | None


class HeadObjectOutput(TypedDict, total=False):
    DeleteMarker: DeleteMarker | None
    AcceptRanges: AcceptRanges | None
    Expiration: Expiration | None
    Restore: Restore | None
    ArchiveStatus: ArchiveStatus | None
    LastModified: LastModified | None
    ContentLength: ContentLength | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None
    ETag: ETag | None
    MissingMeta: MissingMeta | None
    VersionId: ObjectVersionId | None
    CacheControl: CacheControl | None
    ContentDisposition: ContentDisposition | None
    ContentEncoding: ContentEncoding | None
    ContentLanguage: ContentLanguage | None
    ContentType: ContentType | None
    ContentRange: ContentRange | None
    Expires: Expires | None
    WebsiteRedirectLocation: WebsiteRedirectLocation | None
    ServerSideEncryption: ServerSideEncryption | None
    Metadata: Metadata | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    BucketKeyEnabled: BucketKeyEnabled | None
    StorageClass: StorageClass | None
    RequestCharged: RequestCharged | None
    ReplicationStatus: ReplicationStatus | None
    PartsCount: PartsCount | None
    TagCount: TagCount | None
    ObjectLockMode: ObjectLockMode | None
    ObjectLockRetainUntilDate: ObjectLockRetainUntilDate | None
    ObjectLockLegalHoldStatus: ObjectLockLegalHoldStatus | None
    StatusCode: GetObjectResponseStatusCode | None


class HeadObjectRequest(ServiceRequest):
    Bucket: BucketName
    IfMatch: IfMatch | None
    IfModifiedSince: IfModifiedSince | None
    IfNoneMatch: IfNoneMatch | None
    IfUnmodifiedSince: IfUnmodifiedSince | None
    Key: ObjectKey
    Range: Range | None
    ResponseCacheControl: ResponseCacheControl | None
    ResponseContentDisposition: ResponseContentDisposition | None
    ResponseContentEncoding: ResponseContentEncoding | None
    ResponseContentLanguage: ResponseContentLanguage | None
    ResponseContentType: ResponseContentType | None
    ResponseExpires: ResponseExpires | None
    VersionId: ObjectVersionId | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    RequestPayer: RequestPayer | None
    PartNumber: PartNumber | None
    ExpectedBucketOwner: AccountId | None
    ChecksumMode: ChecksumMode | None


Initiated = datetime


class Initiator(TypedDict, total=False):
    ID: ID | None
    DisplayName: DisplayName | None


class ParquetInput(TypedDict, total=False):
    pass


class JSONInput(TypedDict, total=False):
    Type: JSONType | None


class InputSerialization(TypedDict, total=False):
    CSV: CSVInput | None
    CompressionType: CompressionType | None
    JSON: JSONInput | None
    Parquet: ParquetInput | None


IntelligentTieringConfigurationList = list[IntelligentTieringConfiguration]
InventoryConfigurationList = list[InventoryConfiguration]


class InventoryTableConfigurationUpdates(TypedDict, total=False):
    ConfigurationState: InventoryConfigurationState
    EncryptionConfiguration: MetadataTableEncryptionConfiguration | None


class JSONOutput(TypedDict, total=False):
    RecordDelimiter: RecordDelimiter | None


class JournalTableConfigurationUpdates(TypedDict, total=False):
    RecordExpiration: RecordExpiration


class S3KeyFilter(TypedDict, total=False):
    FilterRules: FilterRuleList | None


class NotificationConfigurationFilter(TypedDict, total=False):
    Key: S3KeyFilter | None


class LambdaFunctionConfiguration(TypedDict, total=False):
    Id: NotificationId | None
    LambdaFunctionArn: LambdaFunctionArn
    Events: EventList
    Filter: NotificationConfigurationFilter | None


LambdaFunctionConfigurationList = list[LambdaFunctionConfiguration]


class LifecycleConfiguration(TypedDict, total=False):
    Rules: Rules


class ListBucketAnalyticsConfigurationsOutput(TypedDict, total=False):
    IsTruncated: IsTruncated | None
    ContinuationToken: Token | None
    NextContinuationToken: NextToken | None
    AnalyticsConfigurationList: AnalyticsConfigurationList | None


class ListBucketAnalyticsConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Token | None
    ExpectedBucketOwner: AccountId | None


class ListBucketIntelligentTieringConfigurationsOutput(TypedDict, total=False):
    IsTruncated: IsTruncated | None
    ContinuationToken: Token | None
    NextContinuationToken: NextToken | None
    IntelligentTieringConfigurationList: IntelligentTieringConfigurationList | None


class ListBucketIntelligentTieringConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Token | None
    ExpectedBucketOwner: AccountId | None


class ListBucketInventoryConfigurationsOutput(TypedDict, total=False):
    ContinuationToken: Token | None
    InventoryConfigurationList: InventoryConfigurationList | None
    IsTruncated: IsTruncated | None
    NextContinuationToken: NextToken | None


class ListBucketInventoryConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Token | None
    ExpectedBucketOwner: AccountId | None


MetricsConfigurationList = list[MetricsConfiguration]


class ListBucketMetricsConfigurationsOutput(TypedDict, total=False):
    IsTruncated: IsTruncated | None
    ContinuationToken: Token | None
    NextContinuationToken: NextToken | None
    MetricsConfigurationList: MetricsConfigurationList | None


class ListBucketMetricsConfigurationsRequest(ServiceRequest):
    Bucket: BucketName
    ContinuationToken: Token | None
    ExpectedBucketOwner: AccountId | None


class ListBucketsOutput(TypedDict, total=False):
    Owner: Owner | None
    ContinuationToken: NextToken | None
    Prefix: Prefix | None
    Buckets: Buckets | None


class ListBucketsRequest(ServiceRequest):
    MaxBuckets: MaxBuckets | None
    ContinuationToken: Token | None
    Prefix: Prefix | None
    BucketRegion: BucketRegion | None


class ListDirectoryBucketsOutput(TypedDict, total=False):
    Buckets: Buckets | None
    ContinuationToken: DirectoryBucketToken | None


class ListDirectoryBucketsRequest(ServiceRequest):
    ContinuationToken: DirectoryBucketToken | None
    MaxDirectoryBuckets: MaxDirectoryBuckets | None


class MultipartUpload(TypedDict, total=False):
    UploadId: MultipartUploadId | None
    Key: ObjectKey | None
    Initiated: Initiated | None
    StorageClass: StorageClass | None
    Owner: Owner | None
    Initiator: Initiator | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ChecksumType: ChecksumType | None


MultipartUploadList = list[MultipartUpload]


class ListMultipartUploadsOutput(TypedDict, total=False):
    Bucket: BucketName | None
    KeyMarker: KeyMarker | None
    UploadIdMarker: UploadIdMarker | None
    NextKeyMarker: NextKeyMarker | None
    Prefix: Prefix | None
    Delimiter: Delimiter | None
    NextUploadIdMarker: NextUploadIdMarker | None
    MaxUploads: MaxUploads | None
    IsTruncated: IsTruncated | None
    Uploads: MultipartUploadList | None
    CommonPrefixes: CommonPrefixList | None
    EncodingType: EncodingType | None
    RequestCharged: RequestCharged | None


class ListMultipartUploadsRequest(ServiceRequest):
    Bucket: BucketName
    Delimiter: Delimiter | None
    EncodingType: EncodingType | None
    KeyMarker: KeyMarker | None
    MaxUploads: MaxUploads | None
    Prefix: Prefix | None
    UploadIdMarker: UploadIdMarker | None
    ExpectedBucketOwner: AccountId | None
    RequestPayer: RequestPayer | None


RestoreExpiryDate = datetime


class RestoreStatus(TypedDict, total=False):
    IsRestoreInProgress: IsRestoreInProgress | None
    RestoreExpiryDate: RestoreExpiryDate | None


class ObjectVersion(TypedDict, total=False):
    ETag: ETag | None
    ChecksumAlgorithm: ChecksumAlgorithmList | None
    ChecksumType: ChecksumType | None
    Size: Size | None
    StorageClass: ObjectVersionStorageClass | None
    Key: ObjectKey | None
    VersionId: ObjectVersionId | None
    IsLatest: IsLatest | None
    LastModified: LastModified | None
    Owner: Owner | None
    RestoreStatus: RestoreStatus | None


ObjectVersionList = list[ObjectVersion]


class ListObjectVersionsOutput(TypedDict, total=False):
    IsTruncated: IsTruncated | None
    KeyMarker: KeyMarker | None
    VersionIdMarker: VersionIdMarker | None
    NextKeyMarker: NextKeyMarker | None
    NextVersionIdMarker: NextVersionIdMarker | None
    DeleteMarkers: DeleteMarkers | None
    Name: BucketName | None
    Prefix: Prefix | None
    Delimiter: Delimiter | None
    MaxKeys: MaxKeys | None
    CommonPrefixes: CommonPrefixList | None
    EncodingType: EncodingType | None
    RequestCharged: RequestCharged | None
    Versions: ObjectVersionList | None


OptionalObjectAttributesList = list[OptionalObjectAttributes]


class ListObjectVersionsRequest(ServiceRequest):
    Bucket: BucketName
    Delimiter: Delimiter | None
    EncodingType: EncodingType | None
    KeyMarker: KeyMarker | None
    MaxKeys: MaxKeys | None
    Prefix: Prefix | None
    VersionIdMarker: VersionIdMarker | None
    ExpectedBucketOwner: AccountId | None
    RequestPayer: RequestPayer | None
    OptionalObjectAttributes: OptionalObjectAttributesList | None


class Object(TypedDict, total=False):
    Key: ObjectKey | None
    LastModified: LastModified | None
    ETag: ETag | None
    ChecksumAlgorithm: ChecksumAlgorithmList | None
    ChecksumType: ChecksumType | None
    Size: Size | None
    StorageClass: ObjectStorageClass | None
    Owner: Owner | None
    RestoreStatus: RestoreStatus | None


ObjectList = list[Object]


class ListObjectsOutput(TypedDict, total=False):
    IsTruncated: IsTruncated | None
    Marker: Marker | None
    NextMarker: NextMarker | None
    Name: BucketName | None
    Prefix: Prefix | None
    Delimiter: Delimiter | None
    MaxKeys: MaxKeys | None
    CommonPrefixes: CommonPrefixList | None
    EncodingType: EncodingType | None
    RequestCharged: RequestCharged | None
    BucketRegion: BucketRegion | None
    Contents: ObjectList | None


class ListObjectsRequest(ServiceRequest):
    Bucket: BucketName
    Delimiter: Delimiter | None
    EncodingType: EncodingType | None
    Marker: Marker | None
    MaxKeys: MaxKeys | None
    Prefix: Prefix | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    OptionalObjectAttributes: OptionalObjectAttributesList | None


class ListObjectsV2Output(TypedDict, total=False):
    IsTruncated: IsTruncated | None
    Name: BucketName | None
    Prefix: Prefix | None
    Delimiter: Delimiter | None
    MaxKeys: MaxKeys | None
    CommonPrefixes: CommonPrefixList | None
    EncodingType: EncodingType | None
    KeyCount: KeyCount | None
    ContinuationToken: Token | None
    NextContinuationToken: NextToken | None
    StartAfter: StartAfter | None
    RequestCharged: RequestCharged | None
    BucketRegion: BucketRegion | None
    Contents: ObjectList | None


class ListObjectsV2Request(ServiceRequest):
    Bucket: BucketName
    Delimiter: Delimiter | None
    EncodingType: EncodingType | None
    MaxKeys: MaxKeys | None
    Prefix: Prefix | None
    ContinuationToken: Token | None
    FetchOwner: FetchOwner | None
    StartAfter: StartAfter | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    OptionalObjectAttributes: OptionalObjectAttributesList | None


class Part(TypedDict, total=False):
    PartNumber: PartNumber | None
    LastModified: LastModified | None
    ETag: ETag | None
    Size: Size | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None


Parts = list[Part]


class ListPartsOutput(TypedDict, total=False):
    AbortDate: AbortDate | None
    AbortRuleId: AbortRuleId | None
    Bucket: BucketName | None
    Key: ObjectKey | None
    UploadId: MultipartUploadId | None
    PartNumberMarker: PartNumberMarker | None
    NextPartNumberMarker: NextPartNumberMarker | None
    MaxParts: MaxParts | None
    IsTruncated: IsTruncated | None
    Parts: Parts | None
    Initiator: Initiator | None
    Owner: Owner | None
    StorageClass: StorageClass | None
    RequestCharged: RequestCharged | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ChecksumType: ChecksumType | None


class ListPartsRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    MaxParts: MaxParts | None
    PartNumberMarker: PartNumberMarker | None
    UploadId: MultipartUploadId
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None


class MetadataEntry(TypedDict, total=False):
    Name: MetadataKey | None
    Value: MetadataValue | None


class QueueConfiguration(TypedDict, total=False):
    Id: NotificationId | None
    QueueArn: QueueArn
    Events: EventList
    Filter: NotificationConfigurationFilter | None


QueueConfigurationList = list[QueueConfiguration]


class TopicConfiguration(TypedDict, total=False):
    Id: NotificationId | None
    TopicArn: TopicArn
    Events: EventList
    Filter: NotificationConfigurationFilter | None


TopicConfigurationList = list[TopicConfiguration]


class NotificationConfiguration(TypedDict, total=False):
    TopicConfigurations: TopicConfigurationList | None
    QueueConfigurations: QueueConfigurationList | None
    LambdaFunctionConfigurations: LambdaFunctionConfigurationList | None
    EventBridgeConfiguration: EventBridgeConfiguration | None


class QueueConfigurationDeprecated(TypedDict, total=False):
    Id: NotificationId | None
    Event: Event | None
    Events: EventList | None
    Queue: QueueArn | None


class TopicConfigurationDeprecated(TypedDict, total=False):
    Id: NotificationId | None
    Events: EventList | None
    Event: Event | None
    Topic: TopicArn | None


class NotificationConfigurationDeprecated(TypedDict, total=False):
    TopicConfiguration: TopicConfigurationDeprecated | None
    QueueConfiguration: QueueConfigurationDeprecated | None
    CloudFunctionConfiguration: CloudFunctionConfiguration | None


UserMetadata = list[MetadataEntry]


class Tagging(TypedDict, total=False):
    TagSet: TagSet


class S3Location(TypedDict, total=False):
    BucketName: BucketName
    Prefix: LocationPrefix
    Encryption: Encryption | None
    CannedACL: ObjectCannedACL | None
    AccessControlList: Grants | None
    Tagging: Tagging | None
    UserMetadata: UserMetadata | None
    StorageClass: StorageClass | None


class OutputLocation(TypedDict, total=False):
    S3: S3Location | None


class OutputSerialization(TypedDict, total=False):
    CSV: CSVOutput | None
    JSON: JSONOutput | None


class Progress(TypedDict, total=False):
    BytesScanned: BytesScanned | None
    BytesProcessed: BytesProcessed | None
    BytesReturned: BytesReturned | None


class ProgressEvent(TypedDict, total=False):
    Details: Progress | None


class PutBucketAbacRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None
    AbacStatus: AbacStatus


class PutBucketAccelerateConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    AccelerateConfiguration: AccelerateConfiguration
    ExpectedBucketOwner: AccountId | None
    ChecksumAlgorithm: ChecksumAlgorithm | None


class PutBucketAclRequest(ServiceRequest):
    ACL: BucketCannedACL | None
    AccessControlPolicy: AccessControlPolicy | None
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    GrantFullControl: GrantFullControl | None
    GrantRead: GrantRead | None
    GrantReadACP: GrantReadACP | None
    GrantWrite: GrantWrite | None
    GrantWriteACP: GrantWriteACP | None
    ExpectedBucketOwner: AccountId | None


class PutBucketAnalyticsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: AnalyticsId
    AnalyticsConfiguration: AnalyticsConfiguration
    ExpectedBucketOwner: AccountId | None


class PutBucketCorsRequest(ServiceRequest):
    Bucket: BucketName
    CORSConfiguration: CORSConfiguration
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None


class PutBucketEncryptionRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ServerSideEncryptionConfiguration: ServerSideEncryptionConfiguration
    ExpectedBucketOwner: AccountId | None


class PutBucketIntelligentTieringConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: IntelligentTieringId
    ExpectedBucketOwner: AccountId | None
    IntelligentTieringConfiguration: IntelligentTieringConfiguration


class PutBucketInventoryConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: InventoryId
    InventoryConfiguration: InventoryConfiguration
    ExpectedBucketOwner: AccountId | None


class PutBucketLifecycleConfigurationOutput(TypedDict, total=False):
    TransitionDefaultMinimumObjectSize: TransitionDefaultMinimumObjectSize | None


class PutBucketLifecycleConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ChecksumAlgorithm: ChecksumAlgorithm | None
    LifecycleConfiguration: BucketLifecycleConfiguration | None
    ExpectedBucketOwner: AccountId | None
    TransitionDefaultMinimumObjectSize: TransitionDefaultMinimumObjectSize | None


class PutBucketLifecycleRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    LifecycleConfiguration: LifecycleConfiguration | None
    ExpectedBucketOwner: AccountId | None


class PutBucketLoggingRequest(ServiceRequest):
    Bucket: BucketName
    BucketLoggingStatus: BucketLoggingStatus
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None


class PutBucketMetricsConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    Id: MetricsId
    MetricsConfiguration: MetricsConfiguration
    ExpectedBucketOwner: AccountId | None


class PutBucketNotificationConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    NotificationConfiguration: NotificationConfiguration
    ExpectedBucketOwner: AccountId | None
    SkipDestinationValidation: SkipValidation | None


class PutBucketNotificationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    NotificationConfiguration: NotificationConfigurationDeprecated
    ExpectedBucketOwner: AccountId | None


class PutBucketOwnershipControlsRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ExpectedBucketOwner: AccountId | None
    OwnershipControls: OwnershipControls
    ChecksumAlgorithm: ChecksumAlgorithm | None


class PutBucketPolicyRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ConfirmRemoveSelfBucketAccess: ConfirmRemoveSelfBucketAccess | None
    Policy: Policy
    ExpectedBucketOwner: AccountId | None


class PutBucketReplicationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ReplicationConfiguration: ReplicationConfiguration
    Token: ObjectLockToken | None
    ExpectedBucketOwner: AccountId | None


class RequestPaymentConfiguration(TypedDict, total=False):
    Payer: Payer


class PutBucketRequestPaymentRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    RequestPaymentConfiguration: RequestPaymentConfiguration
    ExpectedBucketOwner: AccountId | None


class PutBucketTaggingRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    Tagging: Tagging
    ExpectedBucketOwner: AccountId | None


class VersioningConfiguration(TypedDict, total=False):
    MFADelete: MFADelete | None
    Status: BucketVersioningStatus | None


class PutBucketVersioningRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    MFA: MFA | None
    VersioningConfiguration: VersioningConfiguration
    ExpectedBucketOwner: AccountId | None


class WebsiteConfiguration(TypedDict, total=False):
    ErrorDocument: ErrorDocument | None
    IndexDocument: IndexDocument | None
    RedirectAllRequestsTo: RedirectAllRequestsTo | None
    RoutingRules: RoutingRules | None


class PutBucketWebsiteRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    WebsiteConfiguration: WebsiteConfiguration
    ExpectedBucketOwner: AccountId | None


class PutObjectAclOutput(TypedDict, total=False):
    RequestCharged: RequestCharged | None


class PutObjectAclRequest(ServiceRequest):
    ACL: ObjectCannedACL | None
    AccessControlPolicy: AccessControlPolicy | None
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    GrantFullControl: GrantFullControl | None
    GrantRead: GrantRead | None
    GrantReadACP: GrantReadACP | None
    GrantWrite: GrantWrite | None
    GrantWriteACP: GrantWriteACP | None
    Key: ObjectKey
    RequestPayer: RequestPayer | None
    VersionId: ObjectVersionId | None
    ExpectedBucketOwner: AccountId | None


class PutObjectLegalHoldOutput(TypedDict, total=False):
    RequestCharged: RequestCharged | None


class PutObjectLegalHoldRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    LegalHold: ObjectLockLegalHold | None
    RequestPayer: RequestPayer | None
    VersionId: ObjectVersionId | None
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None


class PutObjectLockConfigurationOutput(TypedDict, total=False):
    RequestCharged: RequestCharged | None


class PutObjectLockConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ObjectLockConfiguration: ObjectLockConfiguration | None
    RequestPayer: RequestPayer | None
    Token: ObjectLockToken | None
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None


class PutObjectOutput(TypedDict, total=False):
    Expiration: Expiration | None
    ETag: ETag | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None
    ServerSideEncryption: ServerSideEncryption | None
    VersionId: ObjectVersionId | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    Size: Size | None
    RequestCharged: RequestCharged | None


WriteOffsetBytes = int


class PutObjectRequest(ServiceRequest):
    Body: IO[Body] | None
    ACL: ObjectCannedACL | None
    Bucket: BucketName
    CacheControl: CacheControl | None
    ContentDisposition: ContentDisposition | None
    ContentEncoding: ContentEncoding | None
    ContentLanguage: ContentLanguage | None
    ContentLength: ContentLength | None
    ContentMD5: ContentMD5 | None
    ContentType: ContentType | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    Expires: Expires | None
    IfMatch: IfMatch | None
    IfNoneMatch: IfNoneMatch | None
    GrantFullControl: GrantFullControl | None
    GrantRead: GrantRead | None
    GrantReadACP: GrantReadACP | None
    GrantWriteACP: GrantWriteACP | None
    Key: ObjectKey
    WriteOffsetBytes: WriteOffsetBytes | None
    Metadata: Metadata | None
    ServerSideEncryption: ServerSideEncryption | None
    StorageClass: StorageClass | None
    WebsiteRedirectLocation: WebsiteRedirectLocation | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestPayer: RequestPayer | None
    Tagging: TaggingHeader | None
    ObjectLockMode: ObjectLockMode | None
    ObjectLockRetainUntilDate: ObjectLockRetainUntilDate | None
    ObjectLockLegalHoldStatus: ObjectLockLegalHoldStatus | None
    ExpectedBucketOwner: AccountId | None


class PutObjectRetentionOutput(TypedDict, total=False):
    RequestCharged: RequestCharged | None


class PutObjectRetentionRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    Retention: ObjectLockRetention | None
    RequestPayer: RequestPayer | None
    VersionId: ObjectVersionId | None
    BypassGovernanceRetention: BypassGovernanceRetention | None
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None


class PutObjectTaggingOutput(TypedDict, total=False):
    VersionId: ObjectVersionId | None


class PutObjectTaggingRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    Tagging: Tagging
    ExpectedBucketOwner: AccountId | None
    RequestPayer: RequestPayer | None


class PutPublicAccessBlockRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration
    ExpectedBucketOwner: AccountId | None


class RecordsEvent(TypedDict, total=False):
    Payload: Body | None


class RenameObjectOutput(TypedDict, total=False):
    pass


RenameSourceIfUnmodifiedSince = datetime
RenameSourceIfModifiedSince = datetime


class RenameObjectRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    RenameSource: RenameSource
    DestinationIfMatch: IfMatch | None
    DestinationIfNoneMatch: IfNoneMatch | None
    DestinationIfModifiedSince: IfModifiedSince | None
    DestinationIfUnmodifiedSince: IfUnmodifiedSince | None
    SourceIfMatch: RenameSourceIfMatch | None
    SourceIfNoneMatch: RenameSourceIfNoneMatch | None
    SourceIfModifiedSince: RenameSourceIfModifiedSince | None
    SourceIfUnmodifiedSince: RenameSourceIfUnmodifiedSince | None
    ClientToken: ClientToken | None


class RequestProgress(TypedDict, total=False):
    Enabled: EnableRequestProgress | None


class RestoreObjectOutput(TypedDict, total=False):
    RequestCharged: RequestCharged | None
    RestoreOutputPath: RestoreOutputPath | None
    StatusCode: RestoreObjectOutputStatusCode | None


class SelectParameters(TypedDict, total=False):
    InputSerialization: InputSerialization
    ExpressionType: ExpressionType
    Expression: Expression
    OutputSerialization: OutputSerialization


class RestoreRequest(TypedDict, total=False):
    Days: Days | None
    GlacierJobParameters: GlacierJobParameters | None
    Type: RestoreRequestType | None
    Tier: Tier | None
    Description: Description | None
    SelectParameters: SelectParameters | None
    OutputLocation: OutputLocation | None


class RestoreObjectRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    VersionId: ObjectVersionId | None
    RestoreRequest: RestoreRequest | None
    RequestPayer: RequestPayer | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ExpectedBucketOwner: AccountId | None


Start = int


class ScanRange(TypedDict, total=False):
    Start: Start | None
    End: End | None


class Stats(TypedDict, total=False):
    BytesScanned: BytesScanned | None
    BytesProcessed: BytesProcessed | None
    BytesReturned: BytesReturned | None


class StatsEvent(TypedDict, total=False):
    Details: Stats | None


class SelectObjectContentEventStream(TypedDict, total=False):
    Records: RecordsEvent | None
    Stats: StatsEvent | None
    Progress: ProgressEvent | None
    Cont: ContinuationEvent | None
    End: EndEvent | None


class SelectObjectContentOutput(TypedDict, total=False):
    Payload: Iterator[SelectObjectContentEventStream]


class SelectObjectContentRequest(ServiceRequest):
    Bucket: BucketName
    Key: ObjectKey
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    Expression: Expression
    ExpressionType: ExpressionType
    RequestProgress: RequestProgress | None
    InputSerialization: InputSerialization
    OutputSerialization: OutputSerialization
    ScanRange: ScanRange | None
    ExpectedBucketOwner: AccountId | None


class UpdateBucketMetadataInventoryTableConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    InventoryTableConfiguration: InventoryTableConfigurationUpdates
    ExpectedBucketOwner: AccountId | None


class UpdateBucketMetadataJournalTableConfigurationRequest(ServiceRequest):
    Bucket: BucketName
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    JournalTableConfiguration: JournalTableConfigurationUpdates
    ExpectedBucketOwner: AccountId | None


class UploadPartCopyOutput(TypedDict, total=False):
    CopySourceVersionId: CopySourceVersionId | None
    CopyPartResult: CopyPartResult | None
    ServerSideEncryption: ServerSideEncryption | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestCharged: RequestCharged | None


class UploadPartCopyRequest(ServiceRequest):
    Bucket: BucketName
    CopySource: CopySource
    CopySourceIfMatch: CopySourceIfMatch | None
    CopySourceIfModifiedSince: CopySourceIfModifiedSince | None
    CopySourceIfNoneMatch: CopySourceIfNoneMatch | None
    CopySourceIfUnmodifiedSince: CopySourceIfUnmodifiedSince | None
    CopySourceRange: CopySourceRange | None
    Key: ObjectKey
    PartNumber: PartNumber
    UploadId: MultipartUploadId
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    CopySourceSSECustomerAlgorithm: CopySourceSSECustomerAlgorithm | None
    CopySourceSSECustomerKey: CopySourceSSECustomerKey | None
    CopySourceSSECustomerKeyMD5: CopySourceSSECustomerKeyMD5 | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None
    ExpectedSourceBucketOwner: AccountId | None


class UploadPartOutput(TypedDict, total=False):
    ServerSideEncryption: ServerSideEncryption | None
    ETag: ETag | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestCharged: RequestCharged | None


class UploadPartRequest(ServiceRequest):
    Body: IO[Body] | None
    Bucket: BucketName
    ContentLength: ContentLength | None
    ContentMD5: ContentMD5 | None
    ChecksumAlgorithm: ChecksumAlgorithm | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    Key: ObjectKey
    PartNumber: PartNumber
    UploadId: MultipartUploadId
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKey: SSECustomerKey | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    RequestPayer: RequestPayer | None
    ExpectedBucketOwner: AccountId | None


class WriteGetObjectResponseRequest(ServiceRequest):
    Body: IO[Body] | None
    RequestRoute: RequestRoute
    RequestToken: RequestToken
    StatusCode: GetObjectResponseStatusCode | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None
    AcceptRanges: AcceptRanges | None
    CacheControl: CacheControl | None
    ContentDisposition: ContentDisposition | None
    ContentEncoding: ContentEncoding | None
    ContentLanguage: ContentLanguage | None
    ContentLength: ContentLength | None
    ContentRange: ContentRange | None
    ContentType: ContentType | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    DeleteMarker: DeleteMarker | None
    ETag: ETag | None
    Expires: Expires | None
    Expiration: Expiration | None
    LastModified: LastModified | None
    MissingMeta: MissingMeta | None
    Metadata: Metadata | None
    ObjectLockMode: ObjectLockMode | None
    ObjectLockLegalHoldStatus: ObjectLockLegalHoldStatus | None
    ObjectLockRetainUntilDate: ObjectLockRetainUntilDate | None
    PartsCount: PartsCount | None
    ReplicationStatus: ReplicationStatus | None
    RequestCharged: RequestCharged | None
    Restore: Restore | None
    ServerSideEncryption: ServerSideEncryption | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    StorageClass: StorageClass | None
    TagCount: TagCount | None
    VersionId: ObjectVersionId | None
    BucketKeyEnabled: BucketKeyEnabled | None


class PostObjectRequest(ServiceRequest):
    Body: IO[Body] | None
    Bucket: BucketName


class PostResponse(TypedDict, total=False):
    StatusCode: GetObjectResponseStatusCode | None
    Location: Location | None
    LocationHeader: Location | None
    Bucket: BucketName | None
    Key: ObjectKey | None
    Expiration: Expiration | None
    ETag: ETag | None
    ETagHeader: ETag | None
    ChecksumCRC32: ChecksumCRC32 | None
    ChecksumCRC32C: ChecksumCRC32C | None
    ChecksumCRC64NVME: ChecksumCRC64NVME | None
    ChecksumSHA1: ChecksumSHA1 | None
    ChecksumSHA256: ChecksumSHA256 | None
    ChecksumType: ChecksumType | None
    ServerSideEncryption: ServerSideEncryption | None
    VersionId: ObjectVersionId | None
    SSECustomerAlgorithm: SSECustomerAlgorithm | None
    SSECustomerKeyMD5: SSECustomerKeyMD5 | None
    SSEKMSKeyId: SSEKMSKeyId | None
    SSEKMSEncryptionContext: SSEKMSEncryptionContext | None
    BucketKeyEnabled: BucketKeyEnabled | None
    RequestCharged: RequestCharged | None


class S3Api:
    service: str = "s3"
    version: str = "2006-03-01"

    @handler("AbortMultipartUpload")
    def abort_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        if_match_initiated_time: IfMatchInitiatedTime | None = None,
        **kwargs,
    ) -> AbortMultipartUploadOutput:
        raise NotImplementedError

    @handler("CompleteMultipartUpload")
    def complete_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        multipart_upload: CompletedMultipartUpload | None = None,
        checksum_crc32: ChecksumCRC32 | None = None,
        checksum_crc32_c: ChecksumCRC32C | None = None,
        checksum_crc64_nvme: ChecksumCRC64NVME | None = None,
        checksum_sha1: ChecksumSHA1 | None = None,
        checksum_sha256: ChecksumSHA256 | None = None,
        checksum_type: ChecksumType | None = None,
        mpu_object_size: MpuObjectSize | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        if_match: IfMatch | None = None,
        if_none_match: IfNoneMatch | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        **kwargs,
    ) -> CompleteMultipartUploadOutput:
        raise NotImplementedError

    @handler("CopyObject")
    def copy_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        copy_source: CopySource,
        key: ObjectKey,
        acl: ObjectCannedACL | None = None,
        cache_control: CacheControl | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        content_disposition: ContentDisposition | None = None,
        content_encoding: ContentEncoding | None = None,
        content_language: ContentLanguage | None = None,
        content_type: ContentType | None = None,
        copy_source_if_match: CopySourceIfMatch | None = None,
        copy_source_if_modified_since: CopySourceIfModifiedSince | None = None,
        copy_source_if_none_match: CopySourceIfNoneMatch | None = None,
        copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince | None = None,
        expires: Expires | None = None,
        grant_full_control: GrantFullControl | None = None,
        grant_read: GrantRead | None = None,
        grant_read_acp: GrantReadACP | None = None,
        grant_write_acp: GrantWriteACP | None = None,
        if_match: IfMatch | None = None,
        if_none_match: IfNoneMatch | None = None,
        metadata: Metadata | None = None,
        metadata_directive: MetadataDirective | None = None,
        tagging_directive: TaggingDirective | None = None,
        server_side_encryption: ServerSideEncryption | None = None,
        storage_class: StorageClass | None = None,
        website_redirect_location: WebsiteRedirectLocation | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        ssekms_key_id: SSEKMSKeyId | None = None,
        ssekms_encryption_context: SSEKMSEncryptionContext | None = None,
        bucket_key_enabled: BucketKeyEnabled | None = None,
        copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm | None = None,
        copy_source_sse_customer_key: CopySourceSSECustomerKey | None = None,
        copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 | None = None,
        request_payer: RequestPayer | None = None,
        tagging: TaggingHeader | None = None,
        object_lock_mode: ObjectLockMode | None = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate | None = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus | None = None,
        expected_bucket_owner: AccountId | None = None,
        expected_source_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> CopyObjectOutput:
        raise NotImplementedError

    @handler("CreateBucket")
    def create_bucket(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL | None = None,
        create_bucket_configuration: CreateBucketConfiguration | None = None,
        grant_full_control: GrantFullControl | None = None,
        grant_read: GrantRead | None = None,
        grant_read_acp: GrantReadACP | None = None,
        grant_write: GrantWrite | None = None,
        grant_write_acp: GrantWriteACP | None = None,
        object_lock_enabled_for_bucket: ObjectLockEnabledForBucket | None = None,
        object_ownership: ObjectOwnership | None = None,
        **kwargs,
    ) -> CreateBucketOutput:
        raise NotImplementedError

    @handler("CreateBucketMetadataConfiguration")
    def create_bucket_metadata_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        metadata_configuration: MetadataConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateBucketMetadataTableConfiguration")
    def create_bucket_metadata_table_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        metadata_table_configuration: MetadataTableConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateMultipartUpload")
    def create_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL | None = None,
        cache_control: CacheControl | None = None,
        content_disposition: ContentDisposition | None = None,
        content_encoding: ContentEncoding | None = None,
        content_language: ContentLanguage | None = None,
        content_type: ContentType | None = None,
        expires: Expires | None = None,
        grant_full_control: GrantFullControl | None = None,
        grant_read: GrantRead | None = None,
        grant_read_acp: GrantReadACP | None = None,
        grant_write_acp: GrantWriteACP | None = None,
        metadata: Metadata | None = None,
        server_side_encryption: ServerSideEncryption | None = None,
        storage_class: StorageClass | None = None,
        website_redirect_location: WebsiteRedirectLocation | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        ssekms_key_id: SSEKMSKeyId | None = None,
        ssekms_encryption_context: SSEKMSEncryptionContext | None = None,
        bucket_key_enabled: BucketKeyEnabled | None = None,
        request_payer: RequestPayer | None = None,
        tagging: TaggingHeader | None = None,
        object_lock_mode: ObjectLockMode | None = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate | None = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus | None = None,
        expected_bucket_owner: AccountId | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        checksum_type: ChecksumType | None = None,
        **kwargs,
    ) -> CreateMultipartUploadOutput:
        raise NotImplementedError

    @handler("CreateSession")
    def create_session(
        self,
        context: RequestContext,
        bucket: BucketName,
        session_mode: SessionMode | None = None,
        server_side_encryption: ServerSideEncryption | None = None,
        ssekms_key_id: SSEKMSKeyId | None = None,
        ssekms_encryption_context: SSEKMSEncryptionContext | None = None,
        bucket_key_enabled: BucketKeyEnabled | None = None,
        **kwargs,
    ) -> CreateSessionOutput:
        raise NotImplementedError

    @handler("DeleteBucket")
    def delete_bucket(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketAnalyticsConfiguration")
    def delete_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketCors")
    def delete_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketEncryption")
    def delete_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketIntelligentTieringConfiguration")
    def delete_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketInventoryConfiguration")
    def delete_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketLifecycle")
    def delete_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketMetadataConfiguration")
    def delete_bucket_metadata_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketMetadataTableConfiguration")
    def delete_bucket_metadata_table_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketMetricsConfiguration")
    def delete_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketOwnershipControls")
    def delete_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketPolicy")
    def delete_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketReplication")
    def delete_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketTagging")
    def delete_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketWebsite")
    def delete_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteObject")
    def delete_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        mfa: MFA | None = None,
        version_id: ObjectVersionId | None = None,
        request_payer: RequestPayer | None = None,
        bypass_governance_retention: BypassGovernanceRetention | None = None,
        expected_bucket_owner: AccountId | None = None,
        if_match: IfMatch | None = None,
        if_match_last_modified_time: IfMatchLastModifiedTime | None = None,
        if_match_size: IfMatchSize | None = None,
        **kwargs,
    ) -> DeleteObjectOutput:
        raise NotImplementedError

    @handler("DeleteObjectTagging")
    def delete_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> DeleteObjectTaggingOutput:
        raise NotImplementedError

    @handler("DeleteObjects")
    def delete_objects(
        self,
        context: RequestContext,
        bucket: BucketName,
        delete: Delete,
        mfa: MFA | None = None,
        request_payer: RequestPayer | None = None,
        bypass_governance_retention: BypassGovernanceRetention | None = None,
        expected_bucket_owner: AccountId | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        **kwargs,
    ) -> DeleteObjectsOutput:
        raise NotImplementedError

    @handler("DeletePublicAccessBlock")
    def delete_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("GetBucketAbac")
    def get_bucket_abac(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketAbacOutput:
        raise NotImplementedError

    @handler("GetBucketAccelerateConfiguration")
    def get_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        request_payer: RequestPayer | None = None,
        **kwargs,
    ) -> GetBucketAccelerateConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketAcl")
    def get_bucket_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketAclOutput:
        raise NotImplementedError

    @handler("GetBucketAnalyticsConfiguration")
    def get_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketAnalyticsConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketCors")
    def get_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketCorsOutput:
        raise NotImplementedError

    @handler("GetBucketEncryption")
    def get_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketEncryptionOutput:
        raise NotImplementedError

    @handler("GetBucketIntelligentTieringConfiguration")
    def get_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketIntelligentTieringConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketInventoryConfiguration")
    def get_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketInventoryConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketLifecycle")
    def get_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketLifecycleOutput:
        raise NotImplementedError

    @handler("GetBucketLifecycleConfiguration")
    def get_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketLifecycleConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketLocation")
    def get_bucket_location(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketLocationOutput:
        raise NotImplementedError

    @handler("GetBucketLogging")
    def get_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketLoggingOutput:
        raise NotImplementedError

    @handler("GetBucketMetadataConfiguration")
    def get_bucket_metadata_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketMetadataConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketMetadataTableConfiguration")
    def get_bucket_metadata_table_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketMetadataTableConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketMetricsConfiguration")
    def get_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketMetricsConfigurationOutput:
        raise NotImplementedError

    @handler("GetBucketNotification")
    def get_bucket_notification(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> NotificationConfigurationDeprecated:
        raise NotImplementedError

    @handler("GetBucketNotificationConfiguration")
    def get_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> NotificationConfiguration:
        raise NotImplementedError

    @handler("GetBucketOwnershipControls")
    def get_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketOwnershipControlsOutput:
        raise NotImplementedError

    @handler("GetBucketPolicy")
    def get_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketPolicyOutput:
        raise NotImplementedError

    @handler("GetBucketPolicyStatus")
    def get_bucket_policy_status(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketPolicyStatusOutput:
        raise NotImplementedError

    @handler("GetBucketReplication")
    def get_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketReplicationOutput:
        raise NotImplementedError

    @handler("GetBucketRequestPayment")
    def get_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketRequestPaymentOutput:
        raise NotImplementedError

    @handler("GetBucketTagging")
    def get_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketTaggingOutput:
        raise NotImplementedError

    @handler("GetBucketVersioning")
    def get_bucket_versioning(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketVersioningOutput:
        raise NotImplementedError

    @handler("GetBucketWebsite")
    def get_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetBucketWebsiteOutput:
        raise NotImplementedError

    @handler("GetObject")
    def get_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        if_match: IfMatch | None = None,
        if_modified_since: IfModifiedSince | None = None,
        if_none_match: IfNoneMatch | None = None,
        if_unmodified_since: IfUnmodifiedSince | None = None,
        range: Range | None = None,
        response_cache_control: ResponseCacheControl | None = None,
        response_content_disposition: ResponseContentDisposition | None = None,
        response_content_encoding: ResponseContentEncoding | None = None,
        response_content_language: ResponseContentLanguage | None = None,
        response_content_type: ResponseContentType | None = None,
        response_expires: ResponseExpires | None = None,
        version_id: ObjectVersionId | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        request_payer: RequestPayer | None = None,
        part_number: PartNumber | None = None,
        expected_bucket_owner: AccountId | None = None,
        checksum_mode: ChecksumMode | None = None,
        **kwargs,
    ) -> GetObjectOutput:
        raise NotImplementedError

    @handler("GetObjectAcl")
    def get_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetObjectAclOutput:
        raise NotImplementedError

    @handler("GetObjectAttributes")
    def get_object_attributes(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        object_attributes: ObjectAttributesList,
        version_id: ObjectVersionId | None = None,
        max_parts: MaxParts | None = None,
        part_number_marker: PartNumberMarker | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetObjectAttributesOutput:
        raise NotImplementedError

    @handler("GetObjectLegalHold")
    def get_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetObjectLegalHoldOutput:
        raise NotImplementedError

    @handler("GetObjectLockConfiguration")
    def get_object_lock_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetObjectLockConfigurationOutput:
        raise NotImplementedError

    @handler("GetObjectRetention")
    def get_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetObjectRetentionOutput:
        raise NotImplementedError

    @handler("GetObjectTagging")
    def get_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId | None = None,
        expected_bucket_owner: AccountId | None = None,
        request_payer: RequestPayer | None = None,
        **kwargs,
    ) -> GetObjectTaggingOutput:
        raise NotImplementedError

    @handler("GetObjectTorrent")
    def get_object_torrent(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetObjectTorrentOutput:
        raise NotImplementedError

    @handler("GetPublicAccessBlock")
    def get_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> GetPublicAccessBlockOutput:
        raise NotImplementedError

    @handler("HeadBucket")
    def head_bucket(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> HeadBucketOutput:
        raise NotImplementedError

    @handler("HeadObject")
    def head_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        if_match: IfMatch | None = None,
        if_modified_since: IfModifiedSince | None = None,
        if_none_match: IfNoneMatch | None = None,
        if_unmodified_since: IfUnmodifiedSince | None = None,
        range: Range | None = None,
        response_cache_control: ResponseCacheControl | None = None,
        response_content_disposition: ResponseContentDisposition | None = None,
        response_content_encoding: ResponseContentEncoding | None = None,
        response_content_language: ResponseContentLanguage | None = None,
        response_content_type: ResponseContentType | None = None,
        response_expires: ResponseExpires | None = None,
        version_id: ObjectVersionId | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        request_payer: RequestPayer | None = None,
        part_number: PartNumber | None = None,
        expected_bucket_owner: AccountId | None = None,
        checksum_mode: ChecksumMode | None = None,
        **kwargs,
    ) -> HeadObjectOutput:
        raise NotImplementedError

    @handler("ListBucketAnalyticsConfigurations")
    def list_bucket_analytics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> ListBucketAnalyticsConfigurationsOutput:
        raise NotImplementedError

    @handler("ListBucketIntelligentTieringConfigurations")
    def list_bucket_intelligent_tiering_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> ListBucketIntelligentTieringConfigurationsOutput:
        raise NotImplementedError

    @handler("ListBucketInventoryConfigurations")
    def list_bucket_inventory_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> ListBucketInventoryConfigurationsOutput:
        raise NotImplementedError

    @handler("ListBucketMetricsConfigurations")
    def list_bucket_metrics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> ListBucketMetricsConfigurationsOutput:
        raise NotImplementedError

    @handler("ListBuckets")
    def list_buckets(
        self,
        context: RequestContext,
        max_buckets: MaxBuckets | None = None,
        continuation_token: Token | None = None,
        prefix: Prefix | None = None,
        bucket_region: BucketRegion | None = None,
        **kwargs,
    ) -> ListBucketsOutput:
        raise NotImplementedError

    @handler("ListDirectoryBuckets")
    def list_directory_buckets(
        self,
        context: RequestContext,
        continuation_token: DirectoryBucketToken | None = None,
        max_directory_buckets: MaxDirectoryBuckets | None = None,
        **kwargs,
    ) -> ListDirectoryBucketsOutput:
        raise NotImplementedError

    @handler("ListMultipartUploads")
    def list_multipart_uploads(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter | None = None,
        encoding_type: EncodingType | None = None,
        key_marker: KeyMarker | None = None,
        max_uploads: MaxUploads | None = None,
        prefix: Prefix | None = None,
        upload_id_marker: UploadIdMarker | None = None,
        expected_bucket_owner: AccountId | None = None,
        request_payer: RequestPayer | None = None,
        **kwargs,
    ) -> ListMultipartUploadsOutput:
        raise NotImplementedError

    @handler("ListObjectVersions")
    def list_object_versions(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter | None = None,
        encoding_type: EncodingType | None = None,
        key_marker: KeyMarker | None = None,
        max_keys: MaxKeys | None = None,
        prefix: Prefix | None = None,
        version_id_marker: VersionIdMarker | None = None,
        expected_bucket_owner: AccountId | None = None,
        request_payer: RequestPayer | None = None,
        optional_object_attributes: OptionalObjectAttributesList | None = None,
        **kwargs,
    ) -> ListObjectVersionsOutput:
        raise NotImplementedError

    @handler("ListObjects")
    def list_objects(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter | None = None,
        encoding_type: EncodingType | None = None,
        marker: Marker | None = None,
        max_keys: MaxKeys | None = None,
        prefix: Prefix | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        optional_object_attributes: OptionalObjectAttributesList | None = None,
        **kwargs,
    ) -> ListObjectsOutput:
        raise NotImplementedError

    @handler("ListObjectsV2")
    def list_objects_v2(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter | None = None,
        encoding_type: EncodingType | None = None,
        max_keys: MaxKeys | None = None,
        prefix: Prefix | None = None,
        continuation_token: Token | None = None,
        fetch_owner: FetchOwner | None = None,
        start_after: StartAfter | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        optional_object_attributes: OptionalObjectAttributesList | None = None,
        **kwargs,
    ) -> ListObjectsV2Output:
        raise NotImplementedError

    @handler("ListParts")
    def list_parts(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        max_parts: MaxParts | None = None,
        part_number_marker: PartNumberMarker | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        **kwargs,
    ) -> ListPartsOutput:
        raise NotImplementedError

    @handler("PutBucketAbac")
    def put_bucket_abac(
        self,
        context: RequestContext,
        bucket: BucketName,
        abac_status: AbacStatus,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketAccelerateConfiguration")
    def put_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        accelerate_configuration: AccelerateConfiguration,
        expected_bucket_owner: AccountId | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketAcl")
    def put_bucket_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL | None = None,
        access_control_policy: AccessControlPolicy | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        grant_full_control: GrantFullControl | None = None,
        grant_read: GrantRead | None = None,
        grant_read_acp: GrantReadACP | None = None,
        grant_write: GrantWrite | None = None,
        grant_write_acp: GrantWriteACP | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketAnalyticsConfiguration")
    def put_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        analytics_configuration: AnalyticsConfiguration,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketCors")
    def put_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        cors_configuration: CORSConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketEncryption")
    def put_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        server_side_encryption_configuration: ServerSideEncryptionConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketIntelligentTieringConfiguration")
    def put_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        intelligent_tiering_configuration: IntelligentTieringConfiguration,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketInventoryConfiguration")
    def put_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        inventory_configuration: InventoryConfiguration,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketLifecycle")
    def put_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        lifecycle_configuration: LifecycleConfiguration | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketLifecycleConfiguration")
    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        lifecycle_configuration: BucketLifecycleConfiguration | None = None,
        expected_bucket_owner: AccountId | None = None,
        transition_default_minimum_object_size: TransitionDefaultMinimumObjectSize | None = None,
        **kwargs,
    ) -> PutBucketLifecycleConfigurationOutput:
        raise NotImplementedError

    @handler("PutBucketLogging")
    def put_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        bucket_logging_status: BucketLoggingStatus,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketMetricsConfiguration")
    def put_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        metrics_configuration: MetricsConfiguration,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketNotification")
    def put_bucket_notification(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfigurationDeprecated,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketNotificationConfiguration")
    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId | None = None,
        skip_destination_validation: SkipValidation | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketOwnershipControls")
    def put_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        ownership_controls: OwnershipControls,
        content_md5: ContentMD5 | None = None,
        expected_bucket_owner: AccountId | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketPolicy")
    def put_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        policy: Policy,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketReplication")
    def put_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        replication_configuration: ReplicationConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        token: ObjectLockToken | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketRequestPayment")
    def put_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        request_payment_configuration: RequestPaymentConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketTagging")
    def put_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        tagging: Tagging,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketVersioning")
    def put_bucket_versioning(
        self,
        context: RequestContext,
        bucket: BucketName,
        versioning_configuration: VersioningConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        mfa: MFA | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketWebsite")
    def put_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        website_configuration: WebsiteConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutObject")
    def put_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL | None = None,
        body: IO[Body] | None = None,
        cache_control: CacheControl | None = None,
        content_disposition: ContentDisposition | None = None,
        content_encoding: ContentEncoding | None = None,
        content_language: ContentLanguage | None = None,
        content_length: ContentLength | None = None,
        content_md5: ContentMD5 | None = None,
        content_type: ContentType | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        checksum_crc32: ChecksumCRC32 | None = None,
        checksum_crc32_c: ChecksumCRC32C | None = None,
        checksum_crc64_nvme: ChecksumCRC64NVME | None = None,
        checksum_sha1: ChecksumSHA1 | None = None,
        checksum_sha256: ChecksumSHA256 | None = None,
        expires: Expires | None = None,
        if_match: IfMatch | None = None,
        if_none_match: IfNoneMatch | None = None,
        grant_full_control: GrantFullControl | None = None,
        grant_read: GrantRead | None = None,
        grant_read_acp: GrantReadACP | None = None,
        grant_write_acp: GrantWriteACP | None = None,
        write_offset_bytes: WriteOffsetBytes | None = None,
        metadata: Metadata | None = None,
        server_side_encryption: ServerSideEncryption | None = None,
        storage_class: StorageClass | None = None,
        website_redirect_location: WebsiteRedirectLocation | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        ssekms_key_id: SSEKMSKeyId | None = None,
        ssekms_encryption_context: SSEKMSEncryptionContext | None = None,
        bucket_key_enabled: BucketKeyEnabled | None = None,
        request_payer: RequestPayer | None = None,
        tagging: TaggingHeader | None = None,
        object_lock_mode: ObjectLockMode | None = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate | None = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> PutObjectOutput:
        raise NotImplementedError

    @handler("PutObjectAcl")
    def put_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL | None = None,
        access_control_policy: AccessControlPolicy | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        grant_full_control: GrantFullControl | None = None,
        grant_read: GrantRead | None = None,
        grant_read_acp: GrantReadACP | None = None,
        grant_write: GrantWrite | None = None,
        grant_write_acp: GrantWriteACP | None = None,
        request_payer: RequestPayer | None = None,
        version_id: ObjectVersionId | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> PutObjectAclOutput:
        raise NotImplementedError

    @handler("PutObjectLegalHold")
    def put_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        legal_hold: ObjectLockLegalHold | None = None,
        request_payer: RequestPayer | None = None,
        version_id: ObjectVersionId | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> PutObjectLegalHoldOutput:
        raise NotImplementedError

    @handler("PutObjectLockConfiguration")
    def put_object_lock_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        object_lock_configuration: ObjectLockConfiguration | None = None,
        request_payer: RequestPayer | None = None,
        token: ObjectLockToken | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> PutObjectLockConfigurationOutput:
        raise NotImplementedError

    @handler("PutObjectRetention")
    def put_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        retention: ObjectLockRetention | None = None,
        request_payer: RequestPayer | None = None,
        version_id: ObjectVersionId | None = None,
        bypass_governance_retention: BypassGovernanceRetention | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> PutObjectRetentionOutput:
        raise NotImplementedError

    @handler("PutObjectTagging")
    def put_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        tagging: Tagging,
        version_id: ObjectVersionId | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        request_payer: RequestPayer | None = None,
        **kwargs,
    ) -> PutObjectTaggingOutput:
        raise NotImplementedError

    @handler("PutPublicAccessBlock")
    def put_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RenameObject")
    def rename_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        rename_source: RenameSource,
        destination_if_match: IfMatch | None = None,
        destination_if_none_match: IfNoneMatch | None = None,
        destination_if_modified_since: IfModifiedSince | None = None,
        destination_if_unmodified_since: IfUnmodifiedSince | None = None,
        source_if_match: RenameSourceIfMatch | None = None,
        source_if_none_match: RenameSourceIfNoneMatch | None = None,
        source_if_modified_since: RenameSourceIfModifiedSince | None = None,
        source_if_unmodified_since: RenameSourceIfUnmodifiedSince | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> RenameObjectOutput:
        raise NotImplementedError

    @handler("RestoreObject")
    def restore_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId | None = None,
        restore_request: RestoreRequest | None = None,
        request_payer: RequestPayer | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> RestoreObjectOutput:
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
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        request_progress: RequestProgress | None = None,
        scan_range: ScanRange | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> SelectObjectContentOutput:
        raise NotImplementedError

    @handler("UpdateBucketMetadataInventoryTableConfiguration")
    def update_bucket_metadata_inventory_table_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        inventory_table_configuration: InventoryTableConfigurationUpdates,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateBucketMetadataJournalTableConfiguration")
    def update_bucket_metadata_journal_table_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        journal_table_configuration: JournalTableConfigurationUpdates,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UploadPart")
    def upload_part(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        part_number: PartNumber,
        upload_id: MultipartUploadId,
        body: IO[Body] | None = None,
        content_length: ContentLength | None = None,
        content_md5: ContentMD5 | None = None,
        checksum_algorithm: ChecksumAlgorithm | None = None,
        checksum_crc32: ChecksumCRC32 | None = None,
        checksum_crc32_c: ChecksumCRC32C | None = None,
        checksum_crc64_nvme: ChecksumCRC64NVME | None = None,
        checksum_sha1: ChecksumSHA1 | None = None,
        checksum_sha256: ChecksumSHA256 | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> UploadPartOutput:
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
        copy_source_if_match: CopySourceIfMatch | None = None,
        copy_source_if_modified_since: CopySourceIfModifiedSince | None = None,
        copy_source_if_none_match: CopySourceIfNoneMatch | None = None,
        copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince | None = None,
        copy_source_range: CopySourceRange | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        sse_customer_key: SSECustomerKey | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm | None = None,
        copy_source_sse_customer_key: CopySourceSSECustomerKey | None = None,
        copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 | None = None,
        request_payer: RequestPayer | None = None,
        expected_bucket_owner: AccountId | None = None,
        expected_source_bucket_owner: AccountId | None = None,
        **kwargs,
    ) -> UploadPartCopyOutput:
        raise NotImplementedError

    @handler("WriteGetObjectResponse")
    def write_get_object_response(
        self,
        context: RequestContext,
        request_route: RequestRoute,
        request_token: RequestToken,
        body: IO[Body] | None = None,
        status_code: GetObjectResponseStatusCode | None = None,
        error_code: ErrorCode | None = None,
        error_message: ErrorMessage | None = None,
        accept_ranges: AcceptRanges | None = None,
        cache_control: CacheControl | None = None,
        content_disposition: ContentDisposition | None = None,
        content_encoding: ContentEncoding | None = None,
        content_language: ContentLanguage | None = None,
        content_length: ContentLength | None = None,
        content_range: ContentRange | None = None,
        content_type: ContentType | None = None,
        checksum_crc32: ChecksumCRC32 | None = None,
        checksum_crc32_c: ChecksumCRC32C | None = None,
        checksum_crc64_nvme: ChecksumCRC64NVME | None = None,
        checksum_sha1: ChecksumSHA1 | None = None,
        checksum_sha256: ChecksumSHA256 | None = None,
        delete_marker: DeleteMarker | None = None,
        e_tag: ETag | None = None,
        expires: Expires | None = None,
        expiration: Expiration | None = None,
        last_modified: LastModified | None = None,
        missing_meta: MissingMeta | None = None,
        metadata: Metadata | None = None,
        object_lock_mode: ObjectLockMode | None = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus | None = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate | None = None,
        parts_count: PartsCount | None = None,
        replication_status: ReplicationStatus | None = None,
        request_charged: RequestCharged | None = None,
        restore: Restore | None = None,
        server_side_encryption: ServerSideEncryption | None = None,
        sse_customer_algorithm: SSECustomerAlgorithm | None = None,
        ssekms_key_id: SSEKMSKeyId | None = None,
        sse_customer_key_md5: SSECustomerKeyMD5 | None = None,
        storage_class: StorageClass | None = None,
        tag_count: TagCount | None = None,
        version_id: ObjectVersionId | None = None,
        bucket_key_enabled: BucketKeyEnabled | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PostObject")
    def post_object(
        self, context: RequestContext, bucket: BucketName, body: IO[Body] | None = None, **kwargs
    ) -> PostResponse:
        raise NotImplementedError
