from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessGrantArn = str
AccessGrantId = str
AccessGrantsInstanceArn = str
AccessGrantsInstanceId = str
AccessGrantsLocationArn = str
AccessGrantsLocationId = str
AccessKeyId = str
AccessPointBucketName = str
AccessPointName = str
AccountId = str
Alias = str
AsyncRequestStatus = str
AsyncRequestTokenARN = str
AwsLambdaTransformationPayload = str
AwsOrgArn = str
Boolean = bool
BucketIdentifierString = str
BucketName = str
ConfigId = str
ConfirmRemoveSelfBucketAccess = bool
ConfirmationRequired = bool
ContinuationToken = str
DataSourceId = str
DataSourceType = str
Days = int
DaysAfterInitiation = int
DurationSeconds = int
ExceptionMessage = str
ExpiredObjectDeleteMarker = bool
FunctionArnString = str
GrantFullControl = str
GrantRead = str
GrantReadACP = str
GrantWrite = str
GrantWriteACP = str
GranteeIdentifier = str
IAMRoleArn = str
ID = str
IdentityCenterApplicationArn = str
IdentityCenterArn = str
IsEnabled = bool
IsPublic = bool
JobArn = str
JobFailureCode = str
JobFailureReason = str
JobId = str
JobPriority = int
JobStatusUpdateReason = str
KmsKeyArnString = str
Location = str
MFA = str
ManifestPrefixString = str
MaxLength1024String = str
MaxResults = int
MinStorageBytesPercentage = float
Minutes = int
MultiRegionAccessPointAlias = str
MultiRegionAccessPointClientToken = str
MultiRegionAccessPointId = str
MultiRegionAccessPointName = str
NoSuchPublicAccessBlockConfigurationMessage = str
NonEmptyKmsKeyArnString = str
NonEmptyMaxLength1024String = str
NonEmptyMaxLength2048String = str
NonEmptyMaxLength256String = str
NonEmptyMaxLength64String = str
NoncurrentVersionCount = int
ObjectAgeValue = int
ObjectLambdaAccessPointAliasValue = str
ObjectLambdaAccessPointArn = str
ObjectLambdaAccessPointName = str
ObjectLambdaPolicy = str
ObjectLambdaSupportingAccessPointArn = str
ObjectLockEnabledForBucket = bool
Organization = str
Policy = str
PolicyDocument = str
Prefix = str
Priority = int
PublicAccessBlockEnabled = bool
RegionName = str
ReplicaKmsKeyID = str
ReportPrefixString = str
Role = str
S3AWSRegion = str
S3AccessPointArn = str
S3BucketArnString = str
S3ExpirationInDays = int
S3KeyArnString = str
S3ObjectVersionId = str
S3Prefix = str
S3RegionalBucketArn = str
S3RegionalOrS3ExpressBucketArnString = str
S3ResourceArn = str
SSEKMSKeyId = str
SecretAccessKey = str
SessionToken = str
Setting = bool
StorageLensArn = str
StorageLensGroupArn = str
StorageLensGroupName = str
StorageLensPrefixLevelDelimiter = str
StorageLensPrefixLevelMaxDepth = int
StringForNextToken = str
Suffix = str
SuspendedCause = str
TagKeyString = str
TagValueString = str
TrafficDialPercentage = int
VpcId = str


class AsyncOperationName(StrEnum):
    CreateMultiRegionAccessPoint = "CreateMultiRegionAccessPoint"
    DeleteMultiRegionAccessPoint = "DeleteMultiRegionAccessPoint"
    PutMultiRegionAccessPointPolicy = "PutMultiRegionAccessPointPolicy"


class BucketCannedACL(StrEnum):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    authenticated_read = "authenticated-read"


class BucketLocationConstraint(StrEnum):
    EU = "EU"
    eu_west_1 = "eu-west-1"
    us_west_1 = "us-west-1"
    us_west_2 = "us-west-2"
    ap_south_1 = "ap-south-1"
    ap_southeast_1 = "ap-southeast-1"
    ap_southeast_2 = "ap-southeast-2"
    ap_northeast_1 = "ap-northeast-1"
    sa_east_1 = "sa-east-1"
    cn_north_1 = "cn-north-1"
    eu_central_1 = "eu-central-1"


class BucketVersioningStatus(StrEnum):
    Enabled = "Enabled"
    Suspended = "Suspended"


class ComputeObjectChecksumAlgorithm(StrEnum):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    CRC64NVME = "CRC64NVME"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"


class ComputeObjectChecksumType(StrEnum):
    FULL_OBJECT = "FULL_OBJECT"
    COMPOSITE = "COMPOSITE"


class DeleteMarkerReplicationStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExistingObjectReplicationStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExpirationStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class Format(StrEnum):
    CSV = "CSV"
    Parquet = "Parquet"


class GeneratedManifestFormat(StrEnum):
    S3InventoryReport_CSV_20211130 = "S3InventoryReport_CSV_20211130"


class GranteeType(StrEnum):
    DIRECTORY_USER = "DIRECTORY_USER"
    DIRECTORY_GROUP = "DIRECTORY_GROUP"
    IAM = "IAM"


class JobManifestFieldName(StrEnum):
    Ignore = "Ignore"
    Bucket = "Bucket"
    Key = "Key"
    VersionId = "VersionId"


class JobManifestFormat(StrEnum):
    S3BatchOperations_CSV_20180820 = "S3BatchOperations_CSV_20180820"
    S3InventoryReport_CSV_20161130 = "S3InventoryReport_CSV_20161130"


class JobReportFormat(StrEnum):
    Report_CSV_20180820 = "Report_CSV_20180820"


class JobReportScope(StrEnum):
    AllTasks = "AllTasks"
    FailedTasksOnly = "FailedTasksOnly"


class JobStatus(StrEnum):
    Active = "Active"
    Cancelled = "Cancelled"
    Cancelling = "Cancelling"
    Complete = "Complete"
    Completing = "Completing"
    Failed = "Failed"
    Failing = "Failing"
    New = "New"
    Paused = "Paused"
    Pausing = "Pausing"
    Preparing = "Preparing"
    Ready = "Ready"
    Suspended = "Suspended"


class MFADelete(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MFADeleteStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MetricsStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MultiRegionAccessPointStatus(StrEnum):
    READY = "READY"
    INCONSISTENT_ACROSS_REGIONS = "INCONSISTENT_ACROSS_REGIONS"
    CREATING = "CREATING"
    PARTIALLY_CREATED = "PARTIALLY_CREATED"
    PARTIALLY_DELETED = "PARTIALLY_DELETED"
    DELETING = "DELETING"


class NetworkOrigin(StrEnum):
    Internet = "Internet"
    VPC = "VPC"


class ObjectLambdaAccessPointAliasStatus(StrEnum):
    PROVISIONING = "PROVISIONING"
    READY = "READY"


class ObjectLambdaAllowedFeature(StrEnum):
    GetObject_Range = "GetObject-Range"
    GetObject_PartNumber = "GetObject-PartNumber"
    HeadObject_Range = "HeadObject-Range"
    HeadObject_PartNumber = "HeadObject-PartNumber"


class ObjectLambdaTransformationConfigurationAction(StrEnum):
    GetObject = "GetObject"
    HeadObject = "HeadObject"
    ListObjects = "ListObjects"
    ListObjectsV2 = "ListObjectsV2"


class OperationName(StrEnum):
    LambdaInvoke = "LambdaInvoke"
    S3PutObjectCopy = "S3PutObjectCopy"
    S3PutObjectAcl = "S3PutObjectAcl"
    S3PutObjectTagging = "S3PutObjectTagging"
    S3DeleteObjectTagging = "S3DeleteObjectTagging"
    S3InitiateRestoreObject = "S3InitiateRestoreObject"
    S3PutObjectLegalHold = "S3PutObjectLegalHold"
    S3PutObjectRetention = "S3PutObjectRetention"
    S3ReplicateObject = "S3ReplicateObject"
    S3ComputeObjectChecksum = "S3ComputeObjectChecksum"


class OutputSchemaVersion(StrEnum):
    V_1 = "V_1"


class OwnerOverride(StrEnum):
    Destination = "Destination"


class Permission(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    READWRITE = "READWRITE"


class Privilege(StrEnum):
    Minimal = "Minimal"
    Default = "Default"


class ReplicaModificationsStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReplicationRuleStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ReplicationStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REPLICA = "REPLICA"
    NONE = "NONE"


class ReplicationStorageClass(StrEnum):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"


class ReplicationTimeStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class RequestedJobStatus(StrEnum):
    Cancelled = "Cancelled"
    Ready = "Ready"


class S3CannedAccessControlList(StrEnum):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    aws_exec_read = "aws-exec-read"
    authenticated_read = "authenticated-read"
    bucket_owner_read = "bucket-owner-read"
    bucket_owner_full_control = "bucket-owner-full-control"


class S3ChecksumAlgorithm(StrEnum):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    CRC64NVME = "CRC64NVME"


class S3GlacierJobTier(StrEnum):
    BULK = "BULK"
    STANDARD = "STANDARD"


class S3GranteeTypeIdentifier(StrEnum):
    id = "id"
    emailAddress = "emailAddress"
    uri = "uri"


class S3MetadataDirective(StrEnum):
    COPY = "COPY"
    REPLACE = "REPLACE"


class S3ObjectLockLegalHoldStatus(StrEnum):
    OFF = "OFF"
    ON = "ON"


class S3ObjectLockMode(StrEnum):
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"


class S3ObjectLockRetentionMode(StrEnum):
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"


class S3Permission(StrEnum):
    FULL_CONTROL = "FULL_CONTROL"
    READ = "READ"
    WRITE = "WRITE"
    READ_ACP = "READ_ACP"
    WRITE_ACP = "WRITE_ACP"


class S3PrefixType(StrEnum):
    Object = "Object"


class S3SSEAlgorithm(StrEnum):
    AES256 = "AES256"
    KMS = "KMS"


class S3StorageClass(StrEnum):
    STANDARD = "STANDARD"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    GLACIER = "GLACIER"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    GLACIER_IR = "GLACIER_IR"


class ScopePermission(StrEnum):
    GetObject = "GetObject"
    GetObjectAttributes = "GetObjectAttributes"
    ListMultipartUploadParts = "ListMultipartUploadParts"
    ListBucket = "ListBucket"
    ListBucketMultipartUploads = "ListBucketMultipartUploads"
    PutObject = "PutObject"
    DeleteObject = "DeleteObject"
    AbortMultipartUpload = "AbortMultipartUpload"


class SseKmsEncryptedObjectsStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class TransitionStorageClass(StrEnum):
    GLACIER = "GLACIER"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"


class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400


class BucketAlreadyExists(ServiceException):
    code: str = "BucketAlreadyExists"
    sender_fault: bool = False
    status_code: int = 400


class BucketAlreadyOwnedByYou(ServiceException):
    code: str = "BucketAlreadyOwnedByYou"
    sender_fault: bool = False
    status_code: int = 400


class IdempotencyException(ServiceException):
    code: str = "IdempotencyException"
    sender_fault: bool = False
    status_code: int = 400


class InternalServiceException(ServiceException):
    code: str = "InternalServiceException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextTokenException(ServiceException):
    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestException(ServiceException):
    code: str = "InvalidRequestException"
    sender_fault: bool = False
    status_code: int = 400


class JobStatusException(ServiceException):
    code: str = "JobStatusException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchPublicAccessBlockConfiguration(ServiceException):
    code: str = "NoSuchPublicAccessBlockConfiguration"
    sender_fault: bool = False
    status_code: int = 404


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsException(ServiceException):
    code: str = "TooManyTagsException"
    sender_fault: bool = False
    status_code: int = 400


class AbortIncompleteMultipartUpload(TypedDict, total=False):
    DaysAfterInitiation: DaysAfterInitiation | None


class AccessControlTranslation(TypedDict, total=False):
    Owner: OwnerOverride


CreationTimestamp = datetime


class ListAccessGrantsInstanceEntry(TypedDict, total=False):
    AccessGrantsInstanceId: AccessGrantsInstanceId | None
    AccessGrantsInstanceArn: AccessGrantsInstanceArn | None
    CreatedAt: CreationTimestamp | None
    IdentityCenterArn: IdentityCenterArn | None
    IdentityCenterInstanceArn: IdentityCenterArn | None
    IdentityCenterApplicationArn: IdentityCenterApplicationArn | None


AccessGrantsInstancesList = list[ListAccessGrantsInstanceEntry]


class AccessGrantsLocationConfiguration(TypedDict, total=False):
    S3SubPrefix: S3Prefix | None


class Grantee(TypedDict, total=False):
    GranteeType: GranteeType | None
    GranteeIdentifier: GranteeIdentifier | None


class ListAccessGrantEntry(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantId: AccessGrantId | None
    AccessGrantArn: AccessGrantArn | None
    Grantee: Grantee | None
    Permission: Permission | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationConfiguration: AccessGrantsLocationConfiguration | None
    GrantScope: S3Prefix | None
    ApplicationArn: IdentityCenterApplicationArn | None


AccessGrantsList = list[ListAccessGrantEntry]


class ListAccessGrantsLocationsEntry(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationArn: AccessGrantsLocationArn | None
    LocationScope: S3Prefix | None
    IAMRoleArn: IAMRoleArn | None


AccessGrantsLocationsList = list[ListAccessGrantsLocationsEntry]


class VpcConfiguration(TypedDict, total=False):
    VpcId: VpcId


class AccessPoint(TypedDict, total=False):
    Name: AccessPointName
    NetworkOrigin: NetworkOrigin
    VpcConfiguration: VpcConfiguration | None
    Bucket: AccessPointBucketName
    AccessPointArn: S3AccessPointArn | None
    Alias: Alias | None
    BucketAccountId: AccountId | None
    DataSourceId: DataSourceId | None
    DataSourceType: DataSourceType | None


AccessPointList = list[AccessPoint]
StorageLensGroupLevelExclude = list[StorageLensGroupArn]
StorageLensGroupLevelInclude = list[StorageLensGroupArn]


class StorageLensGroupLevelSelectionCriteria(TypedDict, total=False):
    Include: StorageLensGroupLevelInclude | None
    Exclude: StorageLensGroupLevelExclude | None


class StorageLensGroupLevel(TypedDict, total=False):
    SelectionCriteria: StorageLensGroupLevelSelectionCriteria | None


class AdvancedPerformanceMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled | None


class DetailedStatusCodesMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled | None


class AdvancedDataProtectionMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled | None


class AdvancedCostOptimizationMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled | None


class SelectionCriteria(TypedDict, total=False):
    Delimiter: StorageLensPrefixLevelDelimiter | None
    MaxDepth: StorageLensPrefixLevelMaxDepth | None
    MinStorageBytesPercentage: MinStorageBytesPercentage | None


class PrefixLevelStorageMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled | None
    SelectionCriteria: SelectionCriteria | None


class PrefixLevel(TypedDict, total=False):
    StorageMetrics: PrefixLevelStorageMetrics


class ActivityMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled | None


class BucketLevel(TypedDict, total=False):
    ActivityMetrics: ActivityMetrics | None
    PrefixLevel: PrefixLevel | None
    AdvancedCostOptimizationMetrics: AdvancedCostOptimizationMetrics | None
    AdvancedDataProtectionMetrics: AdvancedDataProtectionMetrics | None
    DetailedStatusCodesMetrics: DetailedStatusCodesMetrics | None
    AdvancedPerformanceMetrics: AdvancedPerformanceMetrics | None


class AccountLevel(TypedDict, total=False):
    ActivityMetrics: ActivityMetrics | None
    BucketLevel: BucketLevel
    AdvancedCostOptimizationMetrics: AdvancedCostOptimizationMetrics | None
    AdvancedDataProtectionMetrics: AdvancedDataProtectionMetrics | None
    DetailedStatusCodesMetrics: DetailedStatusCodesMetrics | None
    AdvancedPerformanceMetrics: AdvancedPerformanceMetrics | None
    StorageLensGroupLevel: StorageLensGroupLevel | None


class AssociateAccessGrantsIdentityCenterRequest(ServiceRequest):
    AccountId: AccountId
    IdentityCenterArn: IdentityCenterArn


AsyncCreationTimestamp = datetime


class AsyncErrorDetails(TypedDict, total=False):
    Code: MaxLength1024String | None
    Message: MaxLength1024String | None
    Resource: MaxLength1024String | None
    RequestId: MaxLength1024String | None


class MultiRegionAccessPointRegionalResponse(TypedDict, total=False):
    Name: RegionName | None
    RequestStatus: AsyncRequestStatus | None


MultiRegionAccessPointRegionalResponseList = list[MultiRegionAccessPointRegionalResponse]


class MultiRegionAccessPointsAsyncResponse(TypedDict, total=False):
    Regions: MultiRegionAccessPointRegionalResponseList | None


class AsyncResponseDetails(TypedDict, total=False):
    MultiRegionAccessPointDetails: MultiRegionAccessPointsAsyncResponse | None
    ErrorDetails: AsyncErrorDetails | None


class PutMultiRegionAccessPointPolicyInput(TypedDict, total=False):
    Name: MultiRegionAccessPointName
    Policy: Policy


class DeleteMultiRegionAccessPointInput(TypedDict, total=False):
    Name: MultiRegionAccessPointName


class Region(TypedDict, total=False):
    Bucket: BucketName
    BucketAccountId: AccountId | None


RegionCreationList = list[Region]


class PublicAccessBlockConfiguration(TypedDict, total=False):
    BlockPublicAcls: Setting | None
    IgnorePublicAcls: Setting | None
    BlockPublicPolicy: Setting | None
    RestrictPublicBuckets: Setting | None


class CreateMultiRegionAccessPointInput(TypedDict, total=False):
    Name: MultiRegionAccessPointName
    PublicAccessBlock: PublicAccessBlockConfiguration | None
    Regions: RegionCreationList


class AsyncRequestParameters(TypedDict, total=False):
    CreateMultiRegionAccessPointRequest: CreateMultiRegionAccessPointInput | None
    DeleteMultiRegionAccessPointRequest: DeleteMultiRegionAccessPointInput | None
    PutMultiRegionAccessPointPolicyRequest: PutMultiRegionAccessPointPolicyInput | None


class AsyncOperation(TypedDict, total=False):
    CreationTime: AsyncCreationTimestamp | None
    Operation: AsyncOperationName | None
    RequestTokenARN: AsyncRequestTokenARN | None
    RequestParameters: AsyncRequestParameters | None
    RequestStatus: AsyncRequestStatus | None
    ResponseDetails: AsyncResponseDetails | None


class AwsLambdaTransformation(TypedDict, total=False):
    FunctionArn: FunctionArnString
    FunctionPayload: AwsLambdaTransformationPayload | None


Buckets = list[S3BucketArnString]


class ListCallerAccessGrantsEntry(TypedDict, total=False):
    Permission: Permission | None
    GrantScope: S3Prefix | None
    ApplicationArn: IdentityCenterApplicationArn | None


CallerAccessGrantsList = list[ListCallerAccessGrantsEntry]


class CloudWatchMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled


class Tag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


TagList = list[Tag]


class CreateAccessGrantRequest(ServiceRequest):
    AccountId: AccountId
    AccessGrantsLocationId: AccessGrantsLocationId
    AccessGrantsLocationConfiguration: AccessGrantsLocationConfiguration | None
    Grantee: Grantee
    Permission: Permission
    ApplicationArn: IdentityCenterApplicationArn | None
    S3PrefixType: S3PrefixType | None
    Tags: TagList | None


class CreateAccessGrantResult(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantId: AccessGrantId | None
    AccessGrantArn: AccessGrantArn | None
    Grantee: Grantee | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationConfiguration: AccessGrantsLocationConfiguration | None
    Permission: Permission | None
    ApplicationArn: IdentityCenterApplicationArn | None
    GrantScope: S3Prefix | None


class CreateAccessGrantsInstanceRequest(ServiceRequest):
    AccountId: AccountId
    IdentityCenterArn: IdentityCenterArn | None
    Tags: TagList | None


class CreateAccessGrantsInstanceResult(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantsInstanceId: AccessGrantsInstanceId | None
    AccessGrantsInstanceArn: AccessGrantsInstanceArn | None
    IdentityCenterArn: IdentityCenterArn | None
    IdentityCenterInstanceArn: IdentityCenterArn | None
    IdentityCenterApplicationArn: IdentityCenterApplicationArn | None


class CreateAccessGrantsLocationRequest(ServiceRequest):
    AccountId: AccountId
    LocationScope: S3Prefix
    IAMRoleArn: IAMRoleArn
    Tags: TagList | None


class CreateAccessGrantsLocationResult(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationArn: AccessGrantsLocationArn | None
    LocationScope: S3Prefix | None
    IAMRoleArn: IAMRoleArn | None


class ObjectLambdaContentTransformation(TypedDict, total=False):
    AwsLambda: AwsLambdaTransformation | None


ObjectLambdaTransformationConfigurationActionsList = list[
    ObjectLambdaTransformationConfigurationAction
]


class ObjectLambdaTransformationConfiguration(TypedDict, total=False):
    Actions: ObjectLambdaTransformationConfigurationActionsList
    ContentTransformation: ObjectLambdaContentTransformation


ObjectLambdaTransformationConfigurationsList = list[ObjectLambdaTransformationConfiguration]
ObjectLambdaAllowedFeaturesList = list[ObjectLambdaAllowedFeature]


class ObjectLambdaConfiguration(TypedDict, total=False):
    SupportingAccessPoint: ObjectLambdaSupportingAccessPointArn
    CloudWatchMetricsEnabled: Boolean | None
    AllowedFeatures: ObjectLambdaAllowedFeaturesList | None
    TransformationConfigurations: ObjectLambdaTransformationConfigurationsList


class CreateAccessPointForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName
    Configuration: ObjectLambdaConfiguration


class ObjectLambdaAccessPointAlias(TypedDict, total=False):
    Value: ObjectLambdaAccessPointAliasValue | None
    Status: ObjectLambdaAccessPointAliasStatus | None


class CreateAccessPointForObjectLambdaResult(TypedDict, total=False):
    ObjectLambdaAccessPointArn: ObjectLambdaAccessPointArn | None
    Alias: ObjectLambdaAccessPointAlias | None


ScopePermissionList = list[ScopePermission]
PrefixesList = list[Prefix]


class Scope(TypedDict, total=False):
    Prefixes: PrefixesList | None
    Permissions: ScopePermissionList | None


class CreateAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName
    Bucket: BucketName
    VpcConfiguration: VpcConfiguration | None
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration | None
    BucketAccountId: AccountId | None
    Scope: Scope | None
    Tags: TagList | None


class CreateAccessPointResult(TypedDict, total=False):
    AccessPointArn: S3AccessPointArn | None
    Alias: Alias | None


class CreateBucketConfiguration(TypedDict, total=False):
    LocationConstraint: BucketLocationConstraint | None


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
    OutpostId: NonEmptyMaxLength64String | None


class CreateBucketResult(TypedDict, total=False):
    Location: Location | None
    BucketArn: S3RegionalBucketArn | None


class NotSSEFilter(TypedDict, total=False):
    pass


class SSECFilter(TypedDict, total=False):
    pass


class DSSEKMSFilter(TypedDict, total=False):
    KmsKeyArn: NonEmptyKmsKeyArnString | None


class SSEKMSFilter(TypedDict, total=False):
    KmsKeyArn: NonEmptyKmsKeyArnString | None
    BucketKeyEnabled: Boolean | None


class SSES3Filter(TypedDict, total=False):
    pass


class ObjectEncryptionFilter(TypedDict, total=False):
    SSES3: SSES3Filter | None
    SSEKMS: SSEKMSFilter | None
    DSSEKMS: DSSEKMSFilter | None
    SSEC: SSECFilter | None
    NOTSSE: NotSSEFilter | None


ObjectEncryptionFilterList = list[ObjectEncryptionFilter]
StorageClassList = list[S3StorageClass]
ObjectSizeLessThanBytes = int
ObjectSizeGreaterThanBytes = int
NonEmptyMaxLength1024StringList = list[NonEmptyMaxLength1024String]


class KeyNameConstraint(TypedDict, total=False):
    MatchAnyPrefix: NonEmptyMaxLength1024StringList | None
    MatchAnySuffix: NonEmptyMaxLength1024StringList | None
    MatchAnySubstring: NonEmptyMaxLength1024StringList | None


ReplicationStatusFilterList = list[ReplicationStatus]
ObjectCreationTime = datetime


class JobManifestGeneratorFilter(TypedDict, total=False):
    EligibleForReplication: Boolean | None
    CreatedAfter: ObjectCreationTime | None
    CreatedBefore: ObjectCreationTime | None
    ObjectReplicationStatuses: ReplicationStatusFilterList | None
    KeyNameConstraint: KeyNameConstraint | None
    ObjectSizeGreaterThanBytes: ObjectSizeGreaterThanBytes | None
    ObjectSizeLessThanBytes: ObjectSizeLessThanBytes | None
    MatchAnyStorageClass: StorageClassList | None
    MatchAnyObjectEncryption: ObjectEncryptionFilterList | None


class SSEKMSEncryption(TypedDict, total=False):
    KeyId: KmsKeyArnString


class SSES3Encryption(TypedDict, total=False):
    pass


class GeneratedManifestEncryption(TypedDict, total=False):
    SSES3: SSES3Encryption | None
    SSEKMS: SSEKMSEncryption | None


class S3ManifestOutputLocation(TypedDict, total=False):
    ExpectedManifestBucketOwner: AccountId | None
    Bucket: S3BucketArnString
    ManifestPrefix: ManifestPrefixString | None
    ManifestEncryption: GeneratedManifestEncryption | None
    ManifestFormat: GeneratedManifestFormat


class S3JobManifestGenerator(TypedDict, total=False):
    ExpectedBucketOwner: AccountId | None
    SourceBucket: S3BucketArnString
    ManifestOutputLocation: S3ManifestOutputLocation | None
    Filter: JobManifestGeneratorFilter | None
    EnableManifestOutput: Boolean


class JobManifestGenerator(TypedDict, total=False):
    S3JobManifestGenerator: S3JobManifestGenerator | None


class S3Tag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


S3TagSet = list[S3Tag]


class JobManifestLocation(TypedDict, total=False):
    ObjectArn: S3KeyArnString
    ObjectVersionId: S3ObjectVersionId | None
    ETag: NonEmptyMaxLength1024String


JobManifestFieldList = list[JobManifestFieldName]


class JobManifestSpec(TypedDict, total=False):
    Format: JobManifestFormat
    Fields: JobManifestFieldList | None


class JobManifest(TypedDict, total=False):
    Spec: JobManifestSpec
    Location: JobManifestLocation


class JobReport(TypedDict, total=False):
    Bucket: S3BucketArnString | None
    Format: JobReportFormat | None
    Enabled: Boolean
    Prefix: ReportPrefixString | None
    ReportScope: JobReportScope | None
    ExpectedBucketOwner: AccountId | None


class S3ComputeObjectChecksumOperation(TypedDict, total=False):
    ChecksumAlgorithm: ComputeObjectChecksumAlgorithm | None
    ChecksumType: ComputeObjectChecksumType | None


class S3ReplicateObjectOperation(TypedDict, total=False):
    pass


TimeStamp = datetime


class S3Retention(TypedDict, total=False):
    RetainUntilDate: TimeStamp | None
    Mode: S3ObjectLockRetentionMode | None


class S3SetObjectRetentionOperation(TypedDict, total=False):
    BypassGovernanceRetention: Boolean | None
    Retention: S3Retention


class S3ObjectLockLegalHold(TypedDict, total=False):
    Status: S3ObjectLockLegalHoldStatus


class S3SetObjectLegalHoldOperation(TypedDict, total=False):
    LegalHold: S3ObjectLockLegalHold


class S3InitiateRestoreObjectOperation(TypedDict, total=False):
    ExpirationInDays: S3ExpirationInDays | None
    GlacierJobTier: S3GlacierJobTier | None


class S3DeleteObjectTaggingOperation(TypedDict, total=False):
    pass


class S3SetObjectTaggingOperation(TypedDict, total=False):
    TagSet: S3TagSet | None


class S3Grantee(TypedDict, total=False):
    TypeIdentifier: S3GranteeTypeIdentifier | None
    Identifier: NonEmptyMaxLength1024String | None
    DisplayName: NonEmptyMaxLength1024String | None


class S3Grant(TypedDict, total=False):
    Grantee: S3Grantee | None
    Permission: S3Permission | None


S3GrantList = list[S3Grant]


class S3ObjectOwner(TypedDict, total=False):
    ID: NonEmptyMaxLength1024String | None
    DisplayName: NonEmptyMaxLength1024String | None


class S3AccessControlList(TypedDict, total=False):
    Owner: S3ObjectOwner
    Grants: S3GrantList | None


class S3AccessControlPolicy(TypedDict, total=False):
    AccessControlList: S3AccessControlList | None
    CannedAccessControlList: S3CannedAccessControlList | None


class S3SetObjectAclOperation(TypedDict, total=False):
    AccessControlPolicy: S3AccessControlPolicy | None


S3ContentLength = int
S3UserMetadata = dict[NonEmptyMaxLength1024String, MaxLength1024String]


class S3ObjectMetadata(TypedDict, total=False):
    CacheControl: NonEmptyMaxLength1024String | None
    ContentDisposition: NonEmptyMaxLength1024String | None
    ContentEncoding: NonEmptyMaxLength1024String | None
    ContentLanguage: NonEmptyMaxLength1024String | None
    UserMetadata: S3UserMetadata | None
    ContentLength: S3ContentLength | None
    ContentMD5: NonEmptyMaxLength1024String | None
    ContentType: NonEmptyMaxLength1024String | None
    HttpExpiresDate: TimeStamp | None
    RequesterCharged: Boolean | None
    SSEAlgorithm: S3SSEAlgorithm | None


class S3CopyObjectOperation(TypedDict, total=False):
    TargetResource: S3RegionalOrS3ExpressBucketArnString | None
    CannedAccessControlList: S3CannedAccessControlList | None
    AccessControlGrants: S3GrantList | None
    MetadataDirective: S3MetadataDirective | None
    ModifiedSinceConstraint: TimeStamp | None
    NewObjectMetadata: S3ObjectMetadata | None
    NewObjectTagging: S3TagSet | None
    RedirectLocation: NonEmptyMaxLength2048String | None
    RequesterPays: Boolean | None
    StorageClass: S3StorageClass | None
    UnModifiedSinceConstraint: TimeStamp | None
    SSEAwsKmsKeyId: KmsKeyArnString | None
    TargetKeyPrefix: NonEmptyMaxLength1024String | None
    ObjectLockLegalHoldStatus: S3ObjectLockLegalHoldStatus | None
    ObjectLockMode: S3ObjectLockMode | None
    ObjectLockRetainUntilDate: TimeStamp | None
    BucketKeyEnabled: Boolean | None
    ChecksumAlgorithm: S3ChecksumAlgorithm | None


UserArguments = dict[NonEmptyMaxLength64String, MaxLength1024String]


class LambdaInvokeOperation(TypedDict, total=False):
    FunctionArn: FunctionArnString | None
    InvocationSchemaVersion: NonEmptyMaxLength64String | None
    UserArguments: UserArguments | None


class JobOperation(TypedDict, total=False):
    LambdaInvoke: LambdaInvokeOperation | None
    S3PutObjectCopy: S3CopyObjectOperation | None
    S3PutObjectAcl: S3SetObjectAclOperation | None
    S3PutObjectTagging: S3SetObjectTaggingOperation | None
    S3DeleteObjectTagging: S3DeleteObjectTaggingOperation | None
    S3InitiateRestoreObject: S3InitiateRestoreObjectOperation | None
    S3PutObjectLegalHold: S3SetObjectLegalHoldOperation | None
    S3PutObjectRetention: S3SetObjectRetentionOperation | None
    S3ReplicateObject: S3ReplicateObjectOperation | None
    S3ComputeObjectChecksum: S3ComputeObjectChecksumOperation | None


class CreateJobRequest(ServiceRequest):
    AccountId: AccountId
    ConfirmationRequired: ConfirmationRequired | None
    Operation: JobOperation
    Report: JobReport
    ClientRequestToken: NonEmptyMaxLength64String
    Manifest: JobManifest | None
    Description: NonEmptyMaxLength256String | None
    Priority: JobPriority
    RoleArn: IAMRoleArn
    Tags: S3TagSet | None
    ManifestGenerator: JobManifestGenerator | None


class CreateJobResult(TypedDict, total=False):
    JobId: JobId | None


class CreateMultiRegionAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    ClientToken: MultiRegionAccessPointClientToken
    Details: CreateMultiRegionAccessPointInput


class CreateMultiRegionAccessPointResult(TypedDict, total=False):
    RequestTokenARN: AsyncRequestTokenARN | None


ObjectSizeValue = int


class MatchObjectSize(TypedDict, total=False):
    BytesGreaterThan: ObjectSizeValue | None
    BytesLessThan: ObjectSizeValue | None


class MatchObjectAge(TypedDict, total=False):
    DaysGreaterThan: ObjectAgeValue | None
    DaysLessThan: ObjectAgeValue | None


MatchAnyTag = list[S3Tag]
MatchAnySuffix = list[Suffix]
MatchAnyPrefix = list[Prefix]


class StorageLensGroupOrOperator(TypedDict, total=False):
    MatchAnyPrefix: MatchAnyPrefix | None
    MatchAnySuffix: MatchAnySuffix | None
    MatchAnyTag: MatchAnyTag | None
    MatchObjectAge: MatchObjectAge | None
    MatchObjectSize: MatchObjectSize | None


class StorageLensGroupAndOperator(TypedDict, total=False):
    MatchAnyPrefix: MatchAnyPrefix | None
    MatchAnySuffix: MatchAnySuffix | None
    MatchAnyTag: MatchAnyTag | None
    MatchObjectAge: MatchObjectAge | None
    MatchObjectSize: MatchObjectSize | None


class StorageLensGroupFilter(TypedDict, total=False):
    MatchAnyPrefix: MatchAnyPrefix | None
    MatchAnySuffix: MatchAnySuffix | None
    MatchAnyTag: MatchAnyTag | None
    MatchObjectAge: MatchObjectAge | None
    MatchObjectSize: MatchObjectSize | None
    And: StorageLensGroupAndOperator | None
    Or: StorageLensGroupOrOperator | None


class StorageLensGroup(TypedDict, total=False):
    Name: StorageLensGroupName
    Filter: StorageLensGroupFilter
    StorageLensGroupArn: StorageLensGroupArn | None


class CreateStorageLensGroupRequest(ServiceRequest):
    AccountId: AccountId
    StorageLensGroup: StorageLensGroup
    Tags: TagList | None


CreationDate = datetime
Expiration = datetime


class Credentials(TypedDict, total=False):
    AccessKeyId: AccessKeyId | None
    SecretAccessKey: SecretAccessKey | None
    SessionToken: SessionToken | None
    Expiration: Expiration | None


Date = datetime


class DeleteAccessGrantRequest(ServiceRequest):
    AccountId: AccountId
    AccessGrantId: AccessGrantId


class DeleteAccessGrantsInstanceRequest(ServiceRequest):
    AccountId: AccountId


class DeleteAccessGrantsInstanceResourcePolicyRequest(ServiceRequest):
    AccountId: AccountId


class DeleteAccessGrantsLocationRequest(ServiceRequest):
    AccountId: AccountId
    AccessGrantsLocationId: AccessGrantsLocationId


class DeleteAccessPointForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class DeleteAccessPointPolicyForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class DeleteAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class DeleteAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class DeleteAccessPointScopeRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class DeleteBucketLifecycleConfigurationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class DeleteBucketPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class DeleteBucketReplicationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class DeleteBucketRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class DeleteBucketTaggingRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class DeleteJobTaggingRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId


class DeleteJobTaggingResult(TypedDict, total=False):
    pass


class DeleteMarkerReplication(TypedDict, total=False):
    Status: DeleteMarkerReplicationStatus


class DeleteMultiRegionAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    ClientToken: MultiRegionAccessPointClientToken
    Details: DeleteMultiRegionAccessPointInput


class DeleteMultiRegionAccessPointResult(TypedDict, total=False):
    RequestTokenARN: AsyncRequestTokenARN | None


class DeletePublicAccessBlockRequest(ServiceRequest):
    AccountId: AccountId


class DeleteStorageLensConfigurationRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId


class DeleteStorageLensConfigurationTaggingRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId


class DeleteStorageLensConfigurationTaggingResult(TypedDict, total=False):
    pass


class DeleteStorageLensGroupRequest(ServiceRequest):
    Name: StorageLensGroupName
    AccountId: AccountId


class DescribeJobRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId


class S3GeneratedManifestDescriptor(TypedDict, total=False):
    Format: GeneratedManifestFormat | None
    Location: JobManifestLocation | None


SuspendedDate = datetime
JobTerminationDate = datetime
JobCreationTime = datetime


class JobFailure(TypedDict, total=False):
    FailureCode: JobFailureCode | None
    FailureReason: JobFailureReason | None


JobFailureList = list[JobFailure]
JobTimeInStateSeconds = int


class JobTimers(TypedDict, total=False):
    ElapsedTimeInActiveSeconds: JobTimeInStateSeconds | None


JobNumberOfTasksFailed = int
JobNumberOfTasksSucceeded = int
JobTotalNumberOfTasks = int


class JobProgressSummary(TypedDict, total=False):
    TotalNumberOfTasks: JobTotalNumberOfTasks | None
    NumberOfTasksSucceeded: JobNumberOfTasksSucceeded | None
    NumberOfTasksFailed: JobNumberOfTasksFailed | None
    Timers: JobTimers | None


class JobDescriptor(TypedDict, total=False):
    JobId: JobId | None
    ConfirmationRequired: ConfirmationRequired | None
    Description: NonEmptyMaxLength256String | None
    JobArn: JobArn | None
    Status: JobStatus | None
    Manifest: JobManifest | None
    Operation: JobOperation | None
    Priority: JobPriority | None
    ProgressSummary: JobProgressSummary | None
    StatusUpdateReason: JobStatusUpdateReason | None
    FailureReasons: JobFailureList | None
    Report: JobReport | None
    CreationTime: JobCreationTime | None
    TerminationDate: JobTerminationDate | None
    RoleArn: IAMRoleArn | None
    SuspendedDate: SuspendedDate | None
    SuspendedCause: SuspendedCause | None
    ManifestGenerator: JobManifestGenerator | None
    GeneratedManifestDescriptor: S3GeneratedManifestDescriptor | None


class DescribeJobResult(TypedDict, total=False):
    Job: JobDescriptor | None


class DescribeMultiRegionAccessPointOperationRequest(ServiceRequest):
    AccountId: AccountId
    RequestTokenARN: AsyncRequestTokenARN


class DescribeMultiRegionAccessPointOperationResult(TypedDict, total=False):
    AsyncOperation: AsyncOperation | None


class ReplicationTimeValue(TypedDict, total=False):
    Minutes: Minutes | None


class Metrics(TypedDict, total=False):
    Status: MetricsStatus
    EventThreshold: ReplicationTimeValue | None


class EncryptionConfiguration(TypedDict, total=False):
    ReplicaKmsKeyID: ReplicaKmsKeyID | None


class ReplicationTime(TypedDict, total=False):
    Status: ReplicationTimeStatus
    Time: ReplicationTimeValue


class Destination(TypedDict, total=False):
    Account: AccountId | None
    Bucket: BucketIdentifierString
    ReplicationTime: ReplicationTime | None
    AccessControlTranslation: AccessControlTranslation | None
    EncryptionConfiguration: EncryptionConfiguration | None
    Metrics: Metrics | None
    StorageClass: ReplicationStorageClass | None


class DissociateAccessGrantsIdentityCenterRequest(ServiceRequest):
    AccountId: AccountId


Endpoints = dict[NonEmptyMaxLength64String, NonEmptyMaxLength1024String]


class EstablishedMultiRegionAccessPointPolicy(TypedDict, total=False):
    Policy: Policy | None


Regions = list[S3AWSRegion]


class Exclude(TypedDict, total=False):
    Buckets: Buckets | None
    Regions: Regions | None


class ExistingObjectReplication(TypedDict, total=False):
    Status: ExistingObjectReplicationStatus


class GetAccessGrantRequest(ServiceRequest):
    AccountId: AccountId
    AccessGrantId: AccessGrantId


class GetAccessGrantResult(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantId: AccessGrantId | None
    AccessGrantArn: AccessGrantArn | None
    Grantee: Grantee | None
    Permission: Permission | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationConfiguration: AccessGrantsLocationConfiguration | None
    GrantScope: S3Prefix | None
    ApplicationArn: IdentityCenterApplicationArn | None


class GetAccessGrantsInstanceForPrefixRequest(ServiceRequest):
    AccountId: AccountId
    S3Prefix: S3Prefix


class GetAccessGrantsInstanceForPrefixResult(TypedDict, total=False):
    AccessGrantsInstanceArn: AccessGrantsInstanceArn | None
    AccessGrantsInstanceId: AccessGrantsInstanceId | None


class GetAccessGrantsInstanceRequest(ServiceRequest):
    AccountId: AccountId


class GetAccessGrantsInstanceResourcePolicyRequest(ServiceRequest):
    AccountId: AccountId


class GetAccessGrantsInstanceResourcePolicyResult(TypedDict, total=False):
    Policy: PolicyDocument | None
    Organization: Organization | None
    CreatedAt: CreationTimestamp | None


class GetAccessGrantsInstanceResult(TypedDict, total=False):
    AccessGrantsInstanceArn: AccessGrantsInstanceArn | None
    AccessGrantsInstanceId: AccessGrantsInstanceId | None
    IdentityCenterArn: IdentityCenterArn | None
    IdentityCenterInstanceArn: IdentityCenterArn | None
    IdentityCenterApplicationArn: IdentityCenterApplicationArn | None
    CreatedAt: CreationTimestamp | None


class GetAccessGrantsLocationRequest(ServiceRequest):
    AccountId: AccountId
    AccessGrantsLocationId: AccessGrantsLocationId


class GetAccessGrantsLocationResult(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationArn: AccessGrantsLocationArn | None
    LocationScope: S3Prefix | None
    IAMRoleArn: IAMRoleArn | None


class GetAccessPointConfigurationForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class GetAccessPointConfigurationForObjectLambdaResult(TypedDict, total=False):
    Configuration: ObjectLambdaConfiguration | None


class GetAccessPointForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class GetAccessPointForObjectLambdaResult(TypedDict, total=False):
    Name: ObjectLambdaAccessPointName | None
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration | None
    CreationDate: CreationDate | None
    Alias: ObjectLambdaAccessPointAlias | None


class GetAccessPointPolicyForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class GetAccessPointPolicyForObjectLambdaResult(TypedDict, total=False):
    Policy: ObjectLambdaPolicy | None


class GetAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointPolicyResult(TypedDict, total=False):
    Policy: Policy | None


class GetAccessPointPolicyStatusForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class PolicyStatus(TypedDict, total=False):
    IsPublic: IsPublic | None


class GetAccessPointPolicyStatusForObjectLambdaResult(TypedDict, total=False):
    PolicyStatus: PolicyStatus | None


class GetAccessPointPolicyStatusRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointPolicyStatusResult(TypedDict, total=False):
    PolicyStatus: PolicyStatus | None


class GetAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointResult(TypedDict, total=False):
    Name: AccessPointName | None
    Bucket: AccessPointBucketName | None
    NetworkOrigin: NetworkOrigin | None
    VpcConfiguration: VpcConfiguration | None
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration | None
    CreationDate: CreationDate | None
    Alias: Alias | None
    AccessPointArn: S3AccessPointArn | None
    Endpoints: Endpoints | None
    BucketAccountId: AccountId | None
    DataSourceId: DataSourceId | None
    DataSourceType: DataSourceType | None


class GetAccessPointScopeRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointScopeResult(TypedDict, total=False):
    Scope: Scope | None


class GetBucketLifecycleConfigurationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class NoncurrentVersionExpiration(TypedDict, total=False):
    NoncurrentDays: Days | None
    NewerNoncurrentVersions: NoncurrentVersionCount | None


class NoncurrentVersionTransition(TypedDict, total=False):
    NoncurrentDays: Days | None
    StorageClass: TransitionStorageClass | None


NoncurrentVersionTransitionList = list[NoncurrentVersionTransition]


class Transition(TypedDict, total=False):
    Date: Date | None
    Days: Days | None
    StorageClass: TransitionStorageClass | None


TransitionList = list[Transition]


class LifecycleRuleAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: S3TagSet | None
    ObjectSizeGreaterThan: ObjectSizeGreaterThanBytes | None
    ObjectSizeLessThan: ObjectSizeLessThanBytes | None


class LifecycleRuleFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: S3Tag | None
    And: LifecycleRuleAndOperator | None
    ObjectSizeGreaterThan: ObjectSizeGreaterThanBytes | None
    ObjectSizeLessThan: ObjectSizeLessThanBytes | None


class LifecycleExpiration(TypedDict, total=False):
    Date: Date | None
    Days: Days | None
    ExpiredObjectDeleteMarker: ExpiredObjectDeleteMarker | None


class LifecycleRule(TypedDict, total=False):
    Expiration: LifecycleExpiration | None
    ID: ID | None
    Filter: LifecycleRuleFilter | None
    Status: ExpirationStatus
    Transitions: TransitionList | None
    NoncurrentVersionTransitions: NoncurrentVersionTransitionList | None
    NoncurrentVersionExpiration: NoncurrentVersionExpiration | None
    AbortIncompleteMultipartUpload: AbortIncompleteMultipartUpload | None


LifecycleRules = list[LifecycleRule]


class GetBucketLifecycleConfigurationResult(TypedDict, total=False):
    Rules: LifecycleRules | None


class GetBucketPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketPolicyResult(TypedDict, total=False):
    Policy: Policy | None


class GetBucketReplicationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class ReplicaModifications(TypedDict, total=False):
    Status: ReplicaModificationsStatus


class SseKmsEncryptedObjects(TypedDict, total=False):
    Status: SseKmsEncryptedObjectsStatus


class SourceSelectionCriteria(TypedDict, total=False):
    SseKmsEncryptedObjects: SseKmsEncryptedObjects | None
    ReplicaModifications: ReplicaModifications | None


class ReplicationRuleAndOperator(TypedDict, total=False):
    Prefix: Prefix | None
    Tags: S3TagSet | None


class ReplicationRuleFilter(TypedDict, total=False):
    Prefix: Prefix | None
    Tag: S3Tag | None
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
    Bucket: BucketIdentifierString


ReplicationRules = list[ReplicationRule]


class ReplicationConfiguration(TypedDict, total=False):
    Role: Role
    Rules: ReplicationRules


class GetBucketReplicationResult(TypedDict, total=False):
    ReplicationConfiguration: ReplicationConfiguration | None


class GetBucketRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketResult(TypedDict, total=False):
    Bucket: BucketName | None
    PublicAccessBlockEnabled: PublicAccessBlockEnabled | None
    CreationDate: CreationDate | None


class GetBucketTaggingRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketTaggingResult(TypedDict, total=False):
    TagSet: S3TagSet


class GetBucketVersioningRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketVersioningResult(TypedDict, total=False):
    Status: BucketVersioningStatus | None
    MFADelete: MFADeleteStatus | None


class GetDataAccessRequest(ServiceRequest):
    AccountId: AccountId
    Target: S3Prefix
    Permission: Permission
    DurationSeconds: DurationSeconds | None
    Privilege: Privilege | None
    TargetType: S3PrefixType | None


class GetDataAccessResult(TypedDict, total=False):
    Credentials: Credentials | None
    MatchedGrantTarget: S3Prefix | None
    Grantee: Grantee | None


class GetJobTaggingRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId


class GetJobTaggingResult(TypedDict, total=False):
    Tags: S3TagSet | None


class GetMultiRegionAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Name: MultiRegionAccessPointName


class ProposedMultiRegionAccessPointPolicy(TypedDict, total=False):
    Policy: Policy | None


class MultiRegionAccessPointPolicyDocument(TypedDict, total=False):
    Established: EstablishedMultiRegionAccessPointPolicy | None
    Proposed: ProposedMultiRegionAccessPointPolicy | None


class GetMultiRegionAccessPointPolicyResult(TypedDict, total=False):
    Policy: MultiRegionAccessPointPolicyDocument | None


class GetMultiRegionAccessPointPolicyStatusRequest(ServiceRequest):
    AccountId: AccountId
    Name: MultiRegionAccessPointName


class GetMultiRegionAccessPointPolicyStatusResult(TypedDict, total=False):
    Established: PolicyStatus | None


class GetMultiRegionAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: MultiRegionAccessPointName


class RegionReport(TypedDict, total=False):
    Bucket: BucketName | None
    Region: RegionName | None
    BucketAccountId: AccountId | None


RegionReportList = list[RegionReport]


class MultiRegionAccessPointReport(TypedDict, total=False):
    Name: MultiRegionAccessPointName | None
    Alias: MultiRegionAccessPointAlias | None
    CreatedAt: CreationTimestamp | None
    PublicAccessBlock: PublicAccessBlockConfiguration | None
    Status: MultiRegionAccessPointStatus | None
    Regions: RegionReportList | None


class GetMultiRegionAccessPointResult(TypedDict, total=False):
    AccessPoint: MultiRegionAccessPointReport | None


class GetMultiRegionAccessPointRoutesRequest(ServiceRequest):
    AccountId: AccountId
    Mrap: MultiRegionAccessPointId


class MultiRegionAccessPointRoute(TypedDict, total=False):
    Bucket: BucketName | None
    Region: RegionName | None
    TrafficDialPercentage: TrafficDialPercentage


RouteList = list[MultiRegionAccessPointRoute]


class GetMultiRegionAccessPointRoutesResult(TypedDict, total=False):
    Mrap: MultiRegionAccessPointId | None
    Routes: RouteList | None


class GetPublicAccessBlockOutput(TypedDict, total=False):
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration | None


class GetPublicAccessBlockRequest(ServiceRequest):
    AccountId: AccountId


class GetStorageLensConfigurationRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId


class StorageLensAwsOrg(TypedDict, total=False):
    Arn: AwsOrgArn


class SSEKMS(TypedDict, total=False):
    KeyId: SSEKMSKeyId


class SSES3(TypedDict, total=False):
    pass


class StorageLensDataExportEncryption(TypedDict, total=False):
    SSES3: SSES3 | None
    SSEKMS: SSEKMS | None


class StorageLensTableDestination(TypedDict, total=False):
    IsEnabled: IsEnabled
    Encryption: StorageLensDataExportEncryption | None


class S3BucketDestination(TypedDict, total=False):
    Format: Format
    OutputSchemaVersion: OutputSchemaVersion
    AccountId: AccountId
    Arn: S3BucketArnString
    Prefix: Prefix | None
    Encryption: StorageLensDataExportEncryption | None


class StorageLensExpandedPrefixesDataExport(TypedDict, total=False):
    S3BucketDestination: S3BucketDestination | None
    StorageLensTableDestination: StorageLensTableDestination | None


class StorageLensDataExport(TypedDict, total=False):
    S3BucketDestination: S3BucketDestination | None
    CloudWatchMetrics: CloudWatchMetrics | None
    StorageLensTableDestination: StorageLensTableDestination | None


class Include(TypedDict, total=False):
    Buckets: Buckets | None
    Regions: Regions | None


class StorageLensConfiguration(TypedDict, total=False):
    Id: ConfigId
    AccountLevel: AccountLevel
    Include: Include | None
    Exclude: Exclude | None
    DataExport: StorageLensDataExport | None
    ExpandedPrefixesDataExport: StorageLensExpandedPrefixesDataExport | None
    IsEnabled: IsEnabled
    AwsOrg: StorageLensAwsOrg | None
    StorageLensArn: StorageLensArn | None
    PrefixDelimiter: StorageLensPrefixLevelDelimiter | None


class GetStorageLensConfigurationResult(TypedDict, total=False):
    StorageLensConfiguration: StorageLensConfiguration | None


class GetStorageLensConfigurationTaggingRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId


class StorageLensTag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


StorageLensTags = list[StorageLensTag]


class GetStorageLensConfigurationTaggingResult(TypedDict, total=False):
    Tags: StorageLensTags | None


class GetStorageLensGroupRequest(ServiceRequest):
    Name: StorageLensGroupName
    AccountId: AccountId


class GetStorageLensGroupResult(TypedDict, total=False):
    StorageLensGroup: StorageLensGroup | None


class JobListDescriptor(TypedDict, total=False):
    JobId: JobId | None
    Description: NonEmptyMaxLength256String | None
    Operation: OperationName | None
    Priority: JobPriority | None
    Status: JobStatus | None
    CreationTime: JobCreationTime | None
    TerminationDate: JobTerminationDate | None
    ProgressSummary: JobProgressSummary | None


JobListDescriptorList = list[JobListDescriptor]
JobStatusList = list[JobStatus]


class LifecycleConfiguration(TypedDict, total=False):
    Rules: LifecycleRules | None


class ListAccessGrantsInstancesRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: ContinuationToken | None
    MaxResults: MaxResults | None


class ListAccessGrantsInstancesResult(TypedDict, total=False):
    NextToken: ContinuationToken | None
    AccessGrantsInstancesList: AccessGrantsInstancesList | None


class ListAccessGrantsLocationsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: ContinuationToken | None
    MaxResults: MaxResults | None
    LocationScope: S3Prefix | None


class ListAccessGrantsLocationsResult(TypedDict, total=False):
    NextToken: ContinuationToken | None
    AccessGrantsLocationsList: AccessGrantsLocationsList | None


class ListAccessGrantsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: ContinuationToken | None
    MaxResults: MaxResults | None
    GranteeType: GranteeType | None
    GranteeIdentifier: GranteeIdentifier | None
    Permission: Permission | None
    GrantScope: S3Prefix | None
    ApplicationArn: IdentityCenterApplicationArn | None


class ListAccessGrantsResult(TypedDict, total=False):
    NextToken: ContinuationToken | None
    AccessGrantsList: AccessGrantsList | None


class ListAccessPointsForDirectoryBucketsRequest(ServiceRequest):
    AccountId: AccountId
    DirectoryBucket: BucketName | None
    NextToken: NonEmptyMaxLength1024String | None
    MaxResults: MaxResults | None


class ListAccessPointsForDirectoryBucketsResult(TypedDict, total=False):
    AccessPointList: AccessPointList | None
    NextToken: NonEmptyMaxLength1024String | None


class ListAccessPointsForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: NonEmptyMaxLength1024String | None
    MaxResults: MaxResults | None


class ObjectLambdaAccessPoint(TypedDict, total=False):
    Name: ObjectLambdaAccessPointName
    ObjectLambdaAccessPointArn: ObjectLambdaAccessPointArn | None
    Alias: ObjectLambdaAccessPointAlias | None


ObjectLambdaAccessPointList = list[ObjectLambdaAccessPoint]


class ListAccessPointsForObjectLambdaResult(TypedDict, total=False):
    ObjectLambdaAccessPointList: ObjectLambdaAccessPointList | None
    NextToken: NonEmptyMaxLength1024String | None


class ListAccessPointsRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName | None
    NextToken: NonEmptyMaxLength1024String | None
    MaxResults: MaxResults | None
    DataSourceId: DataSourceId | None
    DataSourceType: DataSourceType | None


class ListAccessPointsResult(TypedDict, total=False):
    AccessPointList: AccessPointList | None
    NextToken: NonEmptyMaxLength1024String | None


class ListCallerAccessGrantsRequest(ServiceRequest):
    AccountId: AccountId
    GrantScope: S3Prefix | None
    NextToken: ContinuationToken | None
    MaxResults: MaxResults | None
    AllowedByApplication: Boolean | None


class ListCallerAccessGrantsResult(TypedDict, total=False):
    NextToken: ContinuationToken | None
    CallerAccessGrantsList: CallerAccessGrantsList | None


class ListJobsRequest(ServiceRequest):
    AccountId: AccountId
    JobStatuses: JobStatusList | None
    NextToken: StringForNextToken | None
    MaxResults: MaxResults | None


class ListJobsResult(TypedDict, total=False):
    NextToken: StringForNextToken | None
    Jobs: JobListDescriptorList | None


class ListMultiRegionAccessPointsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: NonEmptyMaxLength1024String | None
    MaxResults: MaxResults | None


MultiRegionAccessPointReportList = list[MultiRegionAccessPointReport]


class ListMultiRegionAccessPointsResult(TypedDict, total=False):
    AccessPoints: MultiRegionAccessPointReportList | None
    NextToken: NonEmptyMaxLength1024String | None


class ListRegionalBucketsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: NonEmptyMaxLength1024String | None
    MaxResults: MaxResults | None
    OutpostId: NonEmptyMaxLength64String | None


class RegionalBucket(TypedDict, total=False):
    Bucket: BucketName
    BucketArn: S3RegionalBucketArn | None
    PublicAccessBlockEnabled: PublicAccessBlockEnabled
    CreationDate: CreationDate
    OutpostId: NonEmptyMaxLength64String | None


RegionalBucketList = list[RegionalBucket]


class ListRegionalBucketsResult(TypedDict, total=False):
    RegionalBucketList: RegionalBucketList | None
    NextToken: NonEmptyMaxLength1024String | None


class ListStorageLensConfigurationEntry(TypedDict, total=False):
    Id: ConfigId
    StorageLensArn: StorageLensArn
    HomeRegion: S3AWSRegion
    IsEnabled: IsEnabled | None


class ListStorageLensConfigurationsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: ContinuationToken | None


StorageLensConfigurationList = list[ListStorageLensConfigurationEntry]


class ListStorageLensConfigurationsResult(TypedDict, total=False):
    NextToken: ContinuationToken | None
    StorageLensConfigurationList: StorageLensConfigurationList | None


class ListStorageLensGroupEntry(TypedDict, total=False):
    Name: StorageLensGroupName
    StorageLensGroupArn: StorageLensGroupArn
    HomeRegion: S3AWSRegion


class ListStorageLensGroupsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: ContinuationToken | None


StorageLensGroupList = list[ListStorageLensGroupEntry]


class ListStorageLensGroupsResult(TypedDict, total=False):
    NextToken: ContinuationToken | None
    StorageLensGroupList: StorageLensGroupList | None


class ListTagsForResourceRequest(ServiceRequest):
    AccountId: AccountId
    ResourceArn: S3ResourceArn


class ListTagsForResourceResult(TypedDict, total=False):
    Tags: TagList | None


class PutAccessGrantsInstanceResourcePolicyRequest(ServiceRequest):
    AccountId: AccountId
    Policy: PolicyDocument
    Organization: Organization | None


class PutAccessGrantsInstanceResourcePolicyResult(TypedDict, total=False):
    Policy: PolicyDocument | None
    Organization: Organization | None
    CreatedAt: CreationTimestamp | None


class PutAccessPointConfigurationForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName
    Configuration: ObjectLambdaConfiguration


class PutAccessPointPolicyForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName
    Policy: ObjectLambdaPolicy


class PutAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName
    Policy: Policy


class PutAccessPointScopeRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName
    Scope: Scope


class PutBucketLifecycleConfigurationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    LifecycleConfiguration: LifecycleConfiguration | None


class PutBucketPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    ConfirmRemoveSelfBucketAccess: ConfirmRemoveSelfBucketAccess | None
    Policy: Policy


class PutBucketReplicationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    ReplicationConfiguration: ReplicationConfiguration


class Tagging(TypedDict, total=False):
    TagSet: S3TagSet


class PutBucketTaggingRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    Tagging: Tagging


class VersioningConfiguration(TypedDict, total=False):
    MFADelete: MFADelete | None
    Status: BucketVersioningStatus | None


class PutBucketVersioningRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    MFA: MFA | None
    VersioningConfiguration: VersioningConfiguration


class PutJobTaggingRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId
    Tags: S3TagSet


class PutJobTaggingResult(TypedDict, total=False):
    pass


class PutMultiRegionAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    ClientToken: MultiRegionAccessPointClientToken
    Details: PutMultiRegionAccessPointPolicyInput


class PutMultiRegionAccessPointPolicyResult(TypedDict, total=False):
    RequestTokenARN: AsyncRequestTokenARN | None


class PutPublicAccessBlockRequest(ServiceRequest):
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration
    AccountId: AccountId


class PutStorageLensConfigurationRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId
    StorageLensConfiguration: StorageLensConfiguration
    Tags: StorageLensTags | None


class PutStorageLensConfigurationTaggingRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId
    Tags: StorageLensTags


class PutStorageLensConfigurationTaggingResult(TypedDict, total=False):
    pass


class SubmitMultiRegionAccessPointRoutesRequest(ServiceRequest):
    AccountId: AccountId
    Mrap: MultiRegionAccessPointId
    RouteUpdates: RouteList


class SubmitMultiRegionAccessPointRoutesResult(TypedDict, total=False):
    pass


TagKeyList = list[TagKeyString]


class TagResourceRequest(ServiceRequest):
    AccountId: AccountId
    ResourceArn: S3ResourceArn
    Tags: TagList


class TagResourceResult(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    AccountId: AccountId
    ResourceArn: S3ResourceArn
    TagKeys: TagKeyList


class UntagResourceResult(TypedDict, total=False):
    pass


class UpdateAccessGrantsLocationRequest(ServiceRequest):
    AccountId: AccountId
    AccessGrantsLocationId: AccessGrantsLocationId
    IAMRoleArn: IAMRoleArn


class UpdateAccessGrantsLocationResult(TypedDict, total=False):
    CreatedAt: CreationTimestamp | None
    AccessGrantsLocationId: AccessGrantsLocationId | None
    AccessGrantsLocationArn: AccessGrantsLocationArn | None
    LocationScope: S3Prefix | None
    IAMRoleArn: IAMRoleArn | None


class UpdateJobPriorityRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId
    Priority: JobPriority


class UpdateJobPriorityResult(TypedDict, total=False):
    JobId: JobId
    Priority: JobPriority


class UpdateJobStatusRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId
    RequestedJobStatus: RequestedJobStatus
    StatusUpdateReason: JobStatusUpdateReason | None


class UpdateJobStatusResult(TypedDict, total=False):
    JobId: JobId | None
    Status: JobStatus | None
    StatusUpdateReason: JobStatusUpdateReason | None


class UpdateStorageLensGroupRequest(ServiceRequest):
    Name: StorageLensGroupName
    AccountId: AccountId
    StorageLensGroup: StorageLensGroup


class S3ControlApi:
    service: str = "s3control"
    version: str = "2018-08-20"

    @handler("AssociateAccessGrantsIdentityCenter")
    def associate_access_grants_identity_center(
        self,
        context: RequestContext,
        account_id: AccountId,
        identity_center_arn: IdentityCenterArn,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateAccessGrant")
    def create_access_grant(
        self,
        context: RequestContext,
        account_id: AccountId,
        access_grants_location_id: AccessGrantsLocationId,
        grantee: Grantee,
        permission: Permission,
        access_grants_location_configuration: AccessGrantsLocationConfiguration | None = None,
        application_arn: IdentityCenterApplicationArn | None = None,
        s3_prefix_type: S3PrefixType | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateAccessGrantResult:
        raise NotImplementedError

    @handler("CreateAccessGrantsInstance")
    def create_access_grants_instance(
        self,
        context: RequestContext,
        account_id: AccountId,
        identity_center_arn: IdentityCenterArn | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateAccessGrantsInstanceResult:
        raise NotImplementedError

    @handler("CreateAccessGrantsLocation")
    def create_access_grants_location(
        self,
        context: RequestContext,
        account_id: AccountId,
        location_scope: S3Prefix,
        iam_role_arn: IAMRoleArn,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateAccessGrantsLocationResult:
        raise NotImplementedError

    @handler("CreateAccessPoint")
    def create_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: AccessPointName,
        bucket: BucketName,
        vpc_configuration: VpcConfiguration | None = None,
        public_access_block_configuration: PublicAccessBlockConfiguration | None = None,
        bucket_account_id: AccountId | None = None,
        scope: Scope | None = None,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateAccessPointResult:
        raise NotImplementedError

    @handler("CreateAccessPointForObjectLambda")
    def create_access_point_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        configuration: ObjectLambdaConfiguration,
        **kwargs,
    ) -> CreateAccessPointForObjectLambdaResult:
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
        outpost_id: NonEmptyMaxLength64String | None = None,
        **kwargs,
    ) -> CreateBucketResult:
        raise NotImplementedError

    @handler("CreateJob")
    def create_job(
        self,
        context: RequestContext,
        account_id: AccountId,
        operation: JobOperation,
        report: JobReport,
        client_request_token: NonEmptyMaxLength64String,
        priority: JobPriority,
        role_arn: IAMRoleArn,
        confirmation_required: ConfirmationRequired | None = None,
        manifest: JobManifest | None = None,
        description: NonEmptyMaxLength256String | None = None,
        tags: S3TagSet | None = None,
        manifest_generator: JobManifestGenerator | None = None,
        **kwargs,
    ) -> CreateJobResult:
        raise NotImplementedError

    @handler("CreateMultiRegionAccessPoint")
    def create_multi_region_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        client_token: MultiRegionAccessPointClientToken,
        details: CreateMultiRegionAccessPointInput,
        **kwargs,
    ) -> CreateMultiRegionAccessPointResult:
        raise NotImplementedError

    @handler("CreateStorageLensGroup")
    def create_storage_lens_group(
        self,
        context: RequestContext,
        account_id: AccountId,
        storage_lens_group: StorageLensGroup,
        tags: TagList | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessGrant")
    def delete_access_grant(
        self,
        context: RequestContext,
        account_id: AccountId,
        access_grant_id: AccessGrantId,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessGrantsInstance")
    def delete_access_grants_instance(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessGrantsInstanceResourcePolicy")
    def delete_access_grants_instance_resource_policy(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessGrantsLocation")
    def delete_access_grants_location(
        self,
        context: RequestContext,
        account_id: AccountId,
        access_grants_location_id: AccessGrantsLocationId,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPoint")
    def delete_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointForObjectLambda")
    def delete_access_point_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointPolicy")
    def delete_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointPolicyForObjectLambda")
    def delete_access_point_policy_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointScope")
    def delete_access_point_scope(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucket")
    def delete_bucket(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketLifecycleConfiguration")
    def delete_bucket_lifecycle_configuration(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketPolicy")
    def delete_bucket_policy(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketReplication")
    def delete_bucket_replication(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketTagging")
    def delete_bucket_tagging(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteJobTagging")
    def delete_job_tagging(
        self, context: RequestContext, account_id: AccountId, job_id: JobId, **kwargs
    ) -> DeleteJobTaggingResult:
        raise NotImplementedError

    @handler("DeleteMultiRegionAccessPoint")
    def delete_multi_region_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        client_token: MultiRegionAccessPointClientToken,
        details: DeleteMultiRegionAccessPointInput,
        **kwargs,
    ) -> DeleteMultiRegionAccessPointResult:
        raise NotImplementedError

    @handler("DeletePublicAccessBlock")
    def delete_public_access_block(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStorageLensConfiguration")
    def delete_storage_lens_configuration(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStorageLensConfigurationTagging")
    def delete_storage_lens_configuration_tagging(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId, **kwargs
    ) -> DeleteStorageLensConfigurationTaggingResult:
        raise NotImplementedError

    @handler("DeleteStorageLensGroup")
    def delete_storage_lens_group(
        self, context: RequestContext, name: StorageLensGroupName, account_id: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DescribeJob")
    def describe_job(
        self, context: RequestContext, account_id: AccountId, job_id: JobId, **kwargs
    ) -> DescribeJobResult:
        raise NotImplementedError

    @handler("DescribeMultiRegionAccessPointOperation")
    def describe_multi_region_access_point_operation(
        self,
        context: RequestContext,
        account_id: AccountId,
        request_token_arn: AsyncRequestTokenARN,
        **kwargs,
    ) -> DescribeMultiRegionAccessPointOperationResult:
        raise NotImplementedError

    @handler("DissociateAccessGrantsIdentityCenter")
    def dissociate_access_grants_identity_center(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("GetAccessGrant")
    def get_access_grant(
        self,
        context: RequestContext,
        account_id: AccountId,
        access_grant_id: AccessGrantId,
        **kwargs,
    ) -> GetAccessGrantResult:
        raise NotImplementedError

    @handler("GetAccessGrantsInstance")
    def get_access_grants_instance(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> GetAccessGrantsInstanceResult:
        raise NotImplementedError

    @handler("GetAccessGrantsInstanceForPrefix")
    def get_access_grants_instance_for_prefix(
        self, context: RequestContext, account_id: AccountId, s3_prefix: S3Prefix, **kwargs
    ) -> GetAccessGrantsInstanceForPrefixResult:
        raise NotImplementedError

    @handler("GetAccessGrantsInstanceResourcePolicy")
    def get_access_grants_instance_resource_policy(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> GetAccessGrantsInstanceResourcePolicyResult:
        raise NotImplementedError

    @handler("GetAccessGrantsLocation")
    def get_access_grants_location(
        self,
        context: RequestContext,
        account_id: AccountId,
        access_grants_location_id: AccessGrantsLocationId,
        **kwargs,
    ) -> GetAccessGrantsLocationResult:
        raise NotImplementedError

    @handler("GetAccessPoint")
    def get_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> GetAccessPointResult:
        raise NotImplementedError

    @handler("GetAccessPointConfigurationForObjectLambda")
    def get_access_point_configuration_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        **kwargs,
    ) -> GetAccessPointConfigurationForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointForObjectLambda")
    def get_access_point_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        **kwargs,
    ) -> GetAccessPointForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicy")
    def get_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> GetAccessPointPolicyResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicyForObjectLambda")
    def get_access_point_policy_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        **kwargs,
    ) -> GetAccessPointPolicyForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicyStatus")
    def get_access_point_policy_status(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> GetAccessPointPolicyStatusResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicyStatusForObjectLambda")
    def get_access_point_policy_status_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        **kwargs,
    ) -> GetAccessPointPolicyStatusForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointScope")
    def get_access_point_scope(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, **kwargs
    ) -> GetAccessPointScopeResult:
        raise NotImplementedError

    @handler("GetBucket")
    def get_bucket(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> GetBucketResult:
        raise NotImplementedError

    @handler("GetBucketLifecycleConfiguration")
    def get_bucket_lifecycle_configuration(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> GetBucketLifecycleConfigurationResult:
        raise NotImplementedError

    @handler("GetBucketPolicy")
    def get_bucket_policy(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> GetBucketPolicyResult:
        raise NotImplementedError

    @handler("GetBucketReplication")
    def get_bucket_replication(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> GetBucketReplicationResult:
        raise NotImplementedError

    @handler("GetBucketTagging")
    def get_bucket_tagging(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> GetBucketTaggingResult:
        raise NotImplementedError

    @handler("GetBucketVersioning")
    def get_bucket_versioning(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, **kwargs
    ) -> GetBucketVersioningResult:
        raise NotImplementedError

    @handler("GetDataAccess")
    def get_data_access(
        self,
        context: RequestContext,
        account_id: AccountId,
        target: S3Prefix,
        permission: Permission,
        duration_seconds: DurationSeconds | None = None,
        privilege: Privilege | None = None,
        target_type: S3PrefixType | None = None,
        **kwargs,
    ) -> GetDataAccessResult:
        raise NotImplementedError

    @handler("GetJobTagging")
    def get_job_tagging(
        self, context: RequestContext, account_id: AccountId, job_id: JobId, **kwargs
    ) -> GetJobTaggingResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPoint")
    def get_multi_region_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: MultiRegionAccessPointName,
        **kwargs,
    ) -> GetMultiRegionAccessPointResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPointPolicy")
    def get_multi_region_access_point_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: MultiRegionAccessPointName,
        **kwargs,
    ) -> GetMultiRegionAccessPointPolicyResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPointPolicyStatus")
    def get_multi_region_access_point_policy_status(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: MultiRegionAccessPointName,
        **kwargs,
    ) -> GetMultiRegionAccessPointPolicyStatusResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPointRoutes")
    def get_multi_region_access_point_routes(
        self,
        context: RequestContext,
        account_id: AccountId,
        mrap: MultiRegionAccessPointId,
        **kwargs,
    ) -> GetMultiRegionAccessPointRoutesResult:
        raise NotImplementedError

    @handler("GetPublicAccessBlock")
    def get_public_access_block(
        self, context: RequestContext, account_id: AccountId, **kwargs
    ) -> GetPublicAccessBlockOutput:
        raise NotImplementedError

    @handler("GetStorageLensConfiguration")
    def get_storage_lens_configuration(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId, **kwargs
    ) -> GetStorageLensConfigurationResult:
        raise NotImplementedError

    @handler("GetStorageLensConfigurationTagging")
    def get_storage_lens_configuration_tagging(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId, **kwargs
    ) -> GetStorageLensConfigurationTaggingResult:
        raise NotImplementedError

    @handler("GetStorageLensGroup")
    def get_storage_lens_group(
        self, context: RequestContext, name: StorageLensGroupName, account_id: AccountId, **kwargs
    ) -> GetStorageLensGroupResult:
        raise NotImplementedError

    @handler("ListAccessGrants")
    def list_access_grants(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: ContinuationToken | None = None,
        max_results: MaxResults | None = None,
        grantee_type: GranteeType | None = None,
        grantee_identifier: GranteeIdentifier | None = None,
        permission: Permission | None = None,
        grant_scope: S3Prefix | None = None,
        application_arn: IdentityCenterApplicationArn | None = None,
        **kwargs,
    ) -> ListAccessGrantsResult:
        raise NotImplementedError

    @handler("ListAccessGrantsInstances")
    def list_access_grants_instances(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: ContinuationToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListAccessGrantsInstancesResult:
        raise NotImplementedError

    @handler("ListAccessGrantsLocations")
    def list_access_grants_locations(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: ContinuationToken | None = None,
        max_results: MaxResults | None = None,
        location_scope: S3Prefix | None = None,
        **kwargs,
    ) -> ListAccessGrantsLocationsResult:
        raise NotImplementedError

    @handler("ListAccessPoints")
    def list_access_points(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName | None = None,
        next_token: NonEmptyMaxLength1024String | None = None,
        max_results: MaxResults | None = None,
        data_source_id: DataSourceId | None = None,
        data_source_type: DataSourceType | None = None,
        **kwargs,
    ) -> ListAccessPointsResult:
        raise NotImplementedError

    @handler("ListAccessPointsForDirectoryBuckets")
    def list_access_points_for_directory_buckets(
        self,
        context: RequestContext,
        account_id: AccountId,
        directory_bucket: BucketName | None = None,
        next_token: NonEmptyMaxLength1024String | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListAccessPointsForDirectoryBucketsResult:
        raise NotImplementedError

    @handler("ListAccessPointsForObjectLambda")
    def list_access_points_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NonEmptyMaxLength1024String | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListAccessPointsForObjectLambdaResult:
        raise NotImplementedError

    @handler("ListCallerAccessGrants")
    def list_caller_access_grants(
        self,
        context: RequestContext,
        account_id: AccountId,
        grant_scope: S3Prefix | None = None,
        next_token: ContinuationToken | None = None,
        max_results: MaxResults | None = None,
        allowed_by_application: Boolean | None = None,
        **kwargs,
    ) -> ListCallerAccessGrantsResult:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        account_id: AccountId,
        job_statuses: JobStatusList | None = None,
        next_token: StringForNextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListJobsResult:
        raise NotImplementedError

    @handler("ListMultiRegionAccessPoints")
    def list_multi_region_access_points(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NonEmptyMaxLength1024String | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListMultiRegionAccessPointsResult:
        raise NotImplementedError

    @handler("ListRegionalBuckets")
    def list_regional_buckets(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NonEmptyMaxLength1024String | None = None,
        max_results: MaxResults | None = None,
        outpost_id: NonEmptyMaxLength64String | None = None,
        **kwargs,
    ) -> ListRegionalBucketsResult:
        raise NotImplementedError

    @handler("ListStorageLensConfigurations")
    def list_storage_lens_configurations(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: ContinuationToken | None = None,
        **kwargs,
    ) -> ListStorageLensConfigurationsResult:
        raise NotImplementedError

    @handler("ListStorageLensGroups")
    def list_storage_lens_groups(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: ContinuationToken | None = None,
        **kwargs,
    ) -> ListStorageLensGroupsResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, account_id: AccountId, resource_arn: S3ResourceArn, **kwargs
    ) -> ListTagsForResourceResult:
        raise NotImplementedError

    @handler("PutAccessGrantsInstanceResourcePolicy")
    def put_access_grants_instance_resource_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        policy: PolicyDocument,
        organization: Organization | None = None,
        **kwargs,
    ) -> PutAccessGrantsInstanceResourcePolicyResult:
        raise NotImplementedError

    @handler("PutAccessPointConfigurationForObjectLambda")
    def put_access_point_configuration_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        configuration: ObjectLambdaConfiguration,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutAccessPointPolicy")
    def put_access_point_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: AccessPointName,
        policy: Policy,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutAccessPointPolicyForObjectLambda")
    def put_access_point_policy_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        policy: ObjectLambdaPolicy,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutAccessPointScope")
    def put_access_point_scope(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: AccessPointName,
        scope: Scope,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketLifecycleConfiguration")
    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        lifecycle_configuration: LifecycleConfiguration | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketPolicy")
    def put_bucket_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        policy: Policy,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketReplication")
    def put_bucket_replication(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        replication_configuration: ReplicationConfiguration,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketTagging")
    def put_bucket_tagging(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        tagging: Tagging,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketVersioning")
    def put_bucket_versioning(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        versioning_configuration: VersioningConfiguration,
        mfa: MFA | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutJobTagging")
    def put_job_tagging(
        self,
        context: RequestContext,
        account_id: AccountId,
        job_id: JobId,
        tags: S3TagSet,
        **kwargs,
    ) -> PutJobTaggingResult:
        raise NotImplementedError

    @handler("PutMultiRegionAccessPointPolicy")
    def put_multi_region_access_point_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        client_token: MultiRegionAccessPointClientToken,
        details: PutMultiRegionAccessPointPolicyInput,
        **kwargs,
    ) -> PutMultiRegionAccessPointPolicyResult:
        raise NotImplementedError

    @handler("PutPublicAccessBlock")
    def put_public_access_block(
        self,
        context: RequestContext,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        account_id: AccountId,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutStorageLensConfiguration")
    def put_storage_lens_configuration(
        self,
        context: RequestContext,
        config_id: ConfigId,
        account_id: AccountId,
        storage_lens_configuration: StorageLensConfiguration,
        tags: StorageLensTags | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutStorageLensConfigurationTagging")
    def put_storage_lens_configuration_tagging(
        self,
        context: RequestContext,
        config_id: ConfigId,
        account_id: AccountId,
        tags: StorageLensTags,
        **kwargs,
    ) -> PutStorageLensConfigurationTaggingResult:
        raise NotImplementedError

    @handler("SubmitMultiRegionAccessPointRoutes")
    def submit_multi_region_access_point_routes(
        self,
        context: RequestContext,
        account_id: AccountId,
        mrap: MultiRegionAccessPointId,
        route_updates: RouteList,
        **kwargs,
    ) -> SubmitMultiRegionAccessPointRoutesResult:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self,
        context: RequestContext,
        account_id: AccountId,
        resource_arn: S3ResourceArn,
        tags: TagList,
        **kwargs,
    ) -> TagResourceResult:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        account_id: AccountId,
        resource_arn: S3ResourceArn,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceResult:
        raise NotImplementedError

    @handler("UpdateAccessGrantsLocation")
    def update_access_grants_location(
        self,
        context: RequestContext,
        account_id: AccountId,
        access_grants_location_id: AccessGrantsLocationId,
        iam_role_arn: IAMRoleArn,
        **kwargs,
    ) -> UpdateAccessGrantsLocationResult:
        raise NotImplementedError

    @handler("UpdateJobPriority")
    def update_job_priority(
        self,
        context: RequestContext,
        account_id: AccountId,
        job_id: JobId,
        priority: JobPriority,
        **kwargs,
    ) -> UpdateJobPriorityResult:
        raise NotImplementedError

    @handler("UpdateJobStatus")
    def update_job_status(
        self,
        context: RequestContext,
        account_id: AccountId,
        job_id: JobId,
        requested_job_status: RequestedJobStatus,
        status_update_reason: JobStatusUpdateReason | None = None,
        **kwargs,
    ) -> UpdateJobStatusResult:
        raise NotImplementedError

    @handler("UpdateStorageLensGroup")
    def update_storage_lens_group(
        self,
        context: RequestContext,
        name: StorageLensGroupName,
        account_id: AccountId,
        storage_lens_group: StorageLensGroup,
        **kwargs,
    ) -> None:
        raise NotImplementedError
