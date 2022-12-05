import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessPointName = str
AccountId = str
Alias = str
AsyncRequestStatus = str
AsyncRequestTokenARN = str
AwsLambdaTransformationPayload = str
AwsOrgArn = str
Boolean = bool
BucketName = str
ConfigId = str
ConfirmRemoveSelfBucketAccess = bool
ConfirmationRequired = bool
ContinuationToken = str
Days = int
DaysAfterInitiation = int
ExceptionMessage = str
ExpiredObjectDeleteMarker = bool
FunctionArnString = str
GrantFullControl = str
GrantRead = str
GrantReadACP = str
GrantWrite = str
GrantWriteACP = str
IAMRoleArn = str
ID = str
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
MultiRegionAccessPointAlias = str
MultiRegionAccessPointClientToken = str
MultiRegionAccessPointId = str
MultiRegionAccessPointName = str
NoSuchPublicAccessBlockConfigurationMessage = str
NonEmptyMaxLength1024String = str
NonEmptyMaxLength2048String = str
NonEmptyMaxLength256String = str
NonEmptyMaxLength64String = str
NoncurrentVersionCount = int
ObjectLambdaAccessPointArn = str
ObjectLambdaAccessPointName = str
ObjectLambdaPolicy = str
ObjectLambdaSupportingAccessPointArn = str
ObjectLockEnabledForBucket = bool
Policy = str
Prefix = str
PublicAccessBlockEnabled = bool
RegionName = str
ReportPrefixString = str
S3AWSRegion = str
S3AccessPointArn = str
S3BucketArnString = str
S3ExpirationInDays = int
S3KeyArnString = str
S3ObjectVersionId = str
S3RegionalBucketArn = str
SSEKMSKeyId = str
Setting = bool
StorageLensArn = str
StorageLensPrefixLevelDelimiter = str
StorageLensPrefixLevelMaxDepth = int
StringForNextToken = str
SuspendedCause = str
TagKeyString = str
TagValueString = str
TrafficDialPercentage = int
VpcId = str


class AsyncOperationName(str):
    CreateMultiRegionAccessPoint = "CreateMultiRegionAccessPoint"
    DeleteMultiRegionAccessPoint = "DeleteMultiRegionAccessPoint"
    PutMultiRegionAccessPointPolicy = "PutMultiRegionAccessPointPolicy"


class BucketCannedACL(str):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    authenticated_read = "authenticated-read"


class BucketLocationConstraint(str):
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


class BucketVersioningStatus(str):
    Enabled = "Enabled"
    Suspended = "Suspended"


class ExpirationStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class Format(str):
    CSV = "CSV"
    Parquet = "Parquet"


class GeneratedManifestFormat(str):
    S3InventoryReport_CSV_20211130 = "S3InventoryReport_CSV_20211130"


class JobManifestFieldName(str):
    Ignore = "Ignore"
    Bucket = "Bucket"
    Key = "Key"
    VersionId = "VersionId"


class JobManifestFormat(str):
    S3BatchOperations_CSV_20180820 = "S3BatchOperations_CSV_20180820"
    S3InventoryReport_CSV_20161130 = "S3InventoryReport_CSV_20161130"


class JobReportFormat(str):
    Report_CSV_20180820 = "Report_CSV_20180820"


class JobReportScope(str):
    AllTasks = "AllTasks"
    FailedTasksOnly = "FailedTasksOnly"


class JobStatus(str):
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


class MFADelete(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MFADeleteStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class MultiRegionAccessPointStatus(str):
    READY = "READY"
    INCONSISTENT_ACROSS_REGIONS = "INCONSISTENT_ACROSS_REGIONS"
    CREATING = "CREATING"
    PARTIALLY_CREATED = "PARTIALLY_CREATED"
    PARTIALLY_DELETED = "PARTIALLY_DELETED"
    DELETING = "DELETING"


class NetworkOrigin(str):
    Internet = "Internet"
    VPC = "VPC"


class ObjectLambdaAllowedFeature(str):
    GetObject_Range = "GetObject-Range"
    GetObject_PartNumber = "GetObject-PartNumber"
    HeadObject_Range = "HeadObject-Range"
    HeadObject_PartNumber = "HeadObject-PartNumber"


class ObjectLambdaTransformationConfigurationAction(str):
    GetObject = "GetObject"
    HeadObject = "HeadObject"
    ListObjects = "ListObjects"
    ListObjectsV2 = "ListObjectsV2"


class OperationName(str):
    LambdaInvoke = "LambdaInvoke"
    S3PutObjectCopy = "S3PutObjectCopy"
    S3PutObjectAcl = "S3PutObjectAcl"
    S3PutObjectTagging = "S3PutObjectTagging"
    S3DeleteObjectTagging = "S3DeleteObjectTagging"
    S3InitiateRestoreObject = "S3InitiateRestoreObject"
    S3PutObjectLegalHold = "S3PutObjectLegalHold"
    S3PutObjectRetention = "S3PutObjectRetention"
    S3ReplicateObject = "S3ReplicateObject"


class OutputSchemaVersion(str):
    V_1 = "V_1"


class ReplicationStatus(str):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REPLICA = "REPLICA"
    NONE = "NONE"


class RequestedJobStatus(str):
    Cancelled = "Cancelled"
    Ready = "Ready"


class S3CannedAccessControlList(str):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    aws_exec_read = "aws-exec-read"
    authenticated_read = "authenticated-read"
    bucket_owner_read = "bucket-owner-read"
    bucket_owner_full_control = "bucket-owner-full-control"


class S3ChecksumAlgorithm(str):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    SHA1 = "SHA1"
    SHA256 = "SHA256"


class S3GlacierJobTier(str):
    BULK = "BULK"
    STANDARD = "STANDARD"


class S3GranteeTypeIdentifier(str):
    id = "id"
    emailAddress = "emailAddress"
    uri = "uri"


class S3MetadataDirective(str):
    COPY = "COPY"
    REPLACE = "REPLACE"


class S3ObjectLockLegalHoldStatus(str):
    OFF = "OFF"
    ON = "ON"


class S3ObjectLockMode(str):
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"


class S3ObjectLockRetentionMode(str):
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"


class S3Permission(str):
    FULL_CONTROL = "FULL_CONTROL"
    READ = "READ"
    WRITE = "WRITE"
    READ_ACP = "READ_ACP"
    WRITE_ACP = "WRITE_ACP"


class S3SSEAlgorithm(str):
    AES256 = "AES256"
    KMS = "KMS"


class S3StorageClass(str):
    STANDARD = "STANDARD"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    GLACIER = "GLACIER"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    GLACIER_IR = "GLACIER_IR"


class TransitionStorageClass(str):
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
    DaysAfterInitiation: Optional[DaysAfterInitiation]


class VpcConfiguration(TypedDict, total=False):
    VpcId: VpcId


class AccessPoint(TypedDict, total=False):
    Name: AccessPointName
    NetworkOrigin: NetworkOrigin
    VpcConfiguration: Optional[VpcConfiguration]
    Bucket: BucketName
    AccessPointArn: Optional[S3AccessPointArn]
    Alias: Optional[Alias]
    BucketAccountId: Optional[AccountId]


AccessPointList = List[AccessPoint]


class DetailedStatusCodesMetrics(TypedDict, total=False):
    IsEnabled: Optional[IsEnabled]


class AdvancedDataProtectionMetrics(TypedDict, total=False):
    IsEnabled: Optional[IsEnabled]


class AdvancedCostOptimizationMetrics(TypedDict, total=False):
    IsEnabled: Optional[IsEnabled]


class SelectionCriteria(TypedDict, total=False):
    Delimiter: Optional[StorageLensPrefixLevelDelimiter]
    MaxDepth: Optional[StorageLensPrefixLevelMaxDepth]
    MinStorageBytesPercentage: Optional[MinStorageBytesPercentage]


class PrefixLevelStorageMetrics(TypedDict, total=False):
    IsEnabled: Optional[IsEnabled]
    SelectionCriteria: Optional[SelectionCriteria]


class PrefixLevel(TypedDict, total=False):
    StorageMetrics: PrefixLevelStorageMetrics


class ActivityMetrics(TypedDict, total=False):
    IsEnabled: Optional[IsEnabled]


class BucketLevel(TypedDict, total=False):
    ActivityMetrics: Optional[ActivityMetrics]
    PrefixLevel: Optional[PrefixLevel]
    AdvancedCostOptimizationMetrics: Optional[AdvancedCostOptimizationMetrics]
    AdvancedDataProtectionMetrics: Optional[AdvancedDataProtectionMetrics]
    DetailedStatusCodesMetrics: Optional[DetailedStatusCodesMetrics]


class AccountLevel(TypedDict, total=False):
    ActivityMetrics: Optional[ActivityMetrics]
    BucketLevel: BucketLevel
    AdvancedCostOptimizationMetrics: Optional[AdvancedCostOptimizationMetrics]
    AdvancedDataProtectionMetrics: Optional[AdvancedDataProtectionMetrics]
    DetailedStatusCodesMetrics: Optional[DetailedStatusCodesMetrics]


AsyncCreationTimestamp = datetime


class AsyncErrorDetails(TypedDict, total=False):
    Code: Optional[MaxLength1024String]
    Message: Optional[MaxLength1024String]
    Resource: Optional[MaxLength1024String]
    RequestId: Optional[MaxLength1024String]


class MultiRegionAccessPointRegionalResponse(TypedDict, total=False):
    Name: Optional[RegionName]
    RequestStatus: Optional[AsyncRequestStatus]


MultiRegionAccessPointRegionalResponseList = List[MultiRegionAccessPointRegionalResponse]


class MultiRegionAccessPointsAsyncResponse(TypedDict, total=False):
    Regions: Optional[MultiRegionAccessPointRegionalResponseList]


class AsyncResponseDetails(TypedDict, total=False):
    MultiRegionAccessPointDetails: Optional[MultiRegionAccessPointsAsyncResponse]
    ErrorDetails: Optional[AsyncErrorDetails]


class PutMultiRegionAccessPointPolicyInput(TypedDict, total=False):
    Name: MultiRegionAccessPointName
    Policy: Policy


class DeleteMultiRegionAccessPointInput(TypedDict, total=False):
    Name: MultiRegionAccessPointName


class Region(TypedDict, total=False):
    Bucket: BucketName


RegionCreationList = List[Region]


class PublicAccessBlockConfiguration(TypedDict, total=False):
    BlockPublicAcls: Optional[Setting]
    IgnorePublicAcls: Optional[Setting]
    BlockPublicPolicy: Optional[Setting]
    RestrictPublicBuckets: Optional[Setting]


class CreateMultiRegionAccessPointInput(TypedDict, total=False):
    Name: MultiRegionAccessPointName
    PublicAccessBlock: Optional[PublicAccessBlockConfiguration]
    Regions: RegionCreationList


class AsyncRequestParameters(TypedDict, total=False):
    CreateMultiRegionAccessPointRequest: Optional[CreateMultiRegionAccessPointInput]
    DeleteMultiRegionAccessPointRequest: Optional[DeleteMultiRegionAccessPointInput]
    PutMultiRegionAccessPointPolicyRequest: Optional[PutMultiRegionAccessPointPolicyInput]


class AsyncOperation(TypedDict, total=False):
    CreationTime: Optional[AsyncCreationTimestamp]
    Operation: Optional[AsyncOperationName]
    RequestTokenARN: Optional[AsyncRequestTokenARN]
    RequestParameters: Optional[AsyncRequestParameters]
    RequestStatus: Optional[AsyncRequestStatus]
    ResponseDetails: Optional[AsyncResponseDetails]


class AwsLambdaTransformation(TypedDict, total=False):
    FunctionArn: FunctionArnString
    FunctionPayload: Optional[AwsLambdaTransformationPayload]


Buckets = List[S3BucketArnString]


class CloudWatchMetrics(TypedDict, total=False):
    IsEnabled: IsEnabled


class ObjectLambdaContentTransformation(TypedDict, total=False):
    AwsLambda: Optional[AwsLambdaTransformation]


ObjectLambdaTransformationConfigurationActionsList = List[
    ObjectLambdaTransformationConfigurationAction
]


class ObjectLambdaTransformationConfiguration(TypedDict, total=False):
    Actions: ObjectLambdaTransformationConfigurationActionsList
    ContentTransformation: ObjectLambdaContentTransformation


ObjectLambdaTransformationConfigurationsList = List[ObjectLambdaTransformationConfiguration]
ObjectLambdaAllowedFeaturesList = List[ObjectLambdaAllowedFeature]


class ObjectLambdaConfiguration(TypedDict, total=False):
    SupportingAccessPoint: ObjectLambdaSupportingAccessPointArn
    CloudWatchMetricsEnabled: Optional[Boolean]
    AllowedFeatures: Optional[ObjectLambdaAllowedFeaturesList]
    TransformationConfigurations: ObjectLambdaTransformationConfigurationsList


class CreateAccessPointForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName
    Configuration: ObjectLambdaConfiguration


class CreateAccessPointForObjectLambdaResult(TypedDict, total=False):
    ObjectLambdaAccessPointArn: Optional[ObjectLambdaAccessPointArn]


class CreateAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName
    Bucket: BucketName
    VpcConfiguration: Optional[VpcConfiguration]
    PublicAccessBlockConfiguration: Optional[PublicAccessBlockConfiguration]
    BucketAccountId: Optional[AccountId]


class CreateAccessPointResult(TypedDict, total=False):
    AccessPointArn: Optional[S3AccessPointArn]
    Alias: Optional[Alias]


class CreateBucketConfiguration(TypedDict, total=False):
    LocationConstraint: Optional[BucketLocationConstraint]


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
    OutpostId: Optional[NonEmptyMaxLength64String]


class CreateBucketResult(TypedDict, total=False):
    Location: Optional[Location]
    BucketArn: Optional[S3RegionalBucketArn]


ReplicationStatusFilterList = List[ReplicationStatus]
ObjectCreationTime = datetime


class JobManifestGeneratorFilter(TypedDict, total=False):
    EligibleForReplication: Optional[Boolean]
    CreatedAfter: Optional[ObjectCreationTime]
    CreatedBefore: Optional[ObjectCreationTime]
    ObjectReplicationStatuses: Optional[ReplicationStatusFilterList]


class SSEKMSEncryption(TypedDict, total=False):
    KeyId: KmsKeyArnString


class SSES3Encryption(TypedDict, total=False):
    pass


class GeneratedManifestEncryption(TypedDict, total=False):
    SSES3: Optional[SSES3Encryption]
    SSEKMS: Optional[SSEKMSEncryption]


class S3ManifestOutputLocation(TypedDict, total=False):
    ExpectedManifestBucketOwner: Optional[AccountId]
    Bucket: S3BucketArnString
    ManifestPrefix: Optional[ManifestPrefixString]
    ManifestEncryption: Optional[GeneratedManifestEncryption]
    ManifestFormat: GeneratedManifestFormat


class S3JobManifestGenerator(TypedDict, total=False):
    ExpectedBucketOwner: Optional[AccountId]
    SourceBucket: S3BucketArnString
    ManifestOutputLocation: Optional[S3ManifestOutputLocation]
    Filter: Optional[JobManifestGeneratorFilter]
    EnableManifestOutput: Boolean


class JobManifestGenerator(TypedDict, total=False):
    S3JobManifestGenerator: Optional[S3JobManifestGenerator]


class S3Tag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


S3TagSet = List[S3Tag]


class JobManifestLocation(TypedDict, total=False):
    ObjectArn: S3KeyArnString
    ObjectVersionId: Optional[S3ObjectVersionId]
    ETag: NonEmptyMaxLength1024String


JobManifestFieldList = List[JobManifestFieldName]


class JobManifestSpec(TypedDict, total=False):
    Format: JobManifestFormat
    Fields: Optional[JobManifestFieldList]


class JobManifest(TypedDict, total=False):
    Spec: JobManifestSpec
    Location: JobManifestLocation


class JobReport(TypedDict, total=False):
    Bucket: Optional[S3BucketArnString]
    Format: Optional[JobReportFormat]
    Enabled: Boolean
    Prefix: Optional[ReportPrefixString]
    ReportScope: Optional[JobReportScope]


class S3ReplicateObjectOperation(TypedDict, total=False):
    pass


TimeStamp = datetime


class S3Retention(TypedDict, total=False):
    RetainUntilDate: Optional[TimeStamp]
    Mode: Optional[S3ObjectLockRetentionMode]


class S3SetObjectRetentionOperation(TypedDict, total=False):
    BypassGovernanceRetention: Optional[Boolean]
    Retention: S3Retention


class S3ObjectLockLegalHold(TypedDict, total=False):
    Status: S3ObjectLockLegalHoldStatus


class S3SetObjectLegalHoldOperation(TypedDict, total=False):
    LegalHold: S3ObjectLockLegalHold


class S3InitiateRestoreObjectOperation(TypedDict, total=False):
    ExpirationInDays: Optional[S3ExpirationInDays]
    GlacierJobTier: Optional[S3GlacierJobTier]


class S3DeleteObjectTaggingOperation(TypedDict, total=False):
    pass


class S3SetObjectTaggingOperation(TypedDict, total=False):
    TagSet: Optional[S3TagSet]


class S3Grantee(TypedDict, total=False):
    TypeIdentifier: Optional[S3GranteeTypeIdentifier]
    Identifier: Optional[NonEmptyMaxLength1024String]
    DisplayName: Optional[NonEmptyMaxLength1024String]


class S3Grant(TypedDict, total=False):
    Grantee: Optional[S3Grantee]
    Permission: Optional[S3Permission]


S3GrantList = List[S3Grant]


class S3ObjectOwner(TypedDict, total=False):
    ID: Optional[NonEmptyMaxLength1024String]
    DisplayName: Optional[NonEmptyMaxLength1024String]


class S3AccessControlList(TypedDict, total=False):
    Owner: S3ObjectOwner
    Grants: Optional[S3GrantList]


class S3AccessControlPolicy(TypedDict, total=False):
    AccessControlList: Optional[S3AccessControlList]
    CannedAccessControlList: Optional[S3CannedAccessControlList]


class S3SetObjectAclOperation(TypedDict, total=False):
    AccessControlPolicy: Optional[S3AccessControlPolicy]


S3ContentLength = int
S3UserMetadata = Dict[NonEmptyMaxLength1024String, MaxLength1024String]


class S3ObjectMetadata(TypedDict, total=False):
    CacheControl: Optional[NonEmptyMaxLength1024String]
    ContentDisposition: Optional[NonEmptyMaxLength1024String]
    ContentEncoding: Optional[NonEmptyMaxLength1024String]
    ContentLanguage: Optional[NonEmptyMaxLength1024String]
    UserMetadata: Optional[S3UserMetadata]
    ContentLength: Optional[S3ContentLength]
    ContentMD5: Optional[NonEmptyMaxLength1024String]
    ContentType: Optional[NonEmptyMaxLength1024String]
    HttpExpiresDate: Optional[TimeStamp]
    RequesterCharged: Optional[Boolean]
    SSEAlgorithm: Optional[S3SSEAlgorithm]


class S3CopyObjectOperation(TypedDict, total=False):
    TargetResource: Optional[S3BucketArnString]
    CannedAccessControlList: Optional[S3CannedAccessControlList]
    AccessControlGrants: Optional[S3GrantList]
    MetadataDirective: Optional[S3MetadataDirective]
    ModifiedSinceConstraint: Optional[TimeStamp]
    NewObjectMetadata: Optional[S3ObjectMetadata]
    NewObjectTagging: Optional[S3TagSet]
    RedirectLocation: Optional[NonEmptyMaxLength2048String]
    RequesterPays: Optional[Boolean]
    StorageClass: Optional[S3StorageClass]
    UnModifiedSinceConstraint: Optional[TimeStamp]
    SSEAwsKmsKeyId: Optional[KmsKeyArnString]
    TargetKeyPrefix: Optional[NonEmptyMaxLength1024String]
    ObjectLockLegalHoldStatus: Optional[S3ObjectLockLegalHoldStatus]
    ObjectLockMode: Optional[S3ObjectLockMode]
    ObjectLockRetainUntilDate: Optional[TimeStamp]
    BucketKeyEnabled: Optional[Boolean]
    ChecksumAlgorithm: Optional[S3ChecksumAlgorithm]


class LambdaInvokeOperation(TypedDict, total=False):
    FunctionArn: Optional[FunctionArnString]


class JobOperation(TypedDict, total=False):
    LambdaInvoke: Optional[LambdaInvokeOperation]
    S3PutObjectCopy: Optional[S3CopyObjectOperation]
    S3PutObjectAcl: Optional[S3SetObjectAclOperation]
    S3PutObjectTagging: Optional[S3SetObjectTaggingOperation]
    S3DeleteObjectTagging: Optional[S3DeleteObjectTaggingOperation]
    S3InitiateRestoreObject: Optional[S3InitiateRestoreObjectOperation]
    S3PutObjectLegalHold: Optional[S3SetObjectLegalHoldOperation]
    S3PutObjectRetention: Optional[S3SetObjectRetentionOperation]
    S3ReplicateObject: Optional[S3ReplicateObjectOperation]


class CreateJobRequest(ServiceRequest):
    AccountId: AccountId
    ConfirmationRequired: Optional[ConfirmationRequired]
    Operation: JobOperation
    Report: JobReport
    ClientRequestToken: NonEmptyMaxLength64String
    Manifest: Optional[JobManifest]
    Description: Optional[NonEmptyMaxLength256String]
    Priority: JobPriority
    RoleArn: IAMRoleArn
    Tags: Optional[S3TagSet]
    ManifestGenerator: Optional[JobManifestGenerator]


class CreateJobResult(TypedDict, total=False):
    JobId: Optional[JobId]


class CreateMultiRegionAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    ClientToken: MultiRegionAccessPointClientToken
    Details: CreateMultiRegionAccessPointInput


class CreateMultiRegionAccessPointResult(TypedDict, total=False):
    RequestTokenARN: Optional[AsyncRequestTokenARN]


CreationDate = datetime
CreationTimestamp = datetime
Date = datetime


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


class DeleteBucketLifecycleConfigurationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class DeleteBucketPolicyRequest(ServiceRequest):
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


class DeleteMultiRegionAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    ClientToken: MultiRegionAccessPointClientToken
    Details: DeleteMultiRegionAccessPointInput


class DeleteMultiRegionAccessPointResult(TypedDict, total=False):
    RequestTokenARN: Optional[AsyncRequestTokenARN]


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


class DescribeJobRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId


class S3GeneratedManifestDescriptor(TypedDict, total=False):
    Format: Optional[GeneratedManifestFormat]
    Location: Optional[JobManifestLocation]


SuspendedDate = datetime
JobTerminationDate = datetime
JobCreationTime = datetime


class JobFailure(TypedDict, total=False):
    FailureCode: Optional[JobFailureCode]
    FailureReason: Optional[JobFailureReason]


JobFailureList = List[JobFailure]
JobTimeInStateSeconds = int


class JobTimers(TypedDict, total=False):
    ElapsedTimeInActiveSeconds: Optional[JobTimeInStateSeconds]


JobNumberOfTasksFailed = int
JobNumberOfTasksSucceeded = int
JobTotalNumberOfTasks = int


class JobProgressSummary(TypedDict, total=False):
    TotalNumberOfTasks: Optional[JobTotalNumberOfTasks]
    NumberOfTasksSucceeded: Optional[JobNumberOfTasksSucceeded]
    NumberOfTasksFailed: Optional[JobNumberOfTasksFailed]
    Timers: Optional[JobTimers]


class JobDescriptor(TypedDict, total=False):
    JobId: Optional[JobId]
    ConfirmationRequired: Optional[ConfirmationRequired]
    Description: Optional[NonEmptyMaxLength256String]
    JobArn: Optional[JobArn]
    Status: Optional[JobStatus]
    Manifest: Optional[JobManifest]
    Operation: Optional[JobOperation]
    Priority: Optional[JobPriority]
    ProgressSummary: Optional[JobProgressSummary]
    StatusUpdateReason: Optional[JobStatusUpdateReason]
    FailureReasons: Optional[JobFailureList]
    Report: Optional[JobReport]
    CreationTime: Optional[JobCreationTime]
    TerminationDate: Optional[JobTerminationDate]
    RoleArn: Optional[IAMRoleArn]
    SuspendedDate: Optional[SuspendedDate]
    SuspendedCause: Optional[SuspendedCause]
    ManifestGenerator: Optional[JobManifestGenerator]
    GeneratedManifestDescriptor: Optional[S3GeneratedManifestDescriptor]


class DescribeJobResult(TypedDict, total=False):
    Job: Optional[JobDescriptor]


class DescribeMultiRegionAccessPointOperationRequest(ServiceRequest):
    AccountId: AccountId
    RequestTokenARN: AsyncRequestTokenARN


class DescribeMultiRegionAccessPointOperationResult(TypedDict, total=False):
    AsyncOperation: Optional[AsyncOperation]


Endpoints = Dict[NonEmptyMaxLength64String, NonEmptyMaxLength1024String]


class EstablishedMultiRegionAccessPointPolicy(TypedDict, total=False):
    Policy: Optional[Policy]


Regions = List[S3AWSRegion]


class Exclude(TypedDict, total=False):
    Buckets: Optional[Buckets]
    Regions: Optional[Regions]


class GetAccessPointConfigurationForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class GetAccessPointConfigurationForObjectLambdaResult(TypedDict, total=False):
    Configuration: Optional[ObjectLambdaConfiguration]


class GetAccessPointForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class GetAccessPointForObjectLambdaResult(TypedDict, total=False):
    Name: Optional[ObjectLambdaAccessPointName]
    PublicAccessBlockConfiguration: Optional[PublicAccessBlockConfiguration]
    CreationDate: Optional[CreationDate]


class GetAccessPointPolicyForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class GetAccessPointPolicyForObjectLambdaResult(TypedDict, total=False):
    Policy: Optional[ObjectLambdaPolicy]


class GetAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointPolicyResult(TypedDict, total=False):
    Policy: Optional[Policy]


class GetAccessPointPolicyStatusForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    Name: ObjectLambdaAccessPointName


class PolicyStatus(TypedDict, total=False):
    IsPublic: Optional[IsPublic]


class GetAccessPointPolicyStatusForObjectLambdaResult(TypedDict, total=False):
    PolicyStatus: Optional[PolicyStatus]


class GetAccessPointPolicyStatusRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointPolicyStatusResult(TypedDict, total=False):
    PolicyStatus: Optional[PolicyStatus]


class GetAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: AccessPointName


class GetAccessPointResult(TypedDict, total=False):
    Name: Optional[AccessPointName]
    Bucket: Optional[BucketName]
    NetworkOrigin: Optional[NetworkOrigin]
    VpcConfiguration: Optional[VpcConfiguration]
    PublicAccessBlockConfiguration: Optional[PublicAccessBlockConfiguration]
    CreationDate: Optional[CreationDate]
    Alias: Optional[Alias]
    AccessPointArn: Optional[S3AccessPointArn]
    Endpoints: Optional[Endpoints]
    BucketAccountId: Optional[AccountId]


class GetBucketLifecycleConfigurationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class NoncurrentVersionExpiration(TypedDict, total=False):
    NoncurrentDays: Optional[Days]
    NewerNoncurrentVersions: Optional[NoncurrentVersionCount]


class NoncurrentVersionTransition(TypedDict, total=False):
    NoncurrentDays: Optional[Days]
    StorageClass: Optional[TransitionStorageClass]


NoncurrentVersionTransitionList = List[NoncurrentVersionTransition]


class Transition(TypedDict, total=False):
    Date: Optional[Date]
    Days: Optional[Days]
    StorageClass: Optional[TransitionStorageClass]


TransitionList = List[Transition]
ObjectSizeLessThanBytes = int
ObjectSizeGreaterThanBytes = int


class LifecycleRuleAndOperator(TypedDict, total=False):
    Prefix: Optional[Prefix]
    Tags: Optional[S3TagSet]
    ObjectSizeGreaterThan: Optional[ObjectSizeGreaterThanBytes]
    ObjectSizeLessThan: Optional[ObjectSizeLessThanBytes]


class LifecycleRuleFilter(TypedDict, total=False):
    Prefix: Optional[Prefix]
    Tag: Optional[S3Tag]
    And: Optional[LifecycleRuleAndOperator]
    ObjectSizeGreaterThan: Optional[ObjectSizeGreaterThanBytes]
    ObjectSizeLessThan: Optional[ObjectSizeLessThanBytes]


class LifecycleExpiration(TypedDict, total=False):
    Date: Optional[Date]
    Days: Optional[Days]
    ExpiredObjectDeleteMarker: Optional[ExpiredObjectDeleteMarker]


class LifecycleRule(TypedDict, total=False):
    Expiration: Optional[LifecycleExpiration]
    ID: Optional[ID]
    Filter: Optional[LifecycleRuleFilter]
    Status: ExpirationStatus
    Transitions: Optional[TransitionList]
    NoncurrentVersionTransitions: Optional[NoncurrentVersionTransitionList]
    NoncurrentVersionExpiration: Optional[NoncurrentVersionExpiration]
    AbortIncompleteMultipartUpload: Optional[AbortIncompleteMultipartUpload]


LifecycleRules = List[LifecycleRule]


class GetBucketLifecycleConfigurationResult(TypedDict, total=False):
    Rules: Optional[LifecycleRules]


class GetBucketPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketPolicyResult(TypedDict, total=False):
    Policy: Optional[Policy]


class GetBucketRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketResult(TypedDict, total=False):
    Bucket: Optional[BucketName]
    PublicAccessBlockEnabled: Optional[PublicAccessBlockEnabled]
    CreationDate: Optional[CreationDate]


class GetBucketTaggingRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketTaggingResult(TypedDict, total=False):
    TagSet: S3TagSet


class GetBucketVersioningRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName


class GetBucketVersioningResult(TypedDict, total=False):
    Status: Optional[BucketVersioningStatus]
    MFADelete: Optional[MFADeleteStatus]


class GetJobTaggingRequest(ServiceRequest):
    AccountId: AccountId
    JobId: JobId


class GetJobTaggingResult(TypedDict, total=False):
    Tags: Optional[S3TagSet]


class GetMultiRegionAccessPointPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Name: MultiRegionAccessPointName


class ProposedMultiRegionAccessPointPolicy(TypedDict, total=False):
    Policy: Optional[Policy]


class MultiRegionAccessPointPolicyDocument(TypedDict, total=False):
    Established: Optional[EstablishedMultiRegionAccessPointPolicy]
    Proposed: Optional[ProposedMultiRegionAccessPointPolicy]


class GetMultiRegionAccessPointPolicyResult(TypedDict, total=False):
    Policy: Optional[MultiRegionAccessPointPolicyDocument]


class GetMultiRegionAccessPointPolicyStatusRequest(ServiceRequest):
    AccountId: AccountId
    Name: MultiRegionAccessPointName


class GetMultiRegionAccessPointPolicyStatusResult(TypedDict, total=False):
    Established: Optional[PolicyStatus]


class GetMultiRegionAccessPointRequest(ServiceRequest):
    AccountId: AccountId
    Name: MultiRegionAccessPointName


class RegionReport(TypedDict, total=False):
    Bucket: Optional[BucketName]
    Region: Optional[RegionName]


RegionReportList = List[RegionReport]


class MultiRegionAccessPointReport(TypedDict, total=False):
    Name: Optional[MultiRegionAccessPointName]
    Alias: Optional[MultiRegionAccessPointAlias]
    CreatedAt: Optional[CreationTimestamp]
    PublicAccessBlock: Optional[PublicAccessBlockConfiguration]
    Status: Optional[MultiRegionAccessPointStatus]
    Regions: Optional[RegionReportList]


class GetMultiRegionAccessPointResult(TypedDict, total=False):
    AccessPoint: Optional[MultiRegionAccessPointReport]


class GetMultiRegionAccessPointRoutesRequest(ServiceRequest):
    AccountId: AccountId
    Mrap: MultiRegionAccessPointId


class MultiRegionAccessPointRoute(TypedDict, total=False):
    Bucket: Optional[BucketName]
    Region: Optional[RegionName]
    TrafficDialPercentage: TrafficDialPercentage


RouteList = List[MultiRegionAccessPointRoute]


class GetMultiRegionAccessPointRoutesResult(TypedDict, total=False):
    Mrap: Optional[MultiRegionAccessPointId]
    Routes: Optional[RouteList]


class GetPublicAccessBlockOutput(TypedDict, total=False):
    PublicAccessBlockConfiguration: Optional[PublicAccessBlockConfiguration]


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
    SSES3: Optional[SSES3]
    SSEKMS: Optional[SSEKMS]


class S3BucketDestination(TypedDict, total=False):
    Format: Format
    OutputSchemaVersion: OutputSchemaVersion
    AccountId: AccountId
    Arn: S3BucketArnString
    Prefix: Optional[Prefix]
    Encryption: Optional[StorageLensDataExportEncryption]


class StorageLensDataExport(TypedDict, total=False):
    S3BucketDestination: Optional[S3BucketDestination]
    CloudWatchMetrics: Optional[CloudWatchMetrics]


class Include(TypedDict, total=False):
    Buckets: Optional[Buckets]
    Regions: Optional[Regions]


class StorageLensConfiguration(TypedDict, total=False):
    Id: ConfigId
    AccountLevel: AccountLevel
    Include: Optional[Include]
    Exclude: Optional[Exclude]
    DataExport: Optional[StorageLensDataExport]
    IsEnabled: IsEnabled
    AwsOrg: Optional[StorageLensAwsOrg]
    StorageLensArn: Optional[StorageLensArn]


class GetStorageLensConfigurationResult(TypedDict, total=False):
    StorageLensConfiguration: Optional[StorageLensConfiguration]


class GetStorageLensConfigurationTaggingRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId


class StorageLensTag(TypedDict, total=False):
    Key: TagKeyString
    Value: TagValueString


StorageLensTags = List[StorageLensTag]


class GetStorageLensConfigurationTaggingResult(TypedDict, total=False):
    Tags: Optional[StorageLensTags]


class JobListDescriptor(TypedDict, total=False):
    JobId: Optional[JobId]
    Description: Optional[NonEmptyMaxLength256String]
    Operation: Optional[OperationName]
    Priority: Optional[JobPriority]
    Status: Optional[JobStatus]
    CreationTime: Optional[JobCreationTime]
    TerminationDate: Optional[JobTerminationDate]
    ProgressSummary: Optional[JobProgressSummary]


JobListDescriptorList = List[JobListDescriptor]
JobStatusList = List[JobStatus]


class LifecycleConfiguration(TypedDict, total=False):
    Rules: Optional[LifecycleRules]


class ListAccessPointsForObjectLambdaRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: Optional[NonEmptyMaxLength1024String]
    MaxResults: Optional[MaxResults]


class ObjectLambdaAccessPoint(TypedDict, total=False):
    Name: ObjectLambdaAccessPointName
    ObjectLambdaAccessPointArn: Optional[ObjectLambdaAccessPointArn]


ObjectLambdaAccessPointList = List[ObjectLambdaAccessPoint]


class ListAccessPointsForObjectLambdaResult(TypedDict, total=False):
    ObjectLambdaAccessPointList: Optional[ObjectLambdaAccessPointList]
    NextToken: Optional[NonEmptyMaxLength1024String]


class ListAccessPointsRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: Optional[BucketName]
    NextToken: Optional[NonEmptyMaxLength1024String]
    MaxResults: Optional[MaxResults]


class ListAccessPointsResult(TypedDict, total=False):
    AccessPointList: Optional[AccessPointList]
    NextToken: Optional[NonEmptyMaxLength1024String]


class ListJobsRequest(ServiceRequest):
    AccountId: AccountId
    JobStatuses: Optional[JobStatusList]
    NextToken: Optional[StringForNextToken]
    MaxResults: Optional[MaxResults]


class ListJobsResult(TypedDict, total=False):
    NextToken: Optional[StringForNextToken]
    Jobs: Optional[JobListDescriptorList]


class ListMultiRegionAccessPointsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: Optional[NonEmptyMaxLength1024String]
    MaxResults: Optional[MaxResults]


MultiRegionAccessPointReportList = List[MultiRegionAccessPointReport]


class ListMultiRegionAccessPointsResult(TypedDict, total=False):
    AccessPoints: Optional[MultiRegionAccessPointReportList]
    NextToken: Optional[NonEmptyMaxLength1024String]


class ListRegionalBucketsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: Optional[NonEmptyMaxLength1024String]
    MaxResults: Optional[MaxResults]
    OutpostId: Optional[NonEmptyMaxLength64String]


class RegionalBucket(TypedDict, total=False):
    Bucket: BucketName
    BucketArn: Optional[S3RegionalBucketArn]
    PublicAccessBlockEnabled: PublicAccessBlockEnabled
    CreationDate: CreationDate
    OutpostId: Optional[NonEmptyMaxLength64String]


RegionalBucketList = List[RegionalBucket]


class ListRegionalBucketsResult(TypedDict, total=False):
    RegionalBucketList: Optional[RegionalBucketList]
    NextToken: Optional[NonEmptyMaxLength1024String]


class ListStorageLensConfigurationEntry(TypedDict, total=False):
    Id: ConfigId
    StorageLensArn: StorageLensArn
    HomeRegion: S3AWSRegion
    IsEnabled: Optional[IsEnabled]


class ListStorageLensConfigurationsRequest(ServiceRequest):
    AccountId: AccountId
    NextToken: Optional[ContinuationToken]


StorageLensConfigurationList = List[ListStorageLensConfigurationEntry]


class ListStorageLensConfigurationsResult(TypedDict, total=False):
    NextToken: Optional[ContinuationToken]
    StorageLensConfigurationList: Optional[StorageLensConfigurationList]


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


class PutBucketLifecycleConfigurationRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    LifecycleConfiguration: Optional[LifecycleConfiguration]


class PutBucketPolicyRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    ConfirmRemoveSelfBucketAccess: Optional[ConfirmRemoveSelfBucketAccess]
    Policy: Policy


class Tagging(TypedDict, total=False):
    TagSet: S3TagSet


class PutBucketTaggingRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    Tagging: Tagging


class VersioningConfiguration(TypedDict, total=False):
    MFADelete: Optional[MFADelete]
    Status: Optional[BucketVersioningStatus]


class PutBucketVersioningRequest(ServiceRequest):
    AccountId: AccountId
    Bucket: BucketName
    MFA: Optional[MFA]
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
    RequestTokenARN: Optional[AsyncRequestTokenARN]


class PutPublicAccessBlockRequest(ServiceRequest):
    PublicAccessBlockConfiguration: PublicAccessBlockConfiguration
    AccountId: AccountId


class PutStorageLensConfigurationRequest(ServiceRequest):
    ConfigId: ConfigId
    AccountId: AccountId
    StorageLensConfiguration: StorageLensConfiguration
    Tags: Optional[StorageLensTags]


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
    StatusUpdateReason: Optional[JobStatusUpdateReason]


class UpdateJobStatusResult(TypedDict, total=False):
    JobId: Optional[JobId]
    Status: Optional[JobStatus]
    StatusUpdateReason: Optional[JobStatusUpdateReason]


class S3ControlApi:

    service = "s3control"
    version = "2018-08-20"

    @handler("CreateAccessPoint")
    def create_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: AccessPointName,
        bucket: BucketName,
        vpc_configuration: VpcConfiguration = None,
        public_access_block_configuration: PublicAccessBlockConfiguration = None,
        bucket_account_id: AccountId = None,
    ) -> CreateAccessPointResult:
        raise NotImplementedError

    @handler("CreateAccessPointForObjectLambda")
    def create_access_point_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        configuration: ObjectLambdaConfiguration,
    ) -> CreateAccessPointForObjectLambdaResult:
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
        outpost_id: NonEmptyMaxLength64String = None,
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
        confirmation_required: ConfirmationRequired = None,
        manifest: JobManifest = None,
        description: NonEmptyMaxLength256String = None,
        tags: S3TagSet = None,
        manifest_generator: JobManifestGenerator = None,
    ) -> CreateJobResult:
        raise NotImplementedError

    @handler("CreateMultiRegionAccessPoint")
    def create_multi_region_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        client_token: MultiRegionAccessPointClientToken,
        details: CreateMultiRegionAccessPointInput,
    ) -> CreateMultiRegionAccessPointResult:
        raise NotImplementedError

    @handler("DeleteAccessPoint")
    def delete_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointForObjectLambda")
    def delete_access_point_for_object_lambda(
        self, context: RequestContext, account_id: AccountId, name: ObjectLambdaAccessPointName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointPolicy")
    def delete_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPointPolicyForObjectLambda")
    def delete_access_point_policy_for_object_lambda(
        self, context: RequestContext, account_id: AccountId, name: ObjectLambdaAccessPointName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucket")
    def delete_bucket(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketLifecycleConfiguration")
    def delete_bucket_lifecycle_configuration(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketPolicy")
    def delete_bucket_policy(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteBucketTagging")
    def delete_bucket_tagging(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteJobTagging")
    def delete_job_tagging(
        self, context: RequestContext, account_id: AccountId, job_id: JobId
    ) -> DeleteJobTaggingResult:
        raise NotImplementedError

    @handler("DeleteMultiRegionAccessPoint")
    def delete_multi_region_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        client_token: MultiRegionAccessPointClientToken,
        details: DeleteMultiRegionAccessPointInput,
    ) -> DeleteMultiRegionAccessPointResult:
        raise NotImplementedError

    @handler("DeletePublicAccessBlock")
    def delete_public_access_block(self, context: RequestContext, account_id: AccountId) -> None:
        raise NotImplementedError

    @handler("DeleteStorageLensConfiguration")
    def delete_storage_lens_configuration(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStorageLensConfigurationTagging")
    def delete_storage_lens_configuration_tagging(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId
    ) -> DeleteStorageLensConfigurationTaggingResult:
        raise NotImplementedError

    @handler("DescribeJob")
    def describe_job(
        self, context: RequestContext, account_id: AccountId, job_id: JobId
    ) -> DescribeJobResult:
        raise NotImplementedError

    @handler("DescribeMultiRegionAccessPointOperation")
    def describe_multi_region_access_point_operation(
        self,
        context: RequestContext,
        account_id: AccountId,
        request_token_arn: AsyncRequestTokenARN,
    ) -> DescribeMultiRegionAccessPointOperationResult:
        raise NotImplementedError

    @handler("GetAccessPoint")
    def get_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointResult:
        raise NotImplementedError

    @handler("GetAccessPointConfigurationForObjectLambda")
    def get_access_point_configuration_for_object_lambda(
        self, context: RequestContext, account_id: AccountId, name: ObjectLambdaAccessPointName
    ) -> GetAccessPointConfigurationForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointForObjectLambda")
    def get_access_point_for_object_lambda(
        self, context: RequestContext, account_id: AccountId, name: ObjectLambdaAccessPointName
    ) -> GetAccessPointForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicy")
    def get_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointPolicyResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicyForObjectLambda")
    def get_access_point_policy_for_object_lambda(
        self, context: RequestContext, account_id: AccountId, name: ObjectLambdaAccessPointName
    ) -> GetAccessPointPolicyForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicyStatus")
    def get_access_point_policy_status(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointPolicyStatusResult:
        raise NotImplementedError

    @handler("GetAccessPointPolicyStatusForObjectLambda")
    def get_access_point_policy_status_for_object_lambda(
        self, context: RequestContext, account_id: AccountId, name: ObjectLambdaAccessPointName
    ) -> GetAccessPointPolicyStatusForObjectLambdaResult:
        raise NotImplementedError

    @handler("GetBucket")
    def get_bucket(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> GetBucketResult:
        raise NotImplementedError

    @handler("GetBucketLifecycleConfiguration")
    def get_bucket_lifecycle_configuration(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> GetBucketLifecycleConfigurationResult:
        raise NotImplementedError

    @handler("GetBucketPolicy")
    def get_bucket_policy(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> GetBucketPolicyResult:
        raise NotImplementedError

    @handler("GetBucketTagging")
    def get_bucket_tagging(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> GetBucketTaggingResult:
        raise NotImplementedError

    @handler("GetBucketVersioning")
    def get_bucket_versioning(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName
    ) -> GetBucketVersioningResult:
        raise NotImplementedError

    @handler("GetJobTagging")
    def get_job_tagging(
        self, context: RequestContext, account_id: AccountId, job_id: JobId
    ) -> GetJobTaggingResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPoint")
    def get_multi_region_access_point(
        self, context: RequestContext, account_id: AccountId, name: MultiRegionAccessPointName
    ) -> GetMultiRegionAccessPointResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPointPolicy")
    def get_multi_region_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: MultiRegionAccessPointName
    ) -> GetMultiRegionAccessPointPolicyResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPointPolicyStatus")
    def get_multi_region_access_point_policy_status(
        self, context: RequestContext, account_id: AccountId, name: MultiRegionAccessPointName
    ) -> GetMultiRegionAccessPointPolicyStatusResult:
        raise NotImplementedError

    @handler("GetMultiRegionAccessPointRoutes")
    def get_multi_region_access_point_routes(
        self, context: RequestContext, account_id: AccountId, mrap: MultiRegionAccessPointId
    ) -> GetMultiRegionAccessPointRoutesResult:
        raise NotImplementedError

    @handler("GetPublicAccessBlock")
    def get_public_access_block(
        self, context: RequestContext, account_id: AccountId
    ) -> GetPublicAccessBlockOutput:
        raise NotImplementedError

    @handler("GetStorageLensConfiguration")
    def get_storage_lens_configuration(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId
    ) -> GetStorageLensConfigurationResult:
        raise NotImplementedError

    @handler("GetStorageLensConfigurationTagging")
    def get_storage_lens_configuration_tagging(
        self, context: RequestContext, config_id: ConfigId, account_id: AccountId
    ) -> GetStorageLensConfigurationTaggingResult:
        raise NotImplementedError

    @handler("ListAccessPoints")
    def list_access_points(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName = None,
        next_token: NonEmptyMaxLength1024String = None,
        max_results: MaxResults = None,
    ) -> ListAccessPointsResult:
        raise NotImplementedError

    @handler("ListAccessPointsForObjectLambda")
    def list_access_points_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NonEmptyMaxLength1024String = None,
        max_results: MaxResults = None,
    ) -> ListAccessPointsForObjectLambdaResult:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        account_id: AccountId,
        job_statuses: JobStatusList = None,
        next_token: StringForNextToken = None,
        max_results: MaxResults = None,
    ) -> ListJobsResult:
        raise NotImplementedError

    @handler("ListMultiRegionAccessPoints")
    def list_multi_region_access_points(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NonEmptyMaxLength1024String = None,
        max_results: MaxResults = None,
    ) -> ListMultiRegionAccessPointsResult:
        raise NotImplementedError

    @handler("ListRegionalBuckets")
    def list_regional_buckets(
        self,
        context: RequestContext,
        account_id: AccountId,
        next_token: NonEmptyMaxLength1024String = None,
        max_results: MaxResults = None,
        outpost_id: NonEmptyMaxLength64String = None,
    ) -> ListRegionalBucketsResult:
        raise NotImplementedError

    @handler("ListStorageLensConfigurations")
    def list_storage_lens_configurations(
        self, context: RequestContext, account_id: AccountId, next_token: ContinuationToken = None
    ) -> ListStorageLensConfigurationsResult:
        raise NotImplementedError

    @handler("PutAccessPointConfigurationForObjectLambda")
    def put_access_point_configuration_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        configuration: ObjectLambdaConfiguration,
    ) -> None:
        raise NotImplementedError

    @handler("PutAccessPointPolicy")
    def put_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, policy: Policy
    ) -> None:
        raise NotImplementedError

    @handler("PutAccessPointPolicyForObjectLambda")
    def put_access_point_policy_for_object_lambda(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: ObjectLambdaAccessPointName,
        policy: ObjectLambdaPolicy,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketLifecycleConfiguration")
    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        lifecycle_configuration: LifecycleConfiguration = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketPolicy")
    def put_bucket_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        policy: Policy,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketTagging")
    def put_bucket_tagging(
        self, context: RequestContext, account_id: AccountId, bucket: BucketName, tagging: Tagging
    ) -> None:
        raise NotImplementedError

    @handler("PutBucketVersioning")
    def put_bucket_versioning(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName,
        versioning_configuration: VersioningConfiguration,
        mfa: MFA = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutJobTagging")
    def put_job_tagging(
        self, context: RequestContext, account_id: AccountId, job_id: JobId, tags: S3TagSet
    ) -> PutJobTaggingResult:
        raise NotImplementedError

    @handler("PutMultiRegionAccessPointPolicy")
    def put_multi_region_access_point_policy(
        self,
        context: RequestContext,
        account_id: AccountId,
        client_token: MultiRegionAccessPointClientToken,
        details: PutMultiRegionAccessPointPolicyInput,
    ) -> PutMultiRegionAccessPointPolicyResult:
        raise NotImplementedError

    @handler("PutPublicAccessBlock")
    def put_public_access_block(
        self,
        context: RequestContext,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        account_id: AccountId,
    ) -> None:
        raise NotImplementedError

    @handler("PutStorageLensConfiguration")
    def put_storage_lens_configuration(
        self,
        context: RequestContext,
        config_id: ConfigId,
        account_id: AccountId,
        storage_lens_configuration: StorageLensConfiguration,
        tags: StorageLensTags = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutStorageLensConfigurationTagging")
    def put_storage_lens_configuration_tagging(
        self,
        context: RequestContext,
        config_id: ConfigId,
        account_id: AccountId,
        tags: StorageLensTags,
    ) -> PutStorageLensConfigurationTaggingResult:
        raise NotImplementedError

    @handler("SubmitMultiRegionAccessPointRoutes")
    def submit_multi_region_access_point_routes(
        self,
        context: RequestContext,
        account_id: AccountId,
        mrap: MultiRegionAccessPointId,
        route_updates: RouteList,
    ) -> SubmitMultiRegionAccessPointRoutesResult:
        raise NotImplementedError

    @handler("UpdateJobPriority")
    def update_job_priority(
        self, context: RequestContext, account_id: AccountId, job_id: JobId, priority: JobPriority
    ) -> UpdateJobPriorityResult:
        raise NotImplementedError

    @handler("UpdateJobStatus")
    def update_job_status(
        self,
        context: RequestContext,
        account_id: AccountId,
        job_id: JobId,
        requested_job_status: RequestedJobStatus,
        status_update_reason: JobStatusUpdateReason = None,
    ) -> UpdateJobStatusResult:
        raise NotImplementedError
