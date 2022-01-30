import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arch = str
Arn = str
AttributeKey = str
AttributeValue = str
Author = str
Base64 = str
BaseScore = float
BatchedOperationLayerDigest = str
Epoch = int
ExceptionMessage = str
FilePath = str
FindingArn = str
FindingDescription = str
FindingName = str
ForceFlag = bool
ImageCount = int
ImageDigest = str
ImageFailureReason = str
ImageManifest = str
ImageTag = str
KmsError = str
KmsKey = str
LayerDigest = str
LayerFailureReason = str
LifecyclePolicyRulePriority = int
LifecyclePolicyText = str
LifecyclePreviewMaxResults = int
MaxResults = int
MediaType = str
Metric = str
NextToken = str
PackageManager = str
Platform = str
ProxyEndpoint = str
PullThroughCacheRuleRepositoryPrefix = str
Reason = str
RecommendationText = str
Region = str
RegistryId = str
RegistryPolicyText = str
RelatedVulnerability = str
Release = str
ReplicationError = str
RepositoryFilterValue = str
RepositoryName = str
RepositoryPolicyText = str
ResourceId = str
ScanOnPushFlag = bool
ScanStatusDescription = str
ScanningConfigurationFailureReason = str
ScanningRepositoryFilterValue = str
Score = float
ScoringVector = str
Severity = str
SeverityCount = int
Source = str
SourceLayerHash = str
Status = str
TagKey = str
TagValue = str
Title = str
Type = str
UploadId = str
Url = str
Version = str
VulnerabilityId = str
VulnerablePackageName = str


class EncryptionType(str):
    AES256 = "AES256"
    KMS = "KMS"


class FindingSeverity(str):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNDEFINED = "UNDEFINED"


class ImageActionType(str):
    EXPIRE = "EXPIRE"


class ImageFailureCode(str):
    InvalidImageDigest = "InvalidImageDigest"
    InvalidImageTag = "InvalidImageTag"
    ImageTagDoesNotMatchDigest = "ImageTagDoesNotMatchDigest"
    ImageNotFound = "ImageNotFound"
    MissingDigestAndTag = "MissingDigestAndTag"
    ImageReferencedByManifestList = "ImageReferencedByManifestList"
    KmsError = "KmsError"


class ImageTagMutability(str):
    MUTABLE = "MUTABLE"
    IMMUTABLE = "IMMUTABLE"


class LayerAvailability(str):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class LayerFailureCode(str):
    InvalidLayerDigest = "InvalidLayerDigest"
    MissingLayerDigest = "MissingLayerDigest"


class LifecyclePolicyPreviewStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class ReplicationStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class RepositoryFilterType(str):
    PREFIX_MATCH = "PREFIX_MATCH"


class ScanFrequency(str):
    SCAN_ON_PUSH = "SCAN_ON_PUSH"
    CONTINUOUS_SCAN = "CONTINUOUS_SCAN"
    MANUAL = "MANUAL"


class ScanStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    UNSUPPORTED_IMAGE = "UNSUPPORTED_IMAGE"
    ACTIVE = "ACTIVE"
    PENDING = "PENDING"
    SCAN_ELIGIBILITY_EXPIRED = "SCAN_ELIGIBILITY_EXPIRED"
    FINDINGS_UNAVAILABLE = "FINDINGS_UNAVAILABLE"


class ScanType(str):
    BASIC = "BASIC"
    ENHANCED = "ENHANCED"


class ScanningConfigurationFailureCode(str):
    REPOSITORY_NOT_FOUND = "REPOSITORY_NOT_FOUND"


class ScanningRepositoryFilterType(str):
    WILDCARD = "WILDCARD"


class TagStatus(str):
    TAGGED = "TAGGED"
    UNTAGGED = "UNTAGGED"
    ANY = "ANY"


class EmptyUploadException(ServiceException):
    message: Optional[ExceptionMessage]


class ImageAlreadyExistsException(ServiceException):
    message: Optional[ExceptionMessage]


class ImageDigestDoesNotMatchException(ServiceException):
    message: Optional[ExceptionMessage]


class ImageNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class ImageTagAlreadyExistsException(ServiceException):
    message: Optional[ExceptionMessage]


class InvalidLayerException(ServiceException):
    message: Optional[ExceptionMessage]


PartSize = int


class InvalidLayerPartException(ServiceException):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    uploadId: Optional[UploadId]
    lastValidByteReceived: Optional[PartSize]
    message: Optional[ExceptionMessage]


class InvalidParameterException(ServiceException):
    message: Optional[ExceptionMessage]


class InvalidTagParameterException(ServiceException):
    message: Optional[ExceptionMessage]


class KmsException(ServiceException):
    message: Optional[ExceptionMessage]
    kmsError: Optional[KmsError]


class LayerAlreadyExistsException(ServiceException):
    message: Optional[ExceptionMessage]


class LayerInaccessibleException(ServiceException):
    message: Optional[ExceptionMessage]


class LayerPartTooSmallException(ServiceException):
    message: Optional[ExceptionMessage]


class LayersNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class LifecyclePolicyNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class LifecyclePolicyPreviewInProgressException(ServiceException):
    message: Optional[ExceptionMessage]


class LifecyclePolicyPreviewNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class LimitExceededException(ServiceException):
    message: Optional[ExceptionMessage]


class PullThroughCacheRuleAlreadyExistsException(ServiceException):
    message: Optional[ExceptionMessage]


class PullThroughCacheRuleNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class ReferencedImagesNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class RegistryPolicyNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class RepositoryAlreadyExistsException(ServiceException):
    message: Optional[ExceptionMessage]


class RepositoryNotEmptyException(ServiceException):
    message: Optional[ExceptionMessage]


class RepositoryNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class RepositoryPolicyNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class ScanNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class ServerException(ServiceException):
    message: Optional[ExceptionMessage]


class TooManyTagsException(ServiceException):
    message: Optional[ExceptionMessage]


class UnsupportedImageTypeException(ServiceException):
    message: Optional[ExceptionMessage]


class UnsupportedUpstreamRegistryException(ServiceException):
    message: Optional[ExceptionMessage]


class UploadNotFoundException(ServiceException):
    message: Optional[ExceptionMessage]


class ValidationException(ServiceException):
    message: Optional[ExceptionMessage]


class Attribute(TypedDict, total=False):
    key: AttributeKey
    value: Optional[AttributeValue]


AttributeList = List[Attribute]
ExpirationTimestamp = datetime


class AuthorizationData(TypedDict, total=False):
    authorizationToken: Optional[Base64]
    expiresAt: Optional[ExpirationTimestamp]
    proxyEndpoint: Optional[ProxyEndpoint]


AuthorizationDataList = List[AuthorizationData]
Date = datetime
ImageTagsList = List[ImageTag]


class AwsEcrContainerImageDetails(TypedDict, total=False):
    architecture: Optional[Arch]
    author: Optional[Author]
    imageHash: Optional[ImageDigest]
    imageTags: Optional[ImageTagsList]
    platform: Optional[Platform]
    pushedAt: Optional[Date]
    registry: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]


BatchedOperationLayerDigestList = List[BatchedOperationLayerDigest]


class BatchCheckLayerAvailabilityRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    layerDigests: BatchedOperationLayerDigestList


class LayerFailure(TypedDict, total=False):
    layerDigest: Optional[BatchedOperationLayerDigest]
    failureCode: Optional[LayerFailureCode]
    failureReason: Optional[LayerFailureReason]


LayerFailureList = List[LayerFailure]
LayerSizeInBytes = int


class Layer(TypedDict, total=False):
    layerDigest: Optional[LayerDigest]
    layerAvailability: Optional[LayerAvailability]
    layerSize: Optional[LayerSizeInBytes]
    mediaType: Optional[MediaType]


LayerList = List[Layer]


class BatchCheckLayerAvailabilityResponse(TypedDict, total=False):
    layers: Optional[LayerList]
    failures: Optional[LayerFailureList]


class ImageIdentifier(TypedDict, total=False):
    imageDigest: Optional[ImageDigest]
    imageTag: Optional[ImageTag]


ImageIdentifierList = List[ImageIdentifier]


class BatchDeleteImageRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageIds: ImageIdentifierList


class ImageFailure(TypedDict, total=False):
    imageId: Optional[ImageIdentifier]
    failureCode: Optional[ImageFailureCode]
    failureReason: Optional[ImageFailureReason]


ImageFailureList = List[ImageFailure]


class BatchDeleteImageResponse(TypedDict, total=False):
    imageIds: Optional[ImageIdentifierList]
    failures: Optional[ImageFailureList]


MediaTypeList = List[MediaType]


class BatchGetImageRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageIds: ImageIdentifierList
    acceptedMediaTypes: Optional[MediaTypeList]


class Image(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    imageId: Optional[ImageIdentifier]
    imageManifest: Optional[ImageManifest]
    imageManifestMediaType: Optional[MediaType]


ImageList = List[Image]


class BatchGetImageResponse(TypedDict, total=False):
    images: Optional[ImageList]
    failures: Optional[ImageFailureList]


ScanningConfigurationRepositoryNameList = List[RepositoryName]


class BatchGetRepositoryScanningConfigurationRequest(ServiceRequest):
    repositoryNames: ScanningConfigurationRepositoryNameList


class RepositoryScanningConfigurationFailure(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    failureCode: Optional[ScanningConfigurationFailureCode]
    failureReason: Optional[ScanningConfigurationFailureReason]


RepositoryScanningConfigurationFailureList = List[RepositoryScanningConfigurationFailure]


class ScanningRepositoryFilter(TypedDict, total=False):
    filter: ScanningRepositoryFilterValue
    filterType: ScanningRepositoryFilterType


ScanningRepositoryFilterList = List[ScanningRepositoryFilter]


class RepositoryScanningConfiguration(TypedDict, total=False):
    repositoryArn: Optional[Arn]
    repositoryName: Optional[RepositoryName]
    scanOnPush: Optional[ScanOnPushFlag]
    scanFrequency: Optional[ScanFrequency]
    appliedScanFilters: Optional[ScanningRepositoryFilterList]


RepositoryScanningConfigurationList = List[RepositoryScanningConfiguration]


class BatchGetRepositoryScanningConfigurationResponse(TypedDict, total=False):
    scanningConfigurations: Optional[RepositoryScanningConfigurationList]
    failures: Optional[RepositoryScanningConfigurationFailureList]


LayerDigestList = List[LayerDigest]


class CompleteLayerUploadRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    uploadId: UploadId
    layerDigests: LayerDigestList


class CompleteLayerUploadResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    uploadId: Optional[UploadId]
    layerDigest: Optional[LayerDigest]


class CreatePullThroughCacheRuleRequest(ServiceRequest):
    ecrRepositoryPrefix: PullThroughCacheRuleRepositoryPrefix
    upstreamRegistryUrl: Url
    registryId: Optional[RegistryId]


CreationTimestamp = datetime


class CreatePullThroughCacheRuleResponse(TypedDict, total=False):
    ecrRepositoryPrefix: Optional[PullThroughCacheRuleRepositoryPrefix]
    upstreamRegistryUrl: Optional[Url]
    createdAt: Optional[CreationTimestamp]
    registryId: Optional[RegistryId]


class EncryptionConfiguration(TypedDict, total=False):
    encryptionType: EncryptionType
    kmsKey: Optional[KmsKey]


class ImageScanningConfiguration(TypedDict, total=False):
    scanOnPush: Optional[ScanOnPushFlag]


class Tag(TypedDict, total=False):
    Key: Optional[TagKey]
    Value: Optional[TagValue]


TagList = List[Tag]


class CreateRepositoryRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    tags: Optional[TagList]
    imageTagMutability: Optional[ImageTagMutability]
    imageScanningConfiguration: Optional[ImageScanningConfiguration]
    encryptionConfiguration: Optional[EncryptionConfiguration]


class Repository(TypedDict, total=False):
    repositoryArn: Optional[Arn]
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    repositoryUri: Optional[Url]
    createdAt: Optional[CreationTimestamp]
    imageTagMutability: Optional[ImageTagMutability]
    imageScanningConfiguration: Optional[ImageScanningConfiguration]
    encryptionConfiguration: Optional[EncryptionConfiguration]


class CreateRepositoryResponse(TypedDict, total=False):
    repository: Optional[Repository]


class CvssScore(TypedDict, total=False):
    baseScore: Optional[BaseScore]
    scoringVector: Optional[ScoringVector]
    source: Optional[Source]
    version: Optional[Version]


class CvssScoreAdjustment(TypedDict, total=False):
    metric: Optional[Metric]
    reason: Optional[Reason]


CvssScoreAdjustmentList = List[CvssScoreAdjustment]


class CvssScoreDetails(TypedDict, total=False):
    adjustments: Optional[CvssScoreAdjustmentList]
    score: Optional[Score]
    scoreSource: Optional[Source]
    scoringVector: Optional[ScoringVector]
    version: Optional[Version]


CvssScoreList = List[CvssScore]


class DeleteLifecyclePolicyRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName


EvaluationTimestamp = datetime


class DeleteLifecyclePolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    lifecyclePolicyText: Optional[LifecyclePolicyText]
    lastEvaluatedAt: Optional[EvaluationTimestamp]


class DeletePullThroughCacheRuleRequest(ServiceRequest):
    ecrRepositoryPrefix: PullThroughCacheRuleRepositoryPrefix
    registryId: Optional[RegistryId]


class DeletePullThroughCacheRuleResponse(TypedDict, total=False):
    ecrRepositoryPrefix: Optional[PullThroughCacheRuleRepositoryPrefix]
    upstreamRegistryUrl: Optional[Url]
    createdAt: Optional[CreationTimestamp]
    registryId: Optional[RegistryId]


class DeleteRegistryPolicyRequest(ServiceRequest):
    pass


class DeleteRegistryPolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    policyText: Optional[RegistryPolicyText]


class DeleteRepositoryPolicyRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName


class DeleteRepositoryPolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    policyText: Optional[RepositoryPolicyText]


class DeleteRepositoryRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    force: Optional[ForceFlag]


class DeleteRepositoryResponse(TypedDict, total=False):
    repository: Optional[Repository]


class DescribeImageReplicationStatusRequest(ServiceRequest):
    repositoryName: RepositoryName
    imageId: ImageIdentifier
    registryId: Optional[RegistryId]


class ImageReplicationStatus(TypedDict, total=False):
    region: Optional[Region]
    registryId: Optional[RegistryId]
    status: Optional[ReplicationStatus]
    failureCode: Optional[ReplicationError]


ImageReplicationStatusList = List[ImageReplicationStatus]


class DescribeImageReplicationStatusResponse(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    imageId: Optional[ImageIdentifier]
    replicationStatuses: Optional[ImageReplicationStatusList]


class DescribeImageScanFindingsRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageId: ImageIdentifier
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ScoreDetails(TypedDict, total=False):
    cvss: Optional[CvssScoreDetails]


Tags = Dict[TagKey, TagValue]


class ResourceDetails(TypedDict, total=False):
    awsEcrContainerImage: Optional[AwsEcrContainerImageDetails]


Resource = TypedDict(
    "Resource",
    {
        "details": Optional[ResourceDetails],
        "id": Optional[ResourceId],
        "tags": Optional[Tags],
        "type": Optional[Type],
    },
    total=False,
)
ResourceList = List[Resource]


class Recommendation(TypedDict, total=False):
    url: Optional[Url]
    text: Optional[RecommendationText]


class Remediation(TypedDict, total=False):
    recommendation: Optional[Recommendation]


class VulnerablePackage(TypedDict, total=False):
    arch: Optional[Arch]
    epoch: Optional[Epoch]
    filePath: Optional[FilePath]
    name: Optional[VulnerablePackageName]
    packageManager: Optional[PackageManager]
    release: Optional[Release]
    sourceLayerHash: Optional[SourceLayerHash]
    version: Optional[Version]


VulnerablePackagesList = List[VulnerablePackage]
RelatedVulnerabilitiesList = List[RelatedVulnerability]
ReferenceUrlsList = List[Url]


class PackageVulnerabilityDetails(TypedDict, total=False):
    cvss: Optional[CvssScoreList]
    referenceUrls: Optional[ReferenceUrlsList]
    relatedVulnerabilities: Optional[RelatedVulnerabilitiesList]
    source: Optional[Source]
    sourceUrl: Optional[Url]
    vendorCreatedAt: Optional[Date]
    vendorSeverity: Optional[Severity]
    vendorUpdatedAt: Optional[Date]
    vulnerabilityId: Optional[VulnerabilityId]
    vulnerablePackages: Optional[VulnerablePackagesList]


EnhancedImageScanFinding = TypedDict(
    "EnhancedImageScanFinding",
    {
        "awsAccountId": Optional[RegistryId],
        "description": Optional[FindingDescription],
        "findingArn": Optional[FindingArn],
        "firstObservedAt": Optional[Date],
        "lastObservedAt": Optional[Date],
        "packageVulnerabilityDetails": Optional[PackageVulnerabilityDetails],
        "remediation": Optional[Remediation],
        "resources": Optional[ResourceList],
        "score": Optional[Score],
        "scoreDetails": Optional[ScoreDetails],
        "severity": Optional[Severity],
        "status": Optional[Status],
        "title": Optional[Title],
        "type": Optional[Type],
        "updatedAt": Optional[Date],
    },
    total=False,
)
EnhancedImageScanFindingList = List[EnhancedImageScanFinding]


class ImageScanFinding(TypedDict, total=False):
    name: Optional[FindingName]
    description: Optional[FindingDescription]
    uri: Optional[Url]
    severity: Optional[FindingSeverity]
    attributes: Optional[AttributeList]


ImageScanFindingList = List[ImageScanFinding]
FindingSeverityCounts = Dict[FindingSeverity, SeverityCount]
VulnerabilitySourceUpdateTimestamp = datetime
ScanTimestamp = datetime


class ImageScanFindings(TypedDict, total=False):
    imageScanCompletedAt: Optional[ScanTimestamp]
    vulnerabilitySourceUpdatedAt: Optional[VulnerabilitySourceUpdateTimestamp]
    findingSeverityCounts: Optional[FindingSeverityCounts]
    findings: Optional[ImageScanFindingList]
    enhancedFindings: Optional[EnhancedImageScanFindingList]


class ImageScanStatus(TypedDict, total=False):
    status: Optional[ScanStatus]
    description: Optional[ScanStatusDescription]


class DescribeImageScanFindingsResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    imageId: Optional[ImageIdentifier]
    imageScanStatus: Optional[ImageScanStatus]
    imageScanFindings: Optional[ImageScanFindings]
    nextToken: Optional[NextToken]


class DescribeImagesFilter(TypedDict, total=False):
    tagStatus: Optional[TagStatus]


class DescribeImagesRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageIds: Optional[ImageIdentifierList]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]
    filter: Optional[DescribeImagesFilter]


RecordedPullTimestamp = datetime


class ImageScanFindingsSummary(TypedDict, total=False):
    imageScanCompletedAt: Optional[ScanTimestamp]
    vulnerabilitySourceUpdatedAt: Optional[VulnerabilitySourceUpdateTimestamp]
    findingSeverityCounts: Optional[FindingSeverityCounts]


PushTimestamp = datetime
ImageSizeInBytes = int
ImageTagList = List[ImageTag]


class ImageDetail(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    imageDigest: Optional[ImageDigest]
    imageTags: Optional[ImageTagList]
    imageSizeInBytes: Optional[ImageSizeInBytes]
    imagePushedAt: Optional[PushTimestamp]
    imageScanStatus: Optional[ImageScanStatus]
    imageScanFindingsSummary: Optional[ImageScanFindingsSummary]
    imageManifestMediaType: Optional[MediaType]
    artifactMediaType: Optional[MediaType]
    lastRecordedPullTime: Optional[RecordedPullTimestamp]


ImageDetailList = List[ImageDetail]


class DescribeImagesResponse(TypedDict, total=False):
    imageDetails: Optional[ImageDetailList]
    nextToken: Optional[NextToken]


PullThroughCacheRuleRepositoryPrefixList = List[PullThroughCacheRuleRepositoryPrefix]


class DescribePullThroughCacheRulesRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    ecrRepositoryPrefixes: Optional[PullThroughCacheRuleRepositoryPrefixList]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class PullThroughCacheRule(TypedDict, total=False):
    ecrRepositoryPrefix: Optional[PullThroughCacheRuleRepositoryPrefix]
    upstreamRegistryUrl: Optional[Url]
    createdAt: Optional[CreationTimestamp]
    registryId: Optional[RegistryId]


PullThroughCacheRuleList = List[PullThroughCacheRule]


class DescribePullThroughCacheRulesResponse(TypedDict, total=False):
    pullThroughCacheRules: Optional[PullThroughCacheRuleList]
    nextToken: Optional[NextToken]


class DescribeRegistryRequest(ServiceRequest):
    pass


class RepositoryFilter(TypedDict, total=False):
    filter: RepositoryFilterValue
    filterType: RepositoryFilterType


RepositoryFilterList = List[RepositoryFilter]


class ReplicationDestination(TypedDict, total=False):
    region: Region
    registryId: RegistryId


ReplicationDestinationList = List[ReplicationDestination]


class ReplicationRule(TypedDict, total=False):
    destinations: ReplicationDestinationList
    repositoryFilters: Optional[RepositoryFilterList]


ReplicationRuleList = List[ReplicationRule]


class ReplicationConfiguration(TypedDict, total=False):
    rules: ReplicationRuleList


class DescribeRegistryResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    replicationConfiguration: Optional[ReplicationConfiguration]


RepositoryNameList = List[RepositoryName]


class DescribeRepositoriesRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryNames: Optional[RepositoryNameList]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


RepositoryList = List[Repository]


class DescribeRepositoriesResponse(TypedDict, total=False):
    repositories: Optional[RepositoryList]
    nextToken: Optional[NextToken]


GetAuthorizationTokenRegistryIdList = List[RegistryId]


class GetAuthorizationTokenRequest(ServiceRequest):
    registryIds: Optional[GetAuthorizationTokenRegistryIdList]


class GetAuthorizationTokenResponse(TypedDict, total=False):
    authorizationData: Optional[AuthorizationDataList]


class GetDownloadUrlForLayerRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    layerDigest: LayerDigest


class GetDownloadUrlForLayerResponse(TypedDict, total=False):
    downloadUrl: Optional[Url]
    layerDigest: Optional[LayerDigest]


class LifecyclePolicyPreviewFilter(TypedDict, total=False):
    tagStatus: Optional[TagStatus]


class GetLifecyclePolicyPreviewRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageIds: Optional[ImageIdentifierList]
    nextToken: Optional[NextToken]
    maxResults: Optional[LifecyclePreviewMaxResults]
    filter: Optional[LifecyclePolicyPreviewFilter]


class LifecyclePolicyPreviewSummary(TypedDict, total=False):
    expiringImageTotalCount: Optional[ImageCount]


LifecyclePolicyRuleAction = TypedDict(
    "LifecyclePolicyRuleAction",
    {
        "type": Optional[ImageActionType],
    },
    total=False,
)


class LifecyclePolicyPreviewResult(TypedDict, total=False):
    imageTags: Optional[ImageTagList]
    imageDigest: Optional[ImageDigest]
    imagePushedAt: Optional[PushTimestamp]
    action: Optional[LifecyclePolicyRuleAction]
    appliedRulePriority: Optional[LifecyclePolicyRulePriority]


LifecyclePolicyPreviewResultList = List[LifecyclePolicyPreviewResult]


class GetLifecyclePolicyPreviewResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    lifecyclePolicyText: Optional[LifecyclePolicyText]
    status: Optional[LifecyclePolicyPreviewStatus]
    nextToken: Optional[NextToken]
    previewResults: Optional[LifecyclePolicyPreviewResultList]
    summary: Optional[LifecyclePolicyPreviewSummary]


class GetLifecyclePolicyRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName


class GetLifecyclePolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    lifecyclePolicyText: Optional[LifecyclePolicyText]
    lastEvaluatedAt: Optional[EvaluationTimestamp]


class GetRegistryPolicyRequest(ServiceRequest):
    pass


class GetRegistryPolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    policyText: Optional[RegistryPolicyText]


class GetRegistryScanningConfigurationRequest(ServiceRequest):
    pass


class RegistryScanningRule(TypedDict, total=False):
    scanFrequency: ScanFrequency
    repositoryFilters: ScanningRepositoryFilterList


RegistryScanningRuleList = List[RegistryScanningRule]


class RegistryScanningConfiguration(TypedDict, total=False):
    scanType: Optional[ScanType]
    rules: Optional[RegistryScanningRuleList]


class GetRegistryScanningConfigurationResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    scanningConfiguration: Optional[RegistryScanningConfiguration]


class GetRepositoryPolicyRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName


class GetRepositoryPolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    policyText: Optional[RepositoryPolicyText]


class InitiateLayerUploadRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName


class InitiateLayerUploadResponse(TypedDict, total=False):
    uploadId: Optional[UploadId]
    partSize: Optional[PartSize]


LayerPartBlob = bytes


class ListImagesFilter(TypedDict, total=False):
    tagStatus: Optional[TagStatus]


class ListImagesRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]
    filter: Optional[ListImagesFilter]


class ListImagesResponse(TypedDict, total=False):
    imageIds: Optional[ImageIdentifierList]
    nextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: Arn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagList]


class PutImageRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageManifest: ImageManifest
    imageManifestMediaType: Optional[MediaType]
    imageTag: Optional[ImageTag]
    imageDigest: Optional[ImageDigest]


class PutImageResponse(TypedDict, total=False):
    image: Optional[Image]


class PutImageScanningConfigurationRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageScanningConfiguration: ImageScanningConfiguration


class PutImageScanningConfigurationResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    imageScanningConfiguration: Optional[ImageScanningConfiguration]


class PutImageTagMutabilityRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageTagMutability: ImageTagMutability


class PutImageTagMutabilityResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    imageTagMutability: Optional[ImageTagMutability]


class PutLifecyclePolicyRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    lifecyclePolicyText: LifecyclePolicyText


class PutLifecyclePolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    lifecyclePolicyText: Optional[LifecyclePolicyText]


class PutRegistryPolicyRequest(ServiceRequest):
    policyText: RegistryPolicyText


class PutRegistryPolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    policyText: Optional[RegistryPolicyText]


class PutRegistryScanningConfigurationRequest(ServiceRequest):
    scanType: Optional[ScanType]
    rules: Optional[RegistryScanningRuleList]


class PutRegistryScanningConfigurationResponse(TypedDict, total=False):
    registryScanningConfiguration: Optional[RegistryScanningConfiguration]


class PutReplicationConfigurationRequest(ServiceRequest):
    replicationConfiguration: ReplicationConfiguration


class PutReplicationConfigurationResponse(TypedDict, total=False):
    replicationConfiguration: Optional[ReplicationConfiguration]


class SetRepositoryPolicyRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    policyText: RepositoryPolicyText
    force: Optional[ForceFlag]


class SetRepositoryPolicyResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    policyText: Optional[RepositoryPolicyText]


class StartImageScanRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    imageId: ImageIdentifier


class StartImageScanResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    imageId: Optional[ImageIdentifier]
    imageScanStatus: Optional[ImageScanStatus]


class StartLifecyclePolicyPreviewRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    lifecyclePolicyText: Optional[LifecyclePolicyText]


class StartLifecyclePolicyPreviewResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    lifecyclePolicyText: Optional[LifecyclePolicyText]
    status: Optional[LifecyclePolicyPreviewStatus]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: Arn
    tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: Arn
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UploadLayerPartRequest(ServiceRequest):
    registryId: Optional[RegistryId]
    repositoryName: RepositoryName
    uploadId: UploadId
    partFirstByte: PartSize
    partLastByte: PartSize
    layerPartBlob: LayerPartBlob


class UploadLayerPartResponse(TypedDict, total=False):
    registryId: Optional[RegistryId]
    repositoryName: Optional[RepositoryName]
    uploadId: Optional[UploadId]
    lastByteReceived: Optional[PartSize]


class EcrApi:

    service = "ecr"
    version = "2015-09-21"

    @handler("BatchCheckLayerAvailability")
    def batch_check_layer_availability(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        layer_digests: BatchedOperationLayerDigestList,
        registry_id: RegistryId = None,
    ) -> BatchCheckLayerAvailabilityResponse:
        raise NotImplementedError

    @handler("BatchDeleteImage")
    def batch_delete_image(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_ids: ImageIdentifierList,
        registry_id: RegistryId = None,
    ) -> BatchDeleteImageResponse:
        raise NotImplementedError

    @handler("BatchGetImage")
    def batch_get_image(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_ids: ImageIdentifierList,
        registry_id: RegistryId = None,
        accepted_media_types: MediaTypeList = None,
    ) -> BatchGetImageResponse:
        raise NotImplementedError

    @handler("BatchGetRepositoryScanningConfiguration")
    def batch_get_repository_scanning_configuration(
        self, context: RequestContext, repository_names: ScanningConfigurationRepositoryNameList
    ) -> BatchGetRepositoryScanningConfigurationResponse:
        raise NotImplementedError

    @handler("CompleteLayerUpload")
    def complete_layer_upload(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        upload_id: UploadId,
        layer_digests: LayerDigestList,
        registry_id: RegistryId = None,
    ) -> CompleteLayerUploadResponse:
        raise NotImplementedError

    @handler("CreatePullThroughCacheRule")
    def create_pull_through_cache_rule(
        self,
        context: RequestContext,
        ecr_repository_prefix: PullThroughCacheRuleRepositoryPrefix,
        upstream_registry_url: Url,
        registry_id: RegistryId = None,
    ) -> CreatePullThroughCacheRuleResponse:
        raise NotImplementedError

    @handler("CreateRepository")
    def create_repository(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
        tags: TagList = None,
        image_tag_mutability: ImageTagMutability = None,
        image_scanning_configuration: ImageScanningConfiguration = None,
        encryption_configuration: EncryptionConfiguration = None,
    ) -> CreateRepositoryResponse:
        raise NotImplementedError

    @handler("DeleteLifecyclePolicy")
    def delete_lifecycle_policy(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
    ) -> DeleteLifecyclePolicyResponse:
        raise NotImplementedError

    @handler("DeletePullThroughCacheRule")
    def delete_pull_through_cache_rule(
        self,
        context: RequestContext,
        ecr_repository_prefix: PullThroughCacheRuleRepositoryPrefix,
        registry_id: RegistryId = None,
    ) -> DeletePullThroughCacheRuleResponse:
        raise NotImplementedError

    @handler("DeleteRegistryPolicy")
    def delete_registry_policy(
        self,
        context: RequestContext,
    ) -> DeleteRegistryPolicyResponse:
        raise NotImplementedError

    @handler("DeleteRepository")
    def delete_repository(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
        force: ForceFlag = None,
    ) -> DeleteRepositoryResponse:
        raise NotImplementedError

    @handler("DeleteRepositoryPolicy")
    def delete_repository_policy(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
    ) -> DeleteRepositoryPolicyResponse:
        raise NotImplementedError

    @handler("DescribeImageReplicationStatus")
    def describe_image_replication_status(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_id: ImageIdentifier,
        registry_id: RegistryId = None,
    ) -> DescribeImageReplicationStatusResponse:
        raise NotImplementedError

    @handler("DescribeImageScanFindings")
    def describe_image_scan_findings(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_id: ImageIdentifier,
        registry_id: RegistryId = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> DescribeImageScanFindingsResponse:
        raise NotImplementedError

    @handler("DescribeImages")
    def describe_images(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
        image_ids: ImageIdentifierList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        filter: DescribeImagesFilter = None,
    ) -> DescribeImagesResponse:
        raise NotImplementedError

    @handler("DescribePullThroughCacheRules")
    def describe_pull_through_cache_rules(
        self,
        context: RequestContext,
        registry_id: RegistryId = None,
        ecr_repository_prefixes: PullThroughCacheRuleRepositoryPrefixList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> DescribePullThroughCacheRulesResponse:
        raise NotImplementedError

    @handler("DescribeRegistry")
    def describe_registry(
        self,
        context: RequestContext,
    ) -> DescribeRegistryResponse:
        raise NotImplementedError

    @handler("DescribeRepositories")
    def describe_repositories(
        self,
        context: RequestContext,
        registry_id: RegistryId = None,
        repository_names: RepositoryNameList = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> DescribeRepositoriesResponse:
        raise NotImplementedError

    @handler("GetAuthorizationToken")
    def get_authorization_token(
        self, context: RequestContext, registry_ids: GetAuthorizationTokenRegistryIdList = None
    ) -> GetAuthorizationTokenResponse:
        raise NotImplementedError

    @handler("GetDownloadUrlForLayer")
    def get_download_url_for_layer(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        layer_digest: LayerDigest,
        registry_id: RegistryId = None,
    ) -> GetDownloadUrlForLayerResponse:
        raise NotImplementedError

    @handler("GetLifecyclePolicy")
    def get_lifecycle_policy(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
    ) -> GetLifecyclePolicyResponse:
        raise NotImplementedError

    @handler("GetLifecyclePolicyPreview")
    def get_lifecycle_policy_preview(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
        image_ids: ImageIdentifierList = None,
        next_token: NextToken = None,
        max_results: LifecyclePreviewMaxResults = None,
        filter: LifecyclePolicyPreviewFilter = None,
    ) -> GetLifecyclePolicyPreviewResponse:
        raise NotImplementedError

    @handler("GetRegistryPolicy")
    def get_registry_policy(
        self,
        context: RequestContext,
    ) -> GetRegistryPolicyResponse:
        raise NotImplementedError

    @handler("GetRegistryScanningConfiguration")
    def get_registry_scanning_configuration(
        self,
        context: RequestContext,
    ) -> GetRegistryScanningConfigurationResponse:
        raise NotImplementedError

    @handler("GetRepositoryPolicy")
    def get_repository_policy(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
    ) -> GetRepositoryPolicyResponse:
        raise NotImplementedError

    @handler("InitiateLayerUpload")
    def initiate_layer_upload(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
    ) -> InitiateLayerUploadResponse:
        raise NotImplementedError

    @handler("ListImages")
    def list_images(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        filter: ListImagesFilter = None,
    ) -> ListImagesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutImage")
    def put_image(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_manifest: ImageManifest,
        registry_id: RegistryId = None,
        image_manifest_media_type: MediaType = None,
        image_tag: ImageTag = None,
        image_digest: ImageDigest = None,
    ) -> PutImageResponse:
        raise NotImplementedError

    @handler("PutImageScanningConfiguration")
    def put_image_scanning_configuration(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_scanning_configuration: ImageScanningConfiguration,
        registry_id: RegistryId = None,
    ) -> PutImageScanningConfigurationResponse:
        raise NotImplementedError

    @handler("PutImageTagMutability")
    def put_image_tag_mutability(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_tag_mutability: ImageTagMutability,
        registry_id: RegistryId = None,
    ) -> PutImageTagMutabilityResponse:
        raise NotImplementedError

    @handler("PutLifecyclePolicy")
    def put_lifecycle_policy(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        lifecycle_policy_text: LifecyclePolicyText,
        registry_id: RegistryId = None,
    ) -> PutLifecyclePolicyResponse:
        raise NotImplementedError

    @handler("PutRegistryPolicy")
    def put_registry_policy(
        self, context: RequestContext, policy_text: RegistryPolicyText
    ) -> PutRegistryPolicyResponse:
        raise NotImplementedError

    @handler("PutRegistryScanningConfiguration")
    def put_registry_scanning_configuration(
        self,
        context: RequestContext,
        scan_type: ScanType = None,
        rules: RegistryScanningRuleList = None,
    ) -> PutRegistryScanningConfigurationResponse:
        raise NotImplementedError

    @handler("PutReplicationConfiguration")
    def put_replication_configuration(
        self, context: RequestContext, replication_configuration: ReplicationConfiguration
    ) -> PutReplicationConfigurationResponse:
        raise NotImplementedError

    @handler("SetRepositoryPolicy")
    def set_repository_policy(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        policy_text: RepositoryPolicyText,
        registry_id: RegistryId = None,
        force: ForceFlag = None,
    ) -> SetRepositoryPolicyResponse:
        raise NotImplementedError

    @handler("StartImageScan")
    def start_image_scan(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        image_id: ImageIdentifier,
        registry_id: RegistryId = None,
    ) -> StartImageScanResponse:
        raise NotImplementedError

    @handler("StartLifecyclePolicyPreview")
    def start_lifecycle_policy_preview(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        registry_id: RegistryId = None,
        lifecycle_policy_text: LifecyclePolicyText = None,
    ) -> StartLifecyclePolicyPreviewResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UploadLayerPart")
    def upload_layer_part(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        upload_id: UploadId,
        part_first_byte: PartSize,
        part_last_byte: PartSize,
        layer_part_blob: LayerPartBlob,
        registry_id: RegistryId = None,
    ) -> UploadLayerPartResponse:
        raise NotImplementedError
