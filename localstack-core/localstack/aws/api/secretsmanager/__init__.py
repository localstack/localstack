from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

BooleanType = bool
ClientRequestTokenType = str
DescriptionType = str
DurationType = str
ErrorCode = str
ErrorMessage = str
ExcludeCharactersType = str
ExcludeLowercaseType = bool
ExcludeNumbersType = bool
ExcludePunctuationType = bool
ExcludeUppercaseType = bool
ExternalSecretRotationMetadataItemKeyType = str
ExternalSecretRotationMetadataItemValueType = str
FilterValueStringType = str
IncludeSpaceType = bool
KmsKeyIdType = str
MaxResultsBatchType = int
MaxResultsType = int
MedeaTypeType = str
NameType = str
NextTokenType = str
NonEmptyResourcePolicyType = str
OwningServiceType = str
RandomPasswordType = str
RegionType = str
RequireEachIncludedTypeType = bool
RoleARNType = str
RotationEnabledType = bool
RotationLambdaARNType = str
RotationTokenType = str
ScheduleExpressionType = str
SecretARNType = str
SecretIdType = str
SecretNameType = str
SecretStringType = str
SecretVersionIdType = str
SecretVersionStageType = str
StatusMessageType = str
TagKeyType = str
TagValueType = str


class FilterNameStringType(StrEnum):
    description = "description"
    name = "name"
    tag_key = "tag-key"
    tag_value = "tag-value"
    primary_region = "primary-region"
    owning_service = "owning-service"
    all = "all"


class SortByType(StrEnum):
    created_date = "created-date"
    last_accessed_date = "last-accessed-date"
    last_changed_date = "last-changed-date"
    name = "name"


class SortOrderType(StrEnum):
    asc = "asc"
    desc = "desc"


class StatusType(StrEnum):
    InSync = "InSync"
    Failed = "Failed"
    InProgress = "InProgress"


class DecryptionFailure(ServiceException):
    code: str = "DecryptionFailure"
    sender_fault: bool = False
    status_code: int = 400


class EncryptionFailure(ServiceException):
    code: str = "EncryptionFailure"
    sender_fault: bool = False
    status_code: int = 400


class InternalServiceError(ServiceException):
    code: str = "InternalServiceError"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextTokenException(ServiceException):
    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRequestException(ServiceException):
    code: str = "InvalidRequestException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MalformedPolicyDocumentException(ServiceException):
    code: str = "MalformedPolicyDocumentException"
    sender_fault: bool = False
    status_code: int = 400


class PreconditionNotMetException(ServiceException):
    code: str = "PreconditionNotMetException"
    sender_fault: bool = False
    status_code: int = 400


class PublicPolicyException(ServiceException):
    code: str = "PublicPolicyException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceExistsException(ServiceException):
    code: str = "ResourceExistsException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class APIErrorType(TypedDict, total=False):
    SecretId: SecretIdType | None
    ErrorCode: ErrorCode | None
    Message: ErrorMessage | None


APIErrorListType = list[APIErrorType]


class ReplicaRegionType(TypedDict, total=False):
    Region: RegionType | None
    KmsKeyId: KmsKeyIdType | None


AddReplicaRegionListType = list[ReplicaRegionType]
AutomaticallyRotateAfterDaysType = int
FilterValuesStringList = list[FilterValueStringType]


class Filter(TypedDict, total=False):
    Key: FilterNameStringType | None
    Values: FilterValuesStringList | None


FiltersListType = list[Filter]
SecretIdListType = list[SecretIdType]


class BatchGetSecretValueRequest(ServiceRequest):
    SecretIdList: SecretIdListType | None
    Filters: FiltersListType | None
    MaxResults: MaxResultsBatchType | None
    NextToken: NextTokenType | None


CreatedDateType = datetime
SecretVersionStagesType = list[SecretVersionStageType]
SecretBinaryType = bytes


class SecretValueEntry(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None
    SecretBinary: SecretBinaryType | None
    SecretString: SecretStringType | None
    VersionStages: SecretVersionStagesType | None
    CreatedDate: CreatedDateType | None


SecretValuesType = list[SecretValueEntry]


class BatchGetSecretValueResponse(TypedDict, total=False):
    SecretValues: SecretValuesType | None
    NextToken: NextTokenType | None
    Errors: APIErrorListType | None


class CancelRotateSecretRequest(ServiceRequest):
    SecretId: SecretIdType


class CancelRotateSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None


class Tag(TypedDict, total=False):
    Key: TagKeyType | None
    Value: TagValueType | None


TagListType = list[Tag]


class CreateSecretRequest(ServiceRequest):
    Name: NameType
    ClientRequestToken: ClientRequestTokenType | None
    Description: DescriptionType | None
    KmsKeyId: KmsKeyIdType | None
    SecretBinary: SecretBinaryType | None
    SecretString: SecretStringType | None
    Tags: TagListType | None
    AddReplicaRegions: AddReplicaRegionListType | None
    ForceOverwriteReplicaSecret: BooleanType | None
    Type: MedeaTypeType | None


LastAccessedDateType = datetime


class ReplicationStatusType(TypedDict, total=False):
    Region: RegionType | None
    KmsKeyId: KmsKeyIdType | None
    Status: StatusType | None
    StatusMessage: StatusMessageType | None
    LastAccessedDate: LastAccessedDateType | None


ReplicationStatusListType = list[ReplicationStatusType]


class CreateSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None
    ReplicationStatus: ReplicationStatusListType | None


class DeleteResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType


class DeleteResourcePolicyResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: NameType | None


RecoveryWindowInDaysType = int


class DeleteSecretRequest(ServiceRequest):
    SecretId: SecretIdType
    RecoveryWindowInDays: RecoveryWindowInDaysType | None
    ForceDeleteWithoutRecovery: BooleanType | None


DeletionDateType = datetime


class DeleteSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    DeletionDate: DeletionDateType | None


DeletedDateType = datetime


class DescribeSecretRequest(ServiceRequest):
    SecretId: SecretIdType


TimestampType = datetime
SecretVersionsToStagesMapType = dict[SecretVersionIdType, SecretVersionStagesType]
NextRotationDateType = datetime
LastChangedDateType = datetime
LastRotatedDateType = datetime


class ExternalSecretRotationMetadataItem(TypedDict, total=False):
    Key: ExternalSecretRotationMetadataItemKeyType | None
    Value: ExternalSecretRotationMetadataItemValueType | None


ExternalSecretRotationMetadataType = list[ExternalSecretRotationMetadataItem]


class RotationRulesType(TypedDict, total=False):
    AutomaticallyAfterDays: AutomaticallyRotateAfterDaysType | None
    Duration: DurationType | None
    ScheduleExpression: ScheduleExpressionType | None


class DescribeSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    Type: MedeaTypeType | None
    Description: DescriptionType | None
    KmsKeyId: KmsKeyIdType | None
    RotationEnabled: RotationEnabledType | None
    RotationLambdaARN: RotationLambdaARNType | None
    RotationRules: RotationRulesType | None
    ExternalSecretRotationMetadata: ExternalSecretRotationMetadataType | None
    ExternalSecretRotationRoleArn: RoleARNType | None
    LastRotatedDate: LastRotatedDateType | None
    LastChangedDate: LastChangedDateType | None
    LastAccessedDate: LastAccessedDateType | None
    DeletedDate: DeletedDateType | None
    NextRotationDate: NextRotationDateType | None
    Tags: TagListType | None
    VersionIdsToStages: SecretVersionsToStagesMapType | None
    OwningService: OwningServiceType | None
    CreatedDate: TimestampType | None
    PrimaryRegion: RegionType | None
    ReplicationStatus: ReplicationStatusListType | None


PasswordLengthType = int


class GetRandomPasswordRequest(ServiceRequest):
    PasswordLength: PasswordLengthType | None
    ExcludeCharacters: ExcludeCharactersType | None
    ExcludeNumbers: ExcludeNumbersType | None
    ExcludePunctuation: ExcludePunctuationType | None
    ExcludeUppercase: ExcludeUppercaseType | None
    ExcludeLowercase: ExcludeLowercaseType | None
    IncludeSpace: IncludeSpaceType | None
    RequireEachIncludedType: RequireEachIncludedTypeType | None


class GetRandomPasswordResponse(TypedDict, total=False):
    RandomPassword: RandomPasswordType | None


class GetResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType


class GetResourcePolicyResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: NameType | None
    ResourcePolicy: NonEmptyResourcePolicyType | None


class GetSecretValueRequest(ServiceRequest):
    SecretId: SecretIdType
    VersionId: SecretVersionIdType | None
    VersionStage: SecretVersionStageType | None


class GetSecretValueResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None
    SecretBinary: SecretBinaryType | None
    SecretString: SecretStringType | None
    VersionStages: SecretVersionStagesType | None
    CreatedDate: CreatedDateType | None


KmsKeyIdListType = list[KmsKeyIdType]


class ListSecretVersionIdsRequest(ServiceRequest):
    SecretId: SecretIdType
    MaxResults: MaxResultsType | None
    NextToken: NextTokenType | None
    IncludeDeprecated: BooleanType | None


class SecretVersionsListEntry(TypedDict, total=False):
    VersionId: SecretVersionIdType | None
    VersionStages: SecretVersionStagesType | None
    LastAccessedDate: LastAccessedDateType | None
    CreatedDate: CreatedDateType | None
    KmsKeyIds: KmsKeyIdListType | None


SecretVersionsListType = list[SecretVersionsListEntry]


class ListSecretVersionIdsResponse(TypedDict, total=False):
    Versions: SecretVersionsListType | None
    NextToken: NextTokenType | None
    ARN: SecretARNType | None
    Name: SecretNameType | None


class ListSecretsRequest(ServiceRequest):
    IncludePlannedDeletion: BooleanType | None
    MaxResults: MaxResultsType | None
    NextToken: NextTokenType | None
    Filters: FiltersListType | None
    SortOrder: SortOrderType | None
    SortBy: SortByType | None


class SecretListEntry(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    Type: MedeaTypeType | None
    Description: DescriptionType | None
    KmsKeyId: KmsKeyIdType | None
    RotationEnabled: RotationEnabledType | None
    RotationLambdaARN: RotationLambdaARNType | None
    RotationRules: RotationRulesType | None
    ExternalSecretRotationMetadata: ExternalSecretRotationMetadataType | None
    ExternalSecretRotationRoleArn: RoleARNType | None
    LastRotatedDate: LastRotatedDateType | None
    LastChangedDate: LastChangedDateType | None
    LastAccessedDate: LastAccessedDateType | None
    DeletedDate: DeletedDateType | None
    NextRotationDate: NextRotationDateType | None
    Tags: TagListType | None
    SecretVersionsToStages: SecretVersionsToStagesMapType | None
    OwningService: OwningServiceType | None
    CreatedDate: TimestampType | None
    PrimaryRegion: RegionType | None


SecretListType = list[SecretListEntry]


class ListSecretsResponse(TypedDict, total=False):
    SecretList: SecretListType | None
    NextToken: NextTokenType | None


class PutResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType
    ResourcePolicy: NonEmptyResourcePolicyType
    BlockPublicPolicy: BooleanType | None


class PutResourcePolicyResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: NameType | None


class PutSecretValueRequest(ServiceRequest):
    SecretId: SecretIdType
    ClientRequestToken: ClientRequestTokenType | None
    SecretBinary: SecretBinaryType | None
    SecretString: SecretStringType | None
    VersionStages: SecretVersionStagesType | None
    RotationToken: RotationTokenType | None


class PutSecretValueResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None
    VersionStages: SecretVersionStagesType | None


RemoveReplicaRegionListType = list[RegionType]


class RemoveRegionsFromReplicationRequest(ServiceRequest):
    SecretId: SecretIdType
    RemoveReplicaRegions: RemoveReplicaRegionListType


class RemoveRegionsFromReplicationResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    ReplicationStatus: ReplicationStatusListType | None


class ReplicateSecretToRegionsRequest(ServiceRequest):
    SecretId: SecretIdType
    AddReplicaRegions: AddReplicaRegionListType
    ForceOverwriteReplicaSecret: BooleanType | None


class ReplicateSecretToRegionsResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    ReplicationStatus: ReplicationStatusListType | None


class RestoreSecretRequest(ServiceRequest):
    SecretId: SecretIdType


class RestoreSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None


class RotateSecretRequest(ServiceRequest):
    SecretId: SecretIdType
    ClientRequestToken: ClientRequestTokenType | None
    RotationLambdaARN: RotationLambdaARNType | None
    RotationRules: RotationRulesType | None
    ExternalSecretRotationMetadata: ExternalSecretRotationMetadataType | None
    ExternalSecretRotationRoleArn: RoleARNType | None
    RotateImmediately: BooleanType | None


class RotateSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None


class StopReplicationToReplicaRequest(ServiceRequest):
    SecretId: SecretIdType


class StopReplicationToReplicaResponse(TypedDict, total=False):
    ARN: SecretARNType | None


TagKeyListType = list[TagKeyType]


class TagResourceRequest(ServiceRequest):
    SecretId: SecretIdType
    Tags: TagListType


class UntagResourceRequest(ServiceRequest):
    SecretId: SecretIdType
    TagKeys: TagKeyListType


class UpdateSecretRequest(ServiceRequest):
    SecretId: SecretIdType
    ClientRequestToken: ClientRequestTokenType | None
    Description: DescriptionType | None
    KmsKeyId: KmsKeyIdType | None
    SecretBinary: SecretBinaryType | None
    SecretString: SecretStringType | None
    Type: MedeaTypeType | None


class UpdateSecretResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None
    VersionId: SecretVersionIdType | None


class UpdateSecretVersionStageRequest(ServiceRequest):
    SecretId: SecretIdType
    VersionStage: SecretVersionStageType
    RemoveFromVersionId: SecretVersionIdType | None
    MoveToVersionId: SecretVersionIdType | None


class UpdateSecretVersionStageResponse(TypedDict, total=False):
    ARN: SecretARNType | None
    Name: SecretNameType | None


class ValidateResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType | None
    ResourcePolicy: NonEmptyResourcePolicyType


class ValidationErrorsEntry(TypedDict, total=False):
    CheckName: NameType | None
    ErrorMessage: ErrorMessage | None


ValidationErrorsType = list[ValidationErrorsEntry]


class ValidateResourcePolicyResponse(TypedDict, total=False):
    PolicyValidationPassed: BooleanType | None
    ValidationErrors: ValidationErrorsType | None


class SecretsmanagerApi:
    service: str = "secretsmanager"
    version: str = "2017-10-17"

    @handler("BatchGetSecretValue")
    def batch_get_secret_value(
        self,
        context: RequestContext,
        secret_id_list: SecretIdListType | None = None,
        filters: FiltersListType | None = None,
        max_results: MaxResultsBatchType | None = None,
        next_token: NextTokenType | None = None,
        **kwargs,
    ) -> BatchGetSecretValueResponse:
        raise NotImplementedError

    @handler("CancelRotateSecret")
    def cancel_rotate_secret(
        self, context: RequestContext, secret_id: SecretIdType, **kwargs
    ) -> CancelRotateSecretResponse:
        raise NotImplementedError

    @handler("CreateSecret", expand=False)
    def create_secret(
        self, context: RequestContext, request: CreateSecretRequest, **kwargs
    ) -> CreateSecretResponse:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType, **kwargs
    ) -> DeleteResourcePolicyResponse:
        raise NotImplementedError

    @handler("DeleteSecret")
    def delete_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        recovery_window_in_days: RecoveryWindowInDaysType | None = None,
        force_delete_without_recovery: BooleanType | None = None,
        **kwargs,
    ) -> DeleteSecretResponse:
        raise NotImplementedError

    @handler("DescribeSecret")
    def describe_secret(
        self, context: RequestContext, secret_id: SecretIdType, **kwargs
    ) -> DescribeSecretResponse:
        raise NotImplementedError

    @handler("GetRandomPassword")
    def get_random_password(
        self,
        context: RequestContext,
        password_length: PasswordLengthType | None = None,
        exclude_characters: ExcludeCharactersType | None = None,
        exclude_numbers: ExcludeNumbersType | None = None,
        exclude_punctuation: ExcludePunctuationType | None = None,
        exclude_uppercase: ExcludeUppercaseType | None = None,
        exclude_lowercase: ExcludeLowercaseType | None = None,
        include_space: IncludeSpaceType | None = None,
        require_each_included_type: RequireEachIncludedTypeType | None = None,
        **kwargs,
    ) -> GetRandomPasswordResponse:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType, **kwargs
    ) -> GetResourcePolicyResponse:
        raise NotImplementedError

    @handler("GetSecretValue")
    def get_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_id: SecretVersionIdType | None = None,
        version_stage: SecretVersionStageType | None = None,
        **kwargs,
    ) -> GetSecretValueResponse:
        raise NotImplementedError

    @handler("ListSecretVersionIds")
    def list_secret_version_ids(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        max_results: MaxResultsType | None = None,
        next_token: NextTokenType | None = None,
        include_deprecated: BooleanType | None = None,
        **kwargs,
    ) -> ListSecretVersionIdsResponse:
        raise NotImplementedError

    @handler("ListSecrets")
    def list_secrets(
        self,
        context: RequestContext,
        include_planned_deletion: BooleanType | None = None,
        max_results: MaxResultsType | None = None,
        next_token: NextTokenType | None = None,
        filters: FiltersListType | None = None,
        sort_order: SortOrderType | None = None,
        sort_by: SortByType | None = None,
        **kwargs,
    ) -> ListSecretsResponse:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        resource_policy: NonEmptyResourcePolicyType,
        block_public_policy: BooleanType | None = None,
        **kwargs,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("PutSecretValue")
    def put_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType | None = None,
        secret_binary: SecretBinaryType | None = None,
        secret_string: SecretStringType | None = None,
        version_stages: SecretVersionStagesType | None = None,
        rotation_token: RotationTokenType | None = None,
        **kwargs,
    ) -> PutSecretValueResponse:
        raise NotImplementedError

    @handler("RemoveRegionsFromReplication")
    def remove_regions_from_replication(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        remove_replica_regions: RemoveReplicaRegionListType,
        **kwargs,
    ) -> RemoveRegionsFromReplicationResponse:
        raise NotImplementedError

    @handler("ReplicateSecretToRegions")
    def replicate_secret_to_regions(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        add_replica_regions: AddReplicaRegionListType,
        force_overwrite_replica_secret: BooleanType | None = None,
        **kwargs,
    ) -> ReplicateSecretToRegionsResponse:
        raise NotImplementedError

    @handler("RestoreSecret")
    def restore_secret(
        self, context: RequestContext, secret_id: SecretIdType, **kwargs
    ) -> RestoreSecretResponse:
        raise NotImplementedError

    @handler("RotateSecret")
    def rotate_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType | None = None,
        rotation_lambda_arn: RotationLambdaARNType | None = None,
        rotation_rules: RotationRulesType | None = None,
        external_secret_rotation_metadata: ExternalSecretRotationMetadataType | None = None,
        external_secret_rotation_role_arn: RoleARNType | None = None,
        rotate_immediately: BooleanType | None = None,
        **kwargs,
    ) -> RotateSecretResponse:
        raise NotImplementedError

    @handler("StopReplicationToReplica")
    def stop_replication_to_replica(
        self, context: RequestContext, secret_id: SecretIdType, **kwargs
    ) -> StopReplicationToReplicaResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tags: TagListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tag_keys: TagKeyListType, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateSecret", expand=False)
    def update_secret(
        self, context: RequestContext, request: UpdateSecretRequest, **kwargs
    ) -> UpdateSecretResponse:
        raise NotImplementedError

    @handler("UpdateSecretVersionStage")
    def update_secret_version_stage(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_stage: SecretVersionStageType,
        remove_from_version_id: SecretVersionIdType | None = None,
        move_to_version_id: SecretVersionIdType | None = None,
        **kwargs,
    ) -> UpdateSecretVersionStageResponse:
        raise NotImplementedError

    @handler("ValidateResourcePolicy")
    def validate_resource_policy(
        self,
        context: RequestContext,
        resource_policy: NonEmptyResourcePolicyType,
        secret_id: SecretIdType | None = None,
        **kwargs,
    ) -> ValidateResourcePolicyResponse:
        raise NotImplementedError
