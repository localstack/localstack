import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

BooleanType = bool
ClientRequestTokenType = str
DescriptionType = str
DurationType = str
ErrorMessage = str
ExcludeCharactersType = str
ExcludeLowercaseType = bool
ExcludeNumbersType = bool
ExcludePunctuationType = bool
ExcludeUppercaseType = bool
FilterValueStringType = str
IncludeSpaceType = bool
KmsKeyIdType = str
MaxResultsType = int
NameType = str
NextTokenType = str
NonEmptyResourcePolicyType = str
OwningServiceType = str
RandomPasswordType = str
RegionType = str
RequireEachIncludedTypeType = bool
RotationEnabledType = bool
RotationLambdaARNType = str
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


class FilterNameStringType(str):
    description = "description"
    name = "name"
    tag_key = "tag-key"
    tag_value = "tag-value"
    primary_region = "primary-region"
    all = "all"


class SortOrderType(str):
    asc = "asc"
    desc = "desc"


class StatusType(str):
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


class ReplicaRegionType(TypedDict, total=False):
    Region: Optional[RegionType]
    KmsKeyId: Optional[KmsKeyIdType]


AddReplicaRegionListType = List[ReplicaRegionType]
AutomaticallyRotateAfterDaysType = int


class CancelRotateSecretRequest(ServiceRequest):
    SecretId: SecretIdType


class CancelRotateSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    VersionId: Optional[SecretVersionIdType]


class Tag(TypedDict, total=False):
    Key: Optional[TagKeyType]
    Value: Optional[TagValueType]


TagListType = List[Tag]
SecretBinaryType = bytes


class CreateSecretRequest(ServiceRequest):
    Name: NameType
    ClientRequestToken: Optional[ClientRequestTokenType]
    Description: Optional[DescriptionType]
    KmsKeyId: Optional[KmsKeyIdType]
    SecretBinary: Optional[SecretBinaryType]
    SecretString: Optional[SecretStringType]
    Tags: Optional[TagListType]
    AddReplicaRegions: Optional[AddReplicaRegionListType]
    ForceOverwriteReplicaSecret: Optional[BooleanType]


LastAccessedDateType = datetime


class ReplicationStatusType(TypedDict, total=False):
    Region: Optional[RegionType]
    KmsKeyId: Optional[KmsKeyIdType]
    Status: Optional[StatusType]
    StatusMessage: Optional[StatusMessageType]
    LastAccessedDate: Optional[LastAccessedDateType]


ReplicationStatusListType = List[ReplicationStatusType]


class CreateSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    VersionId: Optional[SecretVersionIdType]
    ReplicationStatus: Optional[ReplicationStatusListType]


CreatedDateType = datetime


class DeleteResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType


class DeleteResourcePolicyResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[NameType]


RecoveryWindowInDaysType = int


class DeleteSecretRequest(ServiceRequest):
    SecretId: SecretIdType
    RecoveryWindowInDays: Optional[RecoveryWindowInDaysType]
    ForceDeleteWithoutRecovery: Optional[BooleanType]


DeletionDateType = datetime


class DeleteSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    DeletionDate: Optional[DeletionDateType]


DeletedDateType = datetime


class DescribeSecretRequest(ServiceRequest):
    SecretId: SecretIdType


TimestampType = datetime
SecretVersionStagesType = List[SecretVersionStageType]
SecretVersionsToStagesMapType = Dict[SecretVersionIdType, SecretVersionStagesType]
LastChangedDateType = datetime
LastRotatedDateType = datetime


class RotationRulesType(TypedDict, total=False):
    AutomaticallyAfterDays: Optional[AutomaticallyRotateAfterDaysType]
    Duration: Optional[DurationType]
    ScheduleExpression: Optional[ScheduleExpressionType]


class DescribeSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    Description: Optional[DescriptionType]
    KmsKeyId: Optional[KmsKeyIdType]
    RotationEnabled: Optional[RotationEnabledType]
    RotationLambdaARN: Optional[RotationLambdaARNType]
    RotationRules: Optional[RotationRulesType]
    LastRotatedDate: Optional[LastRotatedDateType]
    LastChangedDate: Optional[LastChangedDateType]
    LastAccessedDate: Optional[LastAccessedDateType]
    DeletedDate: Optional[DeletedDateType]
    Tags: Optional[TagListType]
    VersionIdsToStages: Optional[SecretVersionsToStagesMapType]
    OwningService: Optional[OwningServiceType]
    CreatedDate: Optional[TimestampType]
    PrimaryRegion: Optional[RegionType]
    ReplicationStatus: Optional[ReplicationStatusListType]


FilterValuesStringList = List[FilterValueStringType]


class Filter(TypedDict, total=False):
    Key: Optional[FilterNameStringType]
    Values: Optional[FilterValuesStringList]


FiltersListType = List[Filter]
PasswordLengthType = int


class GetRandomPasswordRequest(ServiceRequest):
    PasswordLength: Optional[PasswordLengthType]
    ExcludeCharacters: Optional[ExcludeCharactersType]
    ExcludeNumbers: Optional[ExcludeNumbersType]
    ExcludePunctuation: Optional[ExcludePunctuationType]
    ExcludeUppercase: Optional[ExcludeUppercaseType]
    ExcludeLowercase: Optional[ExcludeLowercaseType]
    IncludeSpace: Optional[IncludeSpaceType]
    RequireEachIncludedType: Optional[RequireEachIncludedTypeType]


class GetRandomPasswordResponse(TypedDict, total=False):
    RandomPassword: Optional[RandomPasswordType]


class GetResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType


class GetResourcePolicyResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[NameType]
    ResourcePolicy: Optional[NonEmptyResourcePolicyType]


class GetSecretValueRequest(ServiceRequest):
    SecretId: SecretIdType
    VersionId: Optional[SecretVersionIdType]
    VersionStage: Optional[SecretVersionStageType]


class GetSecretValueResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    VersionId: Optional[SecretVersionIdType]
    SecretBinary: Optional[SecretBinaryType]
    SecretString: Optional[SecretStringType]
    VersionStages: Optional[SecretVersionStagesType]
    CreatedDate: Optional[CreatedDateType]


KmsKeyIdListType = List[KmsKeyIdType]


class ListSecretVersionIdsRequest(ServiceRequest):
    SecretId: SecretIdType
    MaxResults: Optional[MaxResultsType]
    NextToken: Optional[NextTokenType]
    IncludeDeprecated: Optional[BooleanType]


class SecretVersionsListEntry(TypedDict, total=False):
    VersionId: Optional[SecretVersionIdType]
    VersionStages: Optional[SecretVersionStagesType]
    LastAccessedDate: Optional[LastAccessedDateType]
    CreatedDate: Optional[CreatedDateType]
    KmsKeyIds: Optional[KmsKeyIdListType]


SecretVersionsListType = List[SecretVersionsListEntry]


class ListSecretVersionIdsResponse(TypedDict, total=False):
    Versions: Optional[SecretVersionsListType]
    NextToken: Optional[NextTokenType]
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]


class ListSecretsRequest(ServiceRequest):
    MaxResults: Optional[MaxResultsType]
    NextToken: Optional[NextTokenType]
    Filters: Optional[FiltersListType]
    SortOrder: Optional[SortOrderType]


class SecretListEntry(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    Description: Optional[DescriptionType]
    KmsKeyId: Optional[KmsKeyIdType]
    RotationEnabled: Optional[RotationEnabledType]
    RotationLambdaARN: Optional[RotationLambdaARNType]
    RotationRules: Optional[RotationRulesType]
    LastRotatedDate: Optional[LastRotatedDateType]
    LastChangedDate: Optional[LastChangedDateType]
    LastAccessedDate: Optional[LastAccessedDateType]
    DeletedDate: Optional[DeletedDateType]
    Tags: Optional[TagListType]
    SecretVersionsToStages: Optional[SecretVersionsToStagesMapType]
    OwningService: Optional[OwningServiceType]
    CreatedDate: Optional[TimestampType]
    PrimaryRegion: Optional[RegionType]


SecretListType = List[SecretListEntry]


class ListSecretsResponse(TypedDict, total=False):
    SecretList: Optional[SecretListType]
    NextToken: Optional[NextTokenType]


class PutResourcePolicyRequest(ServiceRequest):
    SecretId: SecretIdType
    ResourcePolicy: NonEmptyResourcePolicyType
    BlockPublicPolicy: Optional[BooleanType]


class PutResourcePolicyResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[NameType]


class PutSecretValueRequest(ServiceRequest):
    SecretId: SecretIdType
    ClientRequestToken: Optional[ClientRequestTokenType]
    SecretBinary: Optional[SecretBinaryType]
    SecretString: Optional[SecretStringType]
    VersionStages: Optional[SecretVersionStagesType]


class PutSecretValueResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    VersionId: Optional[SecretVersionIdType]
    VersionStages: Optional[SecretVersionStagesType]


RemoveReplicaRegionListType = List[RegionType]


class RemoveRegionsFromReplicationRequest(ServiceRequest):
    SecretId: SecretIdType
    RemoveReplicaRegions: RemoveReplicaRegionListType


class RemoveRegionsFromReplicationResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    ReplicationStatus: Optional[ReplicationStatusListType]


class ReplicateSecretToRegionsRequest(ServiceRequest):
    SecretId: SecretIdType
    AddReplicaRegions: AddReplicaRegionListType
    ForceOverwriteReplicaSecret: Optional[BooleanType]


class ReplicateSecretToRegionsResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    ReplicationStatus: Optional[ReplicationStatusListType]


class RestoreSecretRequest(ServiceRequest):
    SecretId: SecretIdType


class RestoreSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]


class RotateSecretRequest(ServiceRequest):
    SecretId: SecretIdType
    ClientRequestToken: Optional[ClientRequestTokenType]
    RotationLambdaARN: Optional[RotationLambdaARNType]
    RotationRules: Optional[RotationRulesType]
    RotateImmediately: Optional[BooleanType]


class RotateSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    VersionId: Optional[SecretVersionIdType]


class StopReplicationToReplicaRequest(ServiceRequest):
    SecretId: SecretIdType


class StopReplicationToReplicaResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]


TagKeyListType = List[TagKeyType]


class TagResourceRequest(ServiceRequest):
    SecretId: SecretIdType
    Tags: TagListType


class UntagResourceRequest(ServiceRequest):
    SecretId: SecretIdType
    TagKeys: TagKeyListType


class UpdateSecretRequest(ServiceRequest):
    SecretId: SecretIdType
    ClientRequestToken: Optional[ClientRequestTokenType]
    Description: Optional[DescriptionType]
    KmsKeyId: Optional[KmsKeyIdType]
    SecretBinary: Optional[SecretBinaryType]
    SecretString: Optional[SecretStringType]


class UpdateSecretResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]
    VersionId: Optional[SecretVersionIdType]


class UpdateSecretVersionStageRequest(ServiceRequest):
    SecretId: SecretIdType
    VersionStage: SecretVersionStageType
    RemoveFromVersionId: Optional[SecretVersionIdType]
    MoveToVersionId: Optional[SecretVersionIdType]


class UpdateSecretVersionStageResponse(TypedDict, total=False):
    ARN: Optional[SecretARNType]
    Name: Optional[SecretNameType]


class ValidateResourcePolicyRequest(ServiceRequest):
    SecretId: Optional[SecretIdType]
    ResourcePolicy: NonEmptyResourcePolicyType


class ValidationErrorsEntry(TypedDict, total=False):
    CheckName: Optional[NameType]
    ErrorMessage: Optional[ErrorMessage]


ValidationErrorsType = List[ValidationErrorsEntry]


class ValidateResourcePolicyResponse(TypedDict, total=False):
    PolicyValidationPassed: Optional[BooleanType]
    ValidationErrors: Optional[ValidationErrorsType]


class SecretsmanagerApi:

    service = "secretsmanager"
    version = "2017-10-17"

    @handler("CancelRotateSecret")
    def cancel_rotate_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> CancelRotateSecretResponse:
        raise NotImplementedError

    @handler("CreateSecret")
    def create_secret(
        self,
        context: RequestContext,
        name: NameType,
        client_request_token: ClientRequestTokenType = None,
        description: DescriptionType = None,
        kms_key_id: KmsKeyIdType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        tags: TagListType = None,
        add_replica_regions: AddReplicaRegionListType = None,
        force_overwrite_replica_secret: BooleanType = None,
    ) -> CreateSecretResponse:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DeleteResourcePolicyResponse:
        raise NotImplementedError

    @handler("DeleteSecret")
    def delete_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        recovery_window_in_days: RecoveryWindowInDaysType = None,
        force_delete_without_recovery: BooleanType = None,
    ) -> DeleteSecretResponse:
        raise NotImplementedError

    @handler("DescribeSecret")
    def describe_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> DescribeSecretResponse:
        raise NotImplementedError

    @handler("GetRandomPassword")
    def get_random_password(
        self,
        context: RequestContext,
        password_length: PasswordLengthType = None,
        exclude_characters: ExcludeCharactersType = None,
        exclude_numbers: ExcludeNumbersType = None,
        exclude_punctuation: ExcludePunctuationType = None,
        exclude_uppercase: ExcludeUppercaseType = None,
        exclude_lowercase: ExcludeLowercaseType = None,
        include_space: IncludeSpaceType = None,
        require_each_included_type: RequireEachIncludedTypeType = None,
    ) -> GetRandomPasswordResponse:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> GetResourcePolicyResponse:
        raise NotImplementedError

    @handler("GetSecretValue")
    def get_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_id: SecretVersionIdType = None,
        version_stage: SecretVersionStageType = None,
    ) -> GetSecretValueResponse:
        raise NotImplementedError

    @handler("ListSecretVersionIds")
    def list_secret_version_ids(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        include_deprecated: BooleanType = None,
    ) -> ListSecretVersionIdsResponse:
        raise NotImplementedError

    @handler("ListSecrets")
    def list_secrets(
        self,
        context: RequestContext,
        max_results: MaxResultsType = None,
        next_token: NextTokenType = None,
        filters: FiltersListType = None,
        sort_order: SortOrderType = None,
    ) -> ListSecretsResponse:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        resource_policy: NonEmptyResourcePolicyType,
        block_public_policy: BooleanType = None,
    ) -> PutResourcePolicyResponse:
        raise NotImplementedError

    @handler("PutSecretValue")
    def put_secret_value(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
        version_stages: SecretVersionStagesType = None,
    ) -> PutSecretValueResponse:
        raise NotImplementedError

    @handler("RemoveRegionsFromReplication")
    def remove_regions_from_replication(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        remove_replica_regions: RemoveReplicaRegionListType,
    ) -> RemoveRegionsFromReplicationResponse:
        raise NotImplementedError

    @handler("ReplicateSecretToRegions")
    def replicate_secret_to_regions(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        add_replica_regions: AddReplicaRegionListType,
        force_overwrite_replica_secret: BooleanType = None,
    ) -> ReplicateSecretToRegionsResponse:
        raise NotImplementedError

    @handler("RestoreSecret")
    def restore_secret(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> RestoreSecretResponse:
        raise NotImplementedError

    @handler("RotateSecret")
    def rotate_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        rotation_lambda_arn: RotationLambdaARNType = None,
        rotation_rules: RotationRulesType = None,
        rotate_immediately: BooleanType = None,
    ) -> RotateSecretResponse:
        raise NotImplementedError

    @handler("StopReplicationToReplica")
    def stop_replication_to_replica(
        self, context: RequestContext, secret_id: SecretIdType
    ) -> StopReplicationToReplicaResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tags: TagListType
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, secret_id: SecretIdType, tag_keys: TagKeyListType
    ) -> None:
        raise NotImplementedError

    @handler("UpdateSecret")
    def update_secret(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        client_request_token: ClientRequestTokenType = None,
        description: DescriptionType = None,
        kms_key_id: KmsKeyIdType = None,
        secret_binary: SecretBinaryType = None,
        secret_string: SecretStringType = None,
    ) -> UpdateSecretResponse:
        raise NotImplementedError

    @handler("UpdateSecretVersionStage")
    def update_secret_version_stage(
        self,
        context: RequestContext,
        secret_id: SecretIdType,
        version_stage: SecretVersionStageType,
        remove_from_version_id: SecretVersionIdType = None,
        move_to_version_id: SecretVersionIdType = None,
    ) -> UpdateSecretVersionStageResponse:
        raise NotImplementedError

    @handler("ValidateResourcePolicy")
    def validate_resource_policy(
        self,
        context: RequestContext,
        resource_policy: NonEmptyResourcePolicyType,
        secret_id: SecretIdType = None,
    ) -> ValidateResourcePolicyResponse:
        raise NotImplementedError
