import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

DateTime = str
TagKey = str
TagValue = str
boolean = bool
httpstatus = int
string = str


class ActionCode(str):
    ArchiveRetrieval = "ArchiveRetrieval"
    InventoryRetrieval = "InventoryRetrieval"
    Select = "Select"


class CannedACL(str):
    private = "private"
    public_read = "public-read"
    public_read_write = "public-read-write"
    aws_exec_read = "aws-exec-read"
    authenticated_read = "authenticated-read"
    bucket_owner_read = "bucket-owner-read"
    bucket_owner_full_control = "bucket-owner-full-control"


class EncryptionType(str):
    aws_kms = "aws:kms"
    AES256 = "AES256"


class ExpressionType(str):
    SQL = "SQL"


class FileHeaderInfo(str):
    USE = "USE"
    IGNORE = "IGNORE"
    NONE = "NONE"


class Permission(str):
    FULL_CONTROL = "FULL_CONTROL"
    WRITE = "WRITE"
    WRITE_ACP = "WRITE_ACP"
    READ = "READ"
    READ_ACP = "READ_ACP"


class QuoteFields(str):
    ALWAYS = "ALWAYS"
    ASNEEDED = "ASNEEDED"


class StatusCode(str):
    InProgress = "InProgress"
    Succeeded = "Succeeded"
    Failed = "Failed"


class StorageClass(str):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    STANDARD_IA = "STANDARD_IA"


class Type(str):
    AmazonCustomerByEmail = "AmazonCustomerByEmail"
    CanonicalUser = "CanonicalUser"
    Group = "Group"


class InsufficientCapacityException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class InvalidParameterValueException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class LimitExceededException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class MissingParameterValueException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class PolicyEnforcedException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class RequestTimeoutException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class ResourceNotFoundException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class ServiceUnavailableException(ServiceException):
    type: Optional[string]
    code: Optional[string]
    message: Optional[string]


class AbortMultipartUploadInput(ServiceRequest):
    accountId: string
    vaultName: string
    uploadId: string


class AbortVaultLockInput(ServiceRequest):
    accountId: string
    vaultName: string


class Grantee(TypedDict, total=False):
    Type: Type
    DisplayName: Optional[string]
    URI: Optional[string]
    ID: Optional[string]
    EmailAddress: Optional[string]


class Grant(TypedDict, total=False):
    Grantee: Optional[Grantee]
    Permission: Optional[Permission]


AccessControlPolicyList = List[Grant]
TagMap = Dict[TagKey, TagValue]


class AddTagsToVaultInput(ServiceRequest):
    accountId: string
    vaultName: string
    Tags: Optional[TagMap]


class ArchiveCreationOutput(TypedDict, total=False):
    location: Optional[string]
    checksum: Optional[string]
    archiveId: Optional[string]


class CSVInput(TypedDict, total=False):
    FileHeaderInfo: Optional[FileHeaderInfo]
    Comments: Optional[string]
    QuoteEscapeCharacter: Optional[string]
    RecordDelimiter: Optional[string]
    FieldDelimiter: Optional[string]
    QuoteCharacter: Optional[string]


class CSVOutput(TypedDict, total=False):
    QuoteFields: Optional[QuoteFields]
    QuoteEscapeCharacter: Optional[string]
    RecordDelimiter: Optional[string]
    FieldDelimiter: Optional[string]
    QuoteCharacter: Optional[string]


class CompleteMultipartUploadInput(ServiceRequest):
    accountId: string
    vaultName: string
    uploadId: string
    archiveSize: Optional[string]
    checksum: Optional[string]


class CompleteVaultLockInput(ServiceRequest):
    accountId: string
    vaultName: string
    lockId: string


class CreateVaultInput(ServiceRequest):
    accountId: string
    vaultName: string


class CreateVaultOutput(TypedDict, total=False):
    location: Optional[string]


NullableLong = int


class DataRetrievalRule(TypedDict, total=False):
    Strategy: Optional[string]
    BytesPerHour: Optional[NullableLong]


DataRetrievalRulesList = List[DataRetrievalRule]


class DataRetrievalPolicy(TypedDict, total=False):
    Rules: Optional[DataRetrievalRulesList]


class DeleteArchiveInput(ServiceRequest):
    accountId: string
    vaultName: string
    archiveId: string


class DeleteVaultAccessPolicyInput(ServiceRequest):
    accountId: string
    vaultName: string


class DeleteVaultInput(ServiceRequest):
    accountId: string
    vaultName: string


class DeleteVaultNotificationsInput(ServiceRequest):
    accountId: string
    vaultName: string


class DescribeJobInput(ServiceRequest):
    accountId: string
    vaultName: string
    jobId: string


class DescribeVaultInput(ServiceRequest):
    accountId: string
    vaultName: string


long = int


class DescribeVaultOutput(TypedDict, total=False):
    VaultARN: Optional[string]
    VaultName: Optional[string]
    CreationDate: Optional[string]
    LastInventoryDate: Optional[string]
    NumberOfArchives: Optional[long]
    SizeInBytes: Optional[long]


class Encryption(TypedDict, total=False):
    EncryptionType: Optional[EncryptionType]
    KMSKeyId: Optional[string]
    KMSContext: Optional[string]


class GetDataRetrievalPolicyInput(ServiceRequest):
    accountId: string


class GetDataRetrievalPolicyOutput(TypedDict, total=False):
    Policy: Optional[DataRetrievalPolicy]


class GetJobOutputInput(ServiceRequest):
    accountId: string
    vaultName: string
    jobId: string
    range: Optional[string]


Stream = bytes


class GetJobOutputOutput(TypedDict, total=False):
    body: Optional[Stream]
    checksum: Optional[string]
    status: Optional[httpstatus]
    contentRange: Optional[string]
    acceptRanges: Optional[string]
    contentType: Optional[string]
    archiveDescription: Optional[string]


class GetVaultAccessPolicyInput(ServiceRequest):
    accountId: string
    vaultName: string


class VaultAccessPolicy(TypedDict, total=False):
    Policy: Optional[string]


class GetVaultAccessPolicyOutput(TypedDict, total=False):
    policy: Optional[VaultAccessPolicy]


class GetVaultLockInput(ServiceRequest):
    accountId: string
    vaultName: string


class GetVaultLockOutput(TypedDict, total=False):
    Policy: Optional[string]
    State: Optional[string]
    ExpirationDate: Optional[string]
    CreationDate: Optional[string]


class GetVaultNotificationsInput(ServiceRequest):
    accountId: string
    vaultName: string


NotificationEventList = List[string]


class VaultNotificationConfig(TypedDict, total=False):
    SNSTopic: Optional[string]
    Events: Optional[NotificationEventList]


class GetVaultNotificationsOutput(TypedDict, total=False):
    vaultNotificationConfig: Optional[VaultNotificationConfig]


hashmap = Dict[string, string]


class S3Location(TypedDict, total=False):
    BucketName: Optional[string]
    Prefix: Optional[string]
    Encryption: Optional[Encryption]
    CannedACL: Optional[CannedACL]
    AccessControlList: Optional[AccessControlPolicyList]
    Tagging: Optional[hashmap]
    UserMetadata: Optional[hashmap]
    StorageClass: Optional[StorageClass]


class OutputLocation(TypedDict, total=False):
    S3: Optional[S3Location]


class OutputSerialization(TypedDict, total=False):
    csv: Optional[CSVOutput]


class InputSerialization(TypedDict, total=False):
    csv: Optional[CSVInput]


class SelectParameters(TypedDict, total=False):
    InputSerialization: Optional[InputSerialization]
    ExpressionType: Optional[ExpressionType]
    Expression: Optional[string]
    OutputSerialization: Optional[OutputSerialization]


class InventoryRetrievalJobDescription(TypedDict, total=False):
    Format: Optional[string]
    StartDate: Optional[DateTime]
    EndDate: Optional[DateTime]
    Limit: Optional[string]
    Marker: Optional[string]


Size = int


class GlacierJobDescription(TypedDict, total=False):
    JobId: Optional[string]
    JobDescription: Optional[string]
    Action: Optional[ActionCode]
    ArchiveId: Optional[string]
    VaultARN: Optional[string]
    CreationDate: Optional[string]
    Completed: Optional[boolean]
    StatusCode: Optional[StatusCode]
    StatusMessage: Optional[string]
    ArchiveSizeInBytes: Optional[Size]
    InventorySizeInBytes: Optional[Size]
    SNSTopic: Optional[string]
    CompletionDate: Optional[string]
    SHA256TreeHash: Optional[string]
    ArchiveSHA256TreeHash: Optional[string]
    RetrievalByteRange: Optional[string]
    Tier: Optional[string]
    InventoryRetrievalParameters: Optional[InventoryRetrievalJobDescription]
    JobOutputPath: Optional[string]
    SelectParameters: Optional[SelectParameters]
    OutputLocation: Optional[OutputLocation]


class InventoryRetrievalJobInput(TypedDict, total=False):
    StartDate: Optional[string]
    EndDate: Optional[string]
    Limit: Optional[string]
    Marker: Optional[string]


class JobParameters(TypedDict, total=False):
    Format: Optional[string]
    Type: Optional[string]
    ArchiveId: Optional[string]
    Description: Optional[string]
    SNSTopic: Optional[string]
    RetrievalByteRange: Optional[string]
    Tier: Optional[string]
    InventoryRetrievalParameters: Optional[InventoryRetrievalJobInput]
    SelectParameters: Optional[SelectParameters]
    OutputLocation: Optional[OutputLocation]


class InitiateJobInput(ServiceRequest):
    accountId: string
    vaultName: string
    jobParameters: Optional[JobParameters]


class InitiateJobOutput(TypedDict, total=False):
    location: Optional[string]
    jobId: Optional[string]
    jobOutputPath: Optional[string]


class InitiateMultipartUploadInput(ServiceRequest):
    accountId: string
    vaultName: string
    archiveDescription: Optional[string]
    partSize: Optional[string]


class InitiateMultipartUploadOutput(TypedDict, total=False):
    location: Optional[string]
    uploadId: Optional[string]


class VaultLockPolicy(TypedDict, total=False):
    Policy: Optional[string]


class InitiateVaultLockInput(ServiceRequest):
    accountId: string
    vaultName: string
    policy: Optional[VaultLockPolicy]


class InitiateVaultLockOutput(TypedDict, total=False):
    lockId: Optional[string]


JobList = List[GlacierJobDescription]


class ListJobsInput(ServiceRequest):
    accountId: string
    vaultName: string
    limit: Optional[string]
    marker: Optional[string]
    statuscode: Optional[string]
    completed: Optional[string]


class ListJobsOutput(TypedDict, total=False):
    JobList: Optional[JobList]
    Marker: Optional[string]


class ListMultipartUploadsInput(ServiceRequest):
    accountId: string
    vaultName: string
    marker: Optional[string]
    limit: Optional[string]


class UploadListElement(TypedDict, total=False):
    MultipartUploadId: Optional[string]
    VaultARN: Optional[string]
    ArchiveDescription: Optional[string]
    PartSizeInBytes: Optional[long]
    CreationDate: Optional[string]


UploadsList = List[UploadListElement]


class ListMultipartUploadsOutput(TypedDict, total=False):
    UploadsList: Optional[UploadsList]
    Marker: Optional[string]


class ListPartsInput(ServiceRequest):
    accountId: string
    vaultName: string
    uploadId: string
    marker: Optional[string]
    limit: Optional[string]


class PartListElement(TypedDict, total=False):
    RangeInBytes: Optional[string]
    SHA256TreeHash: Optional[string]


PartList = List[PartListElement]


class ListPartsOutput(TypedDict, total=False):
    MultipartUploadId: Optional[string]
    VaultARN: Optional[string]
    ArchiveDescription: Optional[string]
    PartSizeInBytes: Optional[long]
    CreationDate: Optional[string]
    Parts: Optional[PartList]
    Marker: Optional[string]


class ListProvisionedCapacityInput(ServiceRequest):
    accountId: string


class ProvisionedCapacityDescription(TypedDict, total=False):
    CapacityId: Optional[string]
    StartDate: Optional[string]
    ExpirationDate: Optional[string]


ProvisionedCapacityList = List[ProvisionedCapacityDescription]


class ListProvisionedCapacityOutput(TypedDict, total=False):
    ProvisionedCapacityList: Optional[ProvisionedCapacityList]


class ListTagsForVaultInput(ServiceRequest):
    accountId: string
    vaultName: string


class ListTagsForVaultOutput(TypedDict, total=False):
    Tags: Optional[TagMap]


class ListVaultsInput(ServiceRequest):
    accountId: string
    marker: Optional[string]
    limit: Optional[string]


VaultList = List[DescribeVaultOutput]


class ListVaultsOutput(TypedDict, total=False):
    VaultList: Optional[VaultList]
    Marker: Optional[string]


class PurchaseProvisionedCapacityInput(ServiceRequest):
    accountId: string


class PurchaseProvisionedCapacityOutput(TypedDict, total=False):
    capacityId: Optional[string]


TagKeyList = List[string]


class RemoveTagsFromVaultInput(ServiceRequest):
    accountId: string
    vaultName: string
    TagKeys: Optional[TagKeyList]


class SetDataRetrievalPolicyInput(ServiceRequest):
    accountId: string
    Policy: Optional[DataRetrievalPolicy]


class SetVaultAccessPolicyInput(ServiceRequest):
    accountId: string
    vaultName: string
    policy: Optional[VaultAccessPolicy]


class SetVaultNotificationsInput(ServiceRequest):
    accountId: string
    vaultName: string
    vaultNotificationConfig: Optional[VaultNotificationConfig]


class UploadArchiveInput(ServiceRequest):
    vaultName: string
    accountId: string
    archiveDescription: Optional[string]
    checksum: Optional[string]
    body: Optional[Stream]


class UploadMultipartPartInput(ServiceRequest):
    accountId: string
    vaultName: string
    uploadId: string
    checksum: Optional[string]
    range: Optional[string]
    body: Optional[Stream]


class UploadMultipartPartOutput(TypedDict, total=False):
    checksum: Optional[string]


class GlacierApi:

    service = "glacier"
    version = "2012-06-01"

    @handler("AbortMultipartUpload")
    def abort_multipart_upload(
        self, context: RequestContext, account_id: string, vault_name: string, upload_id: string
    ) -> None:
        raise NotImplementedError

    @handler("AbortVaultLock")
    def abort_vault_lock(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> None:
        raise NotImplementedError

    @handler("AddTagsToVault")
    def add_tags_to_vault(
        self, context: RequestContext, account_id: string, vault_name: string, tags: TagMap = None
    ) -> None:
        raise NotImplementedError

    @handler("CompleteMultipartUpload")
    def complete_multipart_upload(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        upload_id: string,
        archive_size: string = None,
        checksum: string = None,
    ) -> ArchiveCreationOutput:
        raise NotImplementedError

    @handler("CompleteVaultLock")
    def complete_vault_lock(
        self, context: RequestContext, account_id: string, vault_name: string, lock_id: string
    ) -> None:
        raise NotImplementedError

    @handler("CreateVault")
    def create_vault(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> CreateVaultOutput:
        raise NotImplementedError

    @handler("DeleteArchive")
    def delete_archive(
        self, context: RequestContext, account_id: string, vault_name: string, archive_id: string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVault")
    def delete_vault(self, context: RequestContext, account_id: string, vault_name: string) -> None:
        raise NotImplementedError

    @handler("DeleteVaultAccessPolicy")
    def delete_vault_access_policy(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVaultNotifications")
    def delete_vault_notifications(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> None:
        raise NotImplementedError

    @handler("DescribeJob")
    def describe_job(
        self, context: RequestContext, account_id: string, vault_name: string, job_id: string
    ) -> GlacierJobDescription:
        raise NotImplementedError

    @handler("DescribeVault")
    def describe_vault(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> DescribeVaultOutput:
        raise NotImplementedError

    @handler("GetDataRetrievalPolicy")
    def get_data_retrieval_policy(
        self, context: RequestContext, account_id: string
    ) -> GetDataRetrievalPolicyOutput:
        raise NotImplementedError

    @handler("GetJobOutput")
    def get_job_output(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        job_id: string,
        range: string = None,
    ) -> GetJobOutputOutput:
        raise NotImplementedError

    @handler("GetVaultAccessPolicy")
    def get_vault_access_policy(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> GetVaultAccessPolicyOutput:
        raise NotImplementedError

    @handler("GetVaultLock")
    def get_vault_lock(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> GetVaultLockOutput:
        raise NotImplementedError

    @handler("GetVaultNotifications")
    def get_vault_notifications(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> GetVaultNotificationsOutput:
        raise NotImplementedError

    @handler("InitiateJob")
    def initiate_job(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        job_parameters: JobParameters = None,
    ) -> InitiateJobOutput:
        raise NotImplementedError

    @handler("InitiateMultipartUpload")
    def initiate_multipart_upload(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        archive_description: string = None,
        part_size: string = None,
    ) -> InitiateMultipartUploadOutput:
        raise NotImplementedError

    @handler("InitiateVaultLock")
    def initiate_vault_lock(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        policy: VaultLockPolicy = None,
    ) -> InitiateVaultLockOutput:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        limit: string = None,
        marker: string = None,
        statuscode: string = None,
        completed: string = None,
    ) -> ListJobsOutput:
        raise NotImplementedError

    @handler("ListMultipartUploads")
    def list_multipart_uploads(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        marker: string = None,
        limit: string = None,
    ) -> ListMultipartUploadsOutput:
        raise NotImplementedError

    @handler("ListParts")
    def list_parts(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        upload_id: string,
        marker: string = None,
        limit: string = None,
    ) -> ListPartsOutput:
        raise NotImplementedError

    @handler("ListProvisionedCapacity")
    def list_provisioned_capacity(
        self, context: RequestContext, account_id: string
    ) -> ListProvisionedCapacityOutput:
        raise NotImplementedError

    @handler("ListTagsForVault")
    def list_tags_for_vault(
        self, context: RequestContext, account_id: string, vault_name: string
    ) -> ListTagsForVaultOutput:
        raise NotImplementedError

    @handler("ListVaults")
    def list_vaults(
        self,
        context: RequestContext,
        account_id: string,
        marker: string = None,
        limit: string = None,
    ) -> ListVaultsOutput:
        raise NotImplementedError

    @handler("PurchaseProvisionedCapacity")
    def purchase_provisioned_capacity(
        self, context: RequestContext, account_id: string
    ) -> PurchaseProvisionedCapacityOutput:
        raise NotImplementedError

    @handler("RemoveTagsFromVault")
    def remove_tags_from_vault(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        tag_keys: TagKeyList = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetDataRetrievalPolicy")
    def set_data_retrieval_policy(
        self, context: RequestContext, account_id: string, policy: DataRetrievalPolicy = None
    ) -> None:
        raise NotImplementedError

    @handler("SetVaultAccessPolicy")
    def set_vault_access_policy(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        policy: VaultAccessPolicy = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetVaultNotifications")
    def set_vault_notifications(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        vault_notification_config: VaultNotificationConfig = None,
    ) -> None:
        raise NotImplementedError

    @handler("UploadArchive")
    def upload_archive(
        self,
        context: RequestContext,
        vault_name: string,
        account_id: string,
        archive_description: string = None,
        checksum: string = None,
        body: Stream = None,
    ) -> ArchiveCreationOutput:
        raise NotImplementedError

    @handler("UploadMultipartPart")
    def upload_multipart_part(
        self,
        context: RequestContext,
        account_id: string,
        vault_name: string,
        upload_id: string,
        checksum: string = None,
        range: string = None,
        body: Stream = None,
    ) -> UploadMultipartPartOutput:
        raise NotImplementedError
