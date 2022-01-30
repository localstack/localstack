import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
Boolean = bool
DeletionProtection = bool
ErrorMessage = str
IonText = str
KmsKey = str
LedgerName = str
MaxResults = int
NextToken = str
ParameterName = str
ResourceName = str
ResourceType = str
S3Bucket = str
S3Prefix = str
StreamName = str
TagKey = str
TagValue = str
UniqueId = str


class EncryptionStatus(str):
    ENABLED = "ENABLED"
    UPDATING = "UPDATING"
    KMS_KEY_INACCESSIBLE = "KMS_KEY_INACCESSIBLE"


class ErrorCause(str):
    KINESIS_STREAM_NOT_FOUND = "KINESIS_STREAM_NOT_FOUND"
    IAM_PERMISSION_REVOKED = "IAM_PERMISSION_REVOKED"


class ExportStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class LedgerState(str):
    CREATING = "CREATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    DELETED = "DELETED"


class OutputFormat(str):
    ION_BINARY = "ION_BINARY"
    ION_TEXT = "ION_TEXT"
    JSON = "JSON"


class PermissionsMode(str):
    ALLOW_ALL = "ALLOW_ALL"
    STANDARD = "STANDARD"


class S3ObjectEncryptionType(str):
    SSE_KMS = "SSE_KMS"
    SSE_S3 = "SSE_S3"
    NO_ENCRYPTION = "NO_ENCRYPTION"


class StreamStatus(str):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"
    FAILED = "FAILED"
    IMPAIRED = "IMPAIRED"


class InvalidParameterException(ServiceException):
    Message: Optional[ErrorMessage]
    ParameterName: Optional[ParameterName]


class LimitExceededException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceType: Optional[ResourceType]


class ResourceAlreadyExistsException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceType: Optional[ResourceType]
    ResourceName: Optional[ResourceName]


class ResourceInUseException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceType: Optional[ResourceType]
    ResourceName: Optional[ResourceName]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceType: Optional[ResourceType]
    ResourceName: Optional[ResourceName]


class ResourcePreconditionNotMetException(ServiceException):
    Message: Optional[ErrorMessage]
    ResourceType: Optional[ResourceType]
    ResourceName: Optional[ResourceName]


class CancelJournalKinesisStreamRequest(ServiceRequest):
    LedgerName: LedgerName
    StreamId: UniqueId


class CancelJournalKinesisStreamResponse(TypedDict, total=False):
    StreamId: Optional[UniqueId]


Tags = Dict[TagKey, TagValue]


class CreateLedgerRequest(ServiceRequest):
    Name: LedgerName
    Tags: Optional[Tags]
    PermissionsMode: PermissionsMode
    DeletionProtection: Optional[DeletionProtection]
    KmsKey: Optional[KmsKey]


Timestamp = datetime


class CreateLedgerResponse(TypedDict, total=False):
    Name: Optional[LedgerName]
    Arn: Optional[Arn]
    State: Optional[LedgerState]
    CreationDateTime: Optional[Timestamp]
    PermissionsMode: Optional[PermissionsMode]
    DeletionProtection: Optional[DeletionProtection]
    KmsKeyArn: Optional[Arn]


class DeleteLedgerRequest(ServiceRequest):
    Name: LedgerName


class DescribeJournalKinesisStreamRequest(ServiceRequest):
    LedgerName: LedgerName
    StreamId: UniqueId


class KinesisConfiguration(TypedDict, total=False):
    StreamArn: Arn
    AggregationEnabled: Optional[Boolean]


class JournalKinesisStreamDescription(TypedDict, total=False):
    LedgerName: LedgerName
    CreationTime: Optional[Timestamp]
    InclusiveStartTime: Optional[Timestamp]
    ExclusiveEndTime: Optional[Timestamp]
    RoleArn: Arn
    StreamId: UniqueId
    Arn: Optional[Arn]
    Status: StreamStatus
    KinesisConfiguration: KinesisConfiguration
    ErrorCause: Optional[ErrorCause]
    StreamName: StreamName


class DescribeJournalKinesisStreamResponse(TypedDict, total=False):
    Stream: Optional[JournalKinesisStreamDescription]


class DescribeJournalS3ExportRequest(ServiceRequest):
    Name: LedgerName
    ExportId: UniqueId


class S3EncryptionConfiguration(TypedDict, total=False):
    ObjectEncryptionType: S3ObjectEncryptionType
    KmsKeyArn: Optional[Arn]


class S3ExportConfiguration(TypedDict, total=False):
    Bucket: S3Bucket
    Prefix: S3Prefix
    EncryptionConfiguration: S3EncryptionConfiguration


class JournalS3ExportDescription(TypedDict, total=False):
    LedgerName: LedgerName
    ExportId: UniqueId
    ExportCreationTime: Timestamp
    Status: ExportStatus
    InclusiveStartTime: Timestamp
    ExclusiveEndTime: Timestamp
    S3ExportConfiguration: S3ExportConfiguration
    RoleArn: Arn
    OutputFormat: Optional[OutputFormat]


class DescribeJournalS3ExportResponse(TypedDict, total=False):
    ExportDescription: JournalS3ExportDescription


class DescribeLedgerRequest(ServiceRequest):
    Name: LedgerName


class LedgerEncryptionDescription(TypedDict, total=False):
    KmsKeyArn: Arn
    EncryptionStatus: EncryptionStatus
    InaccessibleKmsKeyDateTime: Optional[Timestamp]


class DescribeLedgerResponse(TypedDict, total=False):
    Name: Optional[LedgerName]
    Arn: Optional[Arn]
    State: Optional[LedgerState]
    CreationDateTime: Optional[Timestamp]
    PermissionsMode: Optional[PermissionsMode]
    DeletionProtection: Optional[DeletionProtection]
    EncryptionDescription: Optional[LedgerEncryptionDescription]


Digest = bytes


class ExportJournalToS3Request(ServiceRequest):
    Name: LedgerName
    InclusiveStartTime: Timestamp
    ExclusiveEndTime: Timestamp
    S3ExportConfiguration: S3ExportConfiguration
    RoleArn: Arn
    OutputFormat: Optional[OutputFormat]


class ExportJournalToS3Response(TypedDict, total=False):
    ExportId: UniqueId


class ValueHolder(TypedDict, total=False):
    IonText: Optional[IonText]


class GetBlockRequest(ServiceRequest):
    Name: LedgerName
    BlockAddress: ValueHolder
    DigestTipAddress: Optional[ValueHolder]


class GetBlockResponse(TypedDict, total=False):
    Block: ValueHolder
    Proof: Optional[ValueHolder]


class GetDigestRequest(ServiceRequest):
    Name: LedgerName


class GetDigestResponse(TypedDict, total=False):
    Digest: Digest
    DigestTipAddress: ValueHolder


class GetRevisionRequest(ServiceRequest):
    Name: LedgerName
    BlockAddress: ValueHolder
    DocumentId: UniqueId
    DigestTipAddress: Optional[ValueHolder]


class GetRevisionResponse(TypedDict, total=False):
    Proof: Optional[ValueHolder]
    Revision: ValueHolder


JournalKinesisStreamDescriptionList = List[JournalKinesisStreamDescription]
JournalS3ExportList = List[JournalS3ExportDescription]


class LedgerSummary(TypedDict, total=False):
    Name: Optional[LedgerName]
    State: Optional[LedgerState]
    CreationDateTime: Optional[Timestamp]


LedgerList = List[LedgerSummary]


class ListJournalKinesisStreamsForLedgerRequest(ServiceRequest):
    LedgerName: LedgerName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListJournalKinesisStreamsForLedgerResponse(TypedDict, total=False):
    Streams: Optional[JournalKinesisStreamDescriptionList]
    NextToken: Optional[NextToken]


class ListJournalS3ExportsForLedgerRequest(ServiceRequest):
    Name: LedgerName
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListJournalS3ExportsForLedgerResponse(TypedDict, total=False):
    JournalS3Exports: Optional[JournalS3ExportList]
    NextToken: Optional[NextToken]


class ListJournalS3ExportsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListJournalS3ExportsResponse(TypedDict, total=False):
    JournalS3Exports: Optional[JournalS3ExportList]
    NextToken: Optional[NextToken]


class ListLedgersRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListLedgersResponse(TypedDict, total=False):
    Ledgers: Optional[LedgerList]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: Arn


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[Tags]


class StreamJournalToKinesisRequest(ServiceRequest):
    LedgerName: LedgerName
    RoleArn: Arn
    Tags: Optional[Tags]
    InclusiveStartTime: Timestamp
    ExclusiveEndTime: Optional[Timestamp]
    KinesisConfiguration: KinesisConfiguration
    StreamName: StreamName


class StreamJournalToKinesisResponse(TypedDict, total=False):
    StreamId: Optional[UniqueId]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: Arn
    Tags: Tags


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceArn: Arn
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateLedgerPermissionsModeRequest(ServiceRequest):
    Name: LedgerName
    PermissionsMode: PermissionsMode


class UpdateLedgerPermissionsModeResponse(TypedDict, total=False):
    Name: Optional[LedgerName]
    Arn: Optional[Arn]
    PermissionsMode: Optional[PermissionsMode]


class UpdateLedgerRequest(ServiceRequest):
    Name: LedgerName
    DeletionProtection: Optional[DeletionProtection]
    KmsKey: Optional[KmsKey]


class UpdateLedgerResponse(TypedDict, total=False):
    Name: Optional[LedgerName]
    Arn: Optional[Arn]
    State: Optional[LedgerState]
    CreationDateTime: Optional[Timestamp]
    DeletionProtection: Optional[DeletionProtection]
    EncryptionDescription: Optional[LedgerEncryptionDescription]


class QldbApi:

    service = "qldb"
    version = "2019-01-02"

    @handler("CancelJournalKinesisStream")
    def cancel_journal_kinesis_stream(
        self, context: RequestContext, ledger_name: LedgerName, stream_id: UniqueId
    ) -> CancelJournalKinesisStreamResponse:
        raise NotImplementedError

    @handler("CreateLedger")
    def create_ledger(
        self,
        context: RequestContext,
        name: LedgerName,
        permissions_mode: PermissionsMode,
        tags: Tags = None,
        deletion_protection: DeletionProtection = None,
        kms_key: KmsKey = None,
    ) -> CreateLedgerResponse:
        raise NotImplementedError

    @handler("DeleteLedger")
    def delete_ledger(self, context: RequestContext, name: LedgerName) -> None:
        raise NotImplementedError

    @handler("DescribeJournalKinesisStream")
    def describe_journal_kinesis_stream(
        self, context: RequestContext, ledger_name: LedgerName, stream_id: UniqueId
    ) -> DescribeJournalKinesisStreamResponse:
        raise NotImplementedError

    @handler("DescribeJournalS3Export")
    def describe_journal_s3_export(
        self, context: RequestContext, name: LedgerName, export_id: UniqueId
    ) -> DescribeJournalS3ExportResponse:
        raise NotImplementedError

    @handler("DescribeLedger")
    def describe_ledger(self, context: RequestContext, name: LedgerName) -> DescribeLedgerResponse:
        raise NotImplementedError

    @handler("ExportJournalToS3")
    def export_journal_to_s3(
        self,
        context: RequestContext,
        name: LedgerName,
        inclusive_start_time: Timestamp,
        exclusive_end_time: Timestamp,
        s3_export_configuration: S3ExportConfiguration,
        role_arn: Arn,
        output_format: OutputFormat = None,
    ) -> ExportJournalToS3Response:
        raise NotImplementedError

    @handler("GetBlock")
    def get_block(
        self,
        context: RequestContext,
        name: LedgerName,
        block_address: ValueHolder,
        digest_tip_address: ValueHolder = None,
    ) -> GetBlockResponse:
        raise NotImplementedError

    @handler("GetDigest")
    def get_digest(self, context: RequestContext, name: LedgerName) -> GetDigestResponse:
        raise NotImplementedError

    @handler("GetRevision")
    def get_revision(
        self,
        context: RequestContext,
        name: LedgerName,
        block_address: ValueHolder,
        document_id: UniqueId,
        digest_tip_address: ValueHolder = None,
    ) -> GetRevisionResponse:
        raise NotImplementedError

    @handler("ListJournalKinesisStreamsForLedger")
    def list_journal_kinesis_streams_for_ledger(
        self,
        context: RequestContext,
        ledger_name: LedgerName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListJournalKinesisStreamsForLedgerResponse:
        raise NotImplementedError

    @handler("ListJournalS3Exports")
    def list_journal_s3_exports(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListJournalS3ExportsResponse:
        raise NotImplementedError

    @handler("ListJournalS3ExportsForLedger")
    def list_journal_s3_exports_for_ledger(
        self,
        context: RequestContext,
        name: LedgerName,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListJournalS3ExportsForLedgerResponse:
        raise NotImplementedError

    @handler("ListLedgers")
    def list_ledgers(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListLedgersResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("StreamJournalToKinesis")
    def stream_journal_to_kinesis(
        self,
        context: RequestContext,
        ledger_name: LedgerName,
        role_arn: Arn,
        inclusive_start_time: Timestamp,
        kinesis_configuration: KinesisConfiguration,
        stream_name: StreamName,
        tags: Tags = None,
        exclusive_end_time: Timestamp = None,
    ) -> StreamJournalToKinesisResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: Tags
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateLedger")
    def update_ledger(
        self,
        context: RequestContext,
        name: LedgerName,
        deletion_protection: DeletionProtection = None,
        kms_key: KmsKey = None,
    ) -> UpdateLedgerResponse:
        raise NotImplementedError

    @handler("UpdateLedgerPermissionsMode")
    def update_ledger_permissions_mode(
        self, context: RequestContext, name: LedgerName, permissions_mode: PermissionsMode
    ) -> UpdateLedgerPermissionsModeResponse:
        raise NotImplementedError
