from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AttributeName = str
BooleanAttributeValue = bool
ErrorMessage = str
KeySchemaAttributeName = str
NullAttributeValue = bool
NumberAttributeValue = str
PositiveIntegerObject = int
SequenceNumber = str
ShardId = str
ShardIterator = str
StreamArn = str
String = str
StringAttributeValue = str
TableName = str


class KeyType(StrEnum):
    HASH = "HASH"
    RANGE = "RANGE"


class OperationType(StrEnum):
    INSERT = "INSERT"
    MODIFY = "MODIFY"
    REMOVE = "REMOVE"


class ShardFilterType(StrEnum):
    CHILD_SHARDS = "CHILD_SHARDS"


class ShardIteratorType(StrEnum):
    TRIM_HORIZON = "TRIM_HORIZON"
    LATEST = "LATEST"
    AT_SEQUENCE_NUMBER = "AT_SEQUENCE_NUMBER"
    AFTER_SEQUENCE_NUMBER = "AFTER_SEQUENCE_NUMBER"


class StreamStatus(StrEnum):
    ENABLING = "ENABLING"
    ENABLED = "ENABLED"
    DISABLING = "DISABLING"
    DISABLED = "DISABLED"


class StreamViewType(StrEnum):
    NEW_IMAGE = "NEW_IMAGE"
    OLD_IMAGE = "OLD_IMAGE"
    NEW_AND_OLD_IMAGES = "NEW_AND_OLD_IMAGES"
    KEYS_ONLY = "KEYS_ONLY"


class ExpiredIteratorException(ServiceException):
    code: str = "ExpiredIteratorException"
    sender_fault: bool = False
    status_code: int = 400


class InternalServerError(ServiceException):
    code: str = "InternalServerError"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TrimmedDataAccessException(ServiceException):
    code: str = "TrimmedDataAccessException"
    sender_fault: bool = False
    status_code: int = 400


class AttributeValue(TypedDict, total=False):
    S: "StringAttributeValue | None"
    N: "NumberAttributeValue | None"
    B: "BinaryAttributeValue | None"
    SS: "StringSetAttributeValue | None"
    NS: "NumberSetAttributeValue | None"
    BS: "BinarySetAttributeValue | None"
    M: "MapAttributeValue | None"
    L: "ListAttributeValue | None"
    NULL: "NullAttributeValue | None"
    BOOL: "BooleanAttributeValue | None"


ListAttributeValue = list[AttributeValue]
MapAttributeValue = dict[AttributeName, AttributeValue]
BinaryAttributeValue = bytes
BinarySetAttributeValue = list[BinaryAttributeValue]
NumberSetAttributeValue = list[NumberAttributeValue]
StringSetAttributeValue = list[StringAttributeValue]
AttributeMap = dict[AttributeName, AttributeValue]
Date = datetime


class ShardFilter(TypedDict, total=False):
    Type: ShardFilterType | None
    ShardId: ShardId | None


class DescribeStreamInput(ServiceRequest):
    StreamArn: StreamArn
    Limit: PositiveIntegerObject | None
    ExclusiveStartShardId: ShardId | None
    ShardFilter: ShardFilter | None


class SequenceNumberRange(TypedDict, total=False):
    StartingSequenceNumber: SequenceNumber | None
    EndingSequenceNumber: SequenceNumber | None


class Shard(TypedDict, total=False):
    ShardId: ShardId | None
    SequenceNumberRange: SequenceNumberRange | None
    ParentShardId: ShardId | None


ShardDescriptionList = list[Shard]


class KeySchemaElement(TypedDict, total=False):
    AttributeName: KeySchemaAttributeName
    KeyType: KeyType


KeySchema = list[KeySchemaElement]


class StreamDescription(TypedDict, total=False):
    StreamArn: StreamArn | None
    StreamLabel: String | None
    StreamStatus: StreamStatus | None
    StreamViewType: StreamViewType | None
    CreationRequestDateTime: Date | None
    TableName: TableName | None
    KeySchema: KeySchema | None
    Shards: ShardDescriptionList | None
    LastEvaluatedShardId: ShardId | None


class DescribeStreamOutput(TypedDict, total=False):
    StreamDescription: StreamDescription | None


class GetRecordsInput(ServiceRequest):
    ShardIterator: ShardIterator
    Limit: PositiveIntegerObject | None


class Identity(TypedDict, total=False):
    PrincipalId: String | None
    Type: String | None


PositiveLongObject = int


class StreamRecord(TypedDict, total=False):
    ApproximateCreationDateTime: Date | None
    Keys: AttributeMap | None
    NewImage: AttributeMap | None
    OldImage: AttributeMap | None
    SequenceNumber: SequenceNumber | None
    SizeBytes: PositiveLongObject | None
    StreamViewType: StreamViewType | None


class Record(TypedDict, total=False):
    eventID: String | None
    eventName: OperationType | None
    eventVersion: String | None
    eventSource: String | None
    awsRegion: String | None
    dynamodb: StreamRecord | None
    userIdentity: Identity | None


RecordList = list[Record]


class GetRecordsOutput(TypedDict, total=False):
    Records: RecordList | None
    NextShardIterator: ShardIterator | None


class GetShardIteratorInput(ServiceRequest):
    StreamArn: StreamArn
    ShardId: ShardId
    ShardIteratorType: ShardIteratorType
    SequenceNumber: SequenceNumber | None


class GetShardIteratorOutput(TypedDict, total=False):
    ShardIterator: ShardIterator | None


class ListStreamsInput(ServiceRequest):
    TableName: TableName | None
    Limit: PositiveIntegerObject | None
    ExclusiveStartStreamArn: StreamArn | None


class Stream(TypedDict, total=False):
    StreamArn: StreamArn | None
    TableName: TableName | None
    StreamLabel: String | None


StreamList = list[Stream]


class ListStreamsOutput(TypedDict, total=False):
    Streams: StreamList | None
    LastEvaluatedStreamArn: StreamArn | None


class DynamodbstreamsApi:
    service: str = "dynamodbstreams"
    version: str = "2012-08-10"

    @handler("DescribeStream")
    def describe_stream(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        limit: PositiveIntegerObject | None = None,
        exclusive_start_shard_id: ShardId | None = None,
        shard_filter: ShardFilter | None = None,
        **kwargs,
    ) -> DescribeStreamOutput:
        raise NotImplementedError

    @handler("GetRecords")
    def get_records(
        self,
        context: RequestContext,
        shard_iterator: ShardIterator,
        limit: PositiveIntegerObject | None = None,
        **kwargs,
    ) -> GetRecordsOutput:
        raise NotImplementedError

    @handler("GetShardIterator")
    def get_shard_iterator(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        shard_id: ShardId,
        shard_iterator_type: ShardIteratorType,
        sequence_number: SequenceNumber | None = None,
        **kwargs,
    ) -> GetShardIteratorOutput:
        raise NotImplementedError

    @handler("ListStreams")
    def list_streams(
        self,
        context: RequestContext,
        table_name: TableName | None = None,
        limit: PositiveIntegerObject | None = None,
        exclusive_start_stream_arn: StreamArn | None = None,
        **kwargs,
    ) -> ListStreamsOutput:
        raise NotImplementedError
