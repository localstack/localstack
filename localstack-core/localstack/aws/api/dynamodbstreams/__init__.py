from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

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
    S: Optional["StringAttributeValue"]
    N: Optional["NumberAttributeValue"]
    B: Optional["BinaryAttributeValue"]
    SS: Optional["StringSetAttributeValue"]
    NS: Optional["NumberSetAttributeValue"]
    BS: Optional["BinarySetAttributeValue"]
    M: Optional["MapAttributeValue"]
    L: Optional["ListAttributeValue"]
    NULL: Optional["NullAttributeValue"]
    BOOL: Optional["BooleanAttributeValue"]


ListAttributeValue = List[AttributeValue]
MapAttributeValue = Dict[AttributeName, AttributeValue]
BinaryAttributeValue = bytes
BinarySetAttributeValue = List[BinaryAttributeValue]
NumberSetAttributeValue = List[NumberAttributeValue]
StringSetAttributeValue = List[StringAttributeValue]
AttributeMap = Dict[AttributeName, AttributeValue]
Date = datetime


class DescribeStreamInput(ServiceRequest):
    StreamArn: StreamArn
    Limit: Optional[PositiveIntegerObject]
    ExclusiveStartShardId: Optional[ShardId]


class SequenceNumberRange(TypedDict, total=False):
    StartingSequenceNumber: Optional[SequenceNumber]
    EndingSequenceNumber: Optional[SequenceNumber]


class Shard(TypedDict, total=False):
    ShardId: Optional[ShardId]
    SequenceNumberRange: Optional[SequenceNumberRange]
    ParentShardId: Optional[ShardId]


ShardDescriptionList = List[Shard]


class KeySchemaElement(TypedDict, total=False):
    AttributeName: KeySchemaAttributeName
    KeyType: KeyType


KeySchema = List[KeySchemaElement]


class StreamDescription(TypedDict, total=False):
    StreamArn: Optional[StreamArn]
    StreamLabel: Optional[String]
    StreamStatus: Optional[StreamStatus]
    StreamViewType: Optional[StreamViewType]
    CreationRequestDateTime: Optional[Date]
    TableName: Optional[TableName]
    KeySchema: Optional[KeySchema]
    Shards: Optional[ShardDescriptionList]
    LastEvaluatedShardId: Optional[ShardId]


class DescribeStreamOutput(TypedDict, total=False):
    StreamDescription: Optional[StreamDescription]


class GetRecordsInput(ServiceRequest):
    ShardIterator: ShardIterator
    Limit: Optional[PositiveIntegerObject]


class Identity(TypedDict, total=False):
    PrincipalId: Optional[String]
    Type: Optional[String]


PositiveLongObject = int


class StreamRecord(TypedDict, total=False):
    ApproximateCreationDateTime: Optional[Date]
    Keys: Optional[AttributeMap]
    NewImage: Optional[AttributeMap]
    OldImage: Optional[AttributeMap]
    SequenceNumber: Optional[SequenceNumber]
    SizeBytes: Optional[PositiveLongObject]
    StreamViewType: Optional[StreamViewType]


class Record(TypedDict, total=False):
    eventID: Optional[String]
    eventName: Optional[OperationType]
    eventVersion: Optional[String]
    eventSource: Optional[String]
    awsRegion: Optional[String]
    dynamodb: Optional[StreamRecord]
    userIdentity: Optional[Identity]


RecordList = List[Record]


class GetRecordsOutput(TypedDict, total=False):
    Records: Optional[RecordList]
    NextShardIterator: Optional[ShardIterator]


class GetShardIteratorInput(ServiceRequest):
    StreamArn: StreamArn
    ShardId: ShardId
    ShardIteratorType: ShardIteratorType
    SequenceNumber: Optional[SequenceNumber]


class GetShardIteratorOutput(TypedDict, total=False):
    ShardIterator: Optional[ShardIterator]


class ListStreamsInput(ServiceRequest):
    TableName: Optional[TableName]
    Limit: Optional[PositiveIntegerObject]
    ExclusiveStartStreamArn: Optional[StreamArn]


class Stream(TypedDict, total=False):
    StreamArn: Optional[StreamArn]
    TableName: Optional[TableName]
    StreamLabel: Optional[String]


StreamList = List[Stream]


class ListStreamsOutput(TypedDict, total=False):
    Streams: Optional[StreamList]
    LastEvaluatedStreamArn: Optional[StreamArn]


class DynamodbstreamsApi:
    service = "dynamodbstreams"
    version = "2012-08-10"

    @handler("DescribeStream")
    def describe_stream(
        self,
        context: RequestContext,
        stream_arn: StreamArn,
        limit: PositiveIntegerObject | None = None,
        exclusive_start_shard_id: ShardId | None = None,
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
