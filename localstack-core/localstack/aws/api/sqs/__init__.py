from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
BoxedInteger = int
ExceptionMessage = str
MessageAttributeName = str
NullableInteger = int
String = str
TagKey = str
TagValue = str
Token = str


class MessageSystemAttributeName(StrEnum):
    All = "All"
    SenderId = "SenderId"
    SentTimestamp = "SentTimestamp"
    ApproximateReceiveCount = "ApproximateReceiveCount"
    ApproximateFirstReceiveTimestamp = "ApproximateFirstReceiveTimestamp"
    SequenceNumber = "SequenceNumber"
    MessageDeduplicationId = "MessageDeduplicationId"
    MessageGroupId = "MessageGroupId"
    AWSTraceHeader = "AWSTraceHeader"
    DeadLetterQueueSourceArn = "DeadLetterQueueSourceArn"


class MessageSystemAttributeNameForSends(StrEnum):
    AWSTraceHeader = "AWSTraceHeader"


class QueueAttributeName(StrEnum):
    All = "All"
    Policy = "Policy"
    VisibilityTimeout = "VisibilityTimeout"
    MaximumMessageSize = "MaximumMessageSize"
    MessageRetentionPeriod = "MessageRetentionPeriod"
    ApproximateNumberOfMessages = "ApproximateNumberOfMessages"
    ApproximateNumberOfMessagesNotVisible = "ApproximateNumberOfMessagesNotVisible"
    CreatedTimestamp = "CreatedTimestamp"
    LastModifiedTimestamp = "LastModifiedTimestamp"
    QueueArn = "QueueArn"
    ApproximateNumberOfMessagesDelayed = "ApproximateNumberOfMessagesDelayed"
    DelaySeconds = "DelaySeconds"
    ReceiveMessageWaitTimeSeconds = "ReceiveMessageWaitTimeSeconds"
    RedrivePolicy = "RedrivePolicy"
    FifoQueue = "FifoQueue"
    ContentBasedDeduplication = "ContentBasedDeduplication"
    KmsMasterKeyId = "KmsMasterKeyId"
    KmsDataKeyReusePeriodSeconds = "KmsDataKeyReusePeriodSeconds"
    DeduplicationScope = "DeduplicationScope"
    FifoThroughputLimit = "FifoThroughputLimit"
    RedriveAllowPolicy = "RedriveAllowPolicy"
    SqsManagedSseEnabled = "SqsManagedSseEnabled"


class BatchEntryIdsNotDistinct(ServiceException):
    code: str = "BatchEntryIdsNotDistinct"
    sender_fault: bool = False
    status_code: int = 400


class BatchRequestTooLong(ServiceException):
    code: str = "BatchRequestTooLong"
    sender_fault: bool = False
    status_code: int = 400


class EmptyBatchRequest(ServiceException):
    code: str = "EmptyBatchRequest"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAddress(ServiceException):
    code: str = "InvalidAddress"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAttributeName(ServiceException):
    code: str = "InvalidAttributeName"
    sender_fault: bool = False
    status_code: int = 400


class InvalidAttributeValue(ServiceException):
    code: str = "InvalidAttributeValue"
    sender_fault: bool = False
    status_code: int = 400


class InvalidBatchEntryId(ServiceException):
    code: str = "InvalidBatchEntryId"
    sender_fault: bool = False
    status_code: int = 400


class InvalidIdFormat(ServiceException):
    code: str = "InvalidIdFormat"
    sender_fault: bool = False
    status_code: int = 400


class InvalidMessageContents(ServiceException):
    code: str = "InvalidMessageContents"
    sender_fault: bool = False
    status_code: int = 400


class InvalidSecurity(ServiceException):
    code: str = "InvalidSecurity"
    sender_fault: bool = False
    status_code: int = 400


class KmsAccessDenied(ServiceException):
    code: str = "KmsAccessDenied"
    sender_fault: bool = False
    status_code: int = 400


class KmsDisabled(ServiceException):
    code: str = "KmsDisabled"
    sender_fault: bool = False
    status_code: int = 400


class KmsInvalidKeyUsage(ServiceException):
    code: str = "KmsInvalidKeyUsage"
    sender_fault: bool = False
    status_code: int = 400


class KmsInvalidState(ServiceException):
    code: str = "KmsInvalidState"
    sender_fault: bool = False
    status_code: int = 400


class KmsNotFound(ServiceException):
    code: str = "KmsNotFound"
    sender_fault: bool = False
    status_code: int = 400


class KmsOptInRequired(ServiceException):
    code: str = "KmsOptInRequired"
    sender_fault: bool = False
    status_code: int = 400


class KmsThrottled(ServiceException):
    code: str = "KmsThrottled"
    sender_fault: bool = False
    status_code: int = 400


class MessageNotInflight(ServiceException):
    code: str = "MessageNotInflight"
    sender_fault: bool = False
    status_code: int = 400


class OverLimit(ServiceException):
    code: str = "OverLimit"
    sender_fault: bool = False
    status_code: int = 400


class PurgeQueueInProgress(ServiceException):
    code: str = "PurgeQueueInProgress"
    sender_fault: bool = False
    status_code: int = 400


class QueueDeletedRecently(ServiceException):
    code: str = "QueueDeletedRecently"
    sender_fault: bool = False
    status_code: int = 400


class QueueDoesNotExist(ServiceException):
    code: str = "QueueDoesNotExist"
    sender_fault: bool = False
    status_code: int = 400


class QueueNameExists(ServiceException):
    code: str = "QueueNameExists"
    sender_fault: bool = False
    status_code: int = 400


class ReceiptHandleIsInvalid(ServiceException):
    code: str = "ReceiptHandleIsInvalid"
    sender_fault: bool = False
    status_code: int = 400


class RequestThrottled(ServiceException):
    code: str = "RequestThrottled"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyEntriesInBatchRequest(ServiceException):
    code: str = "TooManyEntriesInBatchRequest"
    sender_fault: bool = False
    status_code: int = 400


class UnsupportedOperation(ServiceException):
    code: str = "UnsupportedOperation"
    sender_fault: bool = False
    status_code: int = 400


AWSAccountIdList = List[String]
ActionNameList = List[String]


class AddPermissionRequest(ServiceRequest):
    QueueUrl: String
    Label: String
    AWSAccountIds: AWSAccountIdList
    Actions: ActionNameList


AttributeNameList = List[QueueAttributeName]


class BatchResultErrorEntry(TypedDict, total=False):
    Id: String
    SenderFault: Boolean
    Code: String
    Message: Optional[String]


BatchResultErrorEntryList = List[BatchResultErrorEntry]
Binary = bytes
BinaryList = List[Binary]


class CancelMessageMoveTaskRequest(ServiceRequest):
    TaskHandle: String


Long = int


class CancelMessageMoveTaskResult(TypedDict, total=False):
    ApproximateNumberOfMessagesMoved: Optional[Long]


class ChangeMessageVisibilityBatchRequestEntry(TypedDict, total=False):
    Id: String
    ReceiptHandle: String
    VisibilityTimeout: Optional[NullableInteger]


ChangeMessageVisibilityBatchRequestEntryList = List[ChangeMessageVisibilityBatchRequestEntry]


class ChangeMessageVisibilityBatchRequest(ServiceRequest):
    QueueUrl: String
    Entries: ChangeMessageVisibilityBatchRequestEntryList


class ChangeMessageVisibilityBatchResultEntry(TypedDict, total=False):
    Id: String


ChangeMessageVisibilityBatchResultEntryList = List[ChangeMessageVisibilityBatchResultEntry]


class ChangeMessageVisibilityBatchResult(TypedDict, total=False):
    Successful: ChangeMessageVisibilityBatchResultEntryList
    Failed: BatchResultErrorEntryList


class ChangeMessageVisibilityRequest(ServiceRequest):
    QueueUrl: String
    ReceiptHandle: String
    VisibilityTimeout: NullableInteger


TagMap = Dict[TagKey, TagValue]
QueueAttributeMap = Dict[QueueAttributeName, String]


class CreateQueueRequest(ServiceRequest):
    QueueName: String
    Attributes: Optional[QueueAttributeMap]
    tags: Optional[TagMap]


class CreateQueueResult(TypedDict, total=False):
    QueueUrl: Optional[String]


class DeleteMessageBatchRequestEntry(TypedDict, total=False):
    Id: String
    ReceiptHandle: String


DeleteMessageBatchRequestEntryList = List[DeleteMessageBatchRequestEntry]


class DeleteMessageBatchRequest(ServiceRequest):
    QueueUrl: String
    Entries: DeleteMessageBatchRequestEntryList


class DeleteMessageBatchResultEntry(TypedDict, total=False):
    Id: String


DeleteMessageBatchResultEntryList = List[DeleteMessageBatchResultEntry]


class DeleteMessageBatchResult(TypedDict, total=False):
    Successful: DeleteMessageBatchResultEntryList
    Failed: BatchResultErrorEntryList


class DeleteMessageRequest(ServiceRequest):
    QueueUrl: String
    ReceiptHandle: String


class DeleteQueueRequest(ServiceRequest):
    QueueUrl: String


class GetQueueAttributesRequest(ServiceRequest):
    QueueUrl: String
    AttributeNames: Optional[AttributeNameList]


class GetQueueAttributesResult(TypedDict, total=False):
    Attributes: Optional[QueueAttributeMap]


class GetQueueUrlRequest(ServiceRequest):
    QueueName: String
    QueueOwnerAWSAccountId: Optional[String]


class GetQueueUrlResult(TypedDict, total=False):
    QueueUrl: Optional[String]


class ListDeadLetterSourceQueuesRequest(ServiceRequest):
    QueueUrl: String
    NextToken: Optional[Token]
    MaxResults: Optional[BoxedInteger]


QueueUrlList = List[String]


class ListDeadLetterSourceQueuesResult(TypedDict, total=False):
    queueUrls: QueueUrlList
    NextToken: Optional[Token]


class ListMessageMoveTasksRequest(ServiceRequest):
    SourceArn: String
    MaxResults: Optional[NullableInteger]


NullableLong = int


class ListMessageMoveTasksResultEntry(TypedDict, total=False):
    TaskHandle: Optional[String]
    Status: Optional[String]
    SourceArn: Optional[String]
    DestinationArn: Optional[String]
    MaxNumberOfMessagesPerSecond: Optional[NullableInteger]
    ApproximateNumberOfMessagesMoved: Optional[Long]
    ApproximateNumberOfMessagesToMove: Optional[NullableLong]
    FailureReason: Optional[String]
    StartedTimestamp: Optional[Long]


ListMessageMoveTasksResultEntryList = List[ListMessageMoveTasksResultEntry]


class ListMessageMoveTasksResult(TypedDict, total=False):
    Results: Optional[ListMessageMoveTasksResultEntryList]


class ListQueueTagsRequest(ServiceRequest):
    QueueUrl: String


class ListQueueTagsResult(TypedDict, total=False):
    Tags: Optional[TagMap]


class ListQueuesRequest(ServiceRequest):
    QueueNamePrefix: Optional[String]
    NextToken: Optional[Token]
    MaxResults: Optional[BoxedInteger]


class ListQueuesResult(TypedDict, total=False):
    QueueUrls: Optional[QueueUrlList]
    NextToken: Optional[Token]


StringList = List[String]


class MessageAttributeValue(TypedDict, total=False):
    StringValue: Optional[String]
    BinaryValue: Optional[Binary]
    StringListValues: Optional[StringList]
    BinaryListValues: Optional[BinaryList]
    DataType: String


MessageBodyAttributeMap = Dict[String, MessageAttributeValue]
MessageSystemAttributeMap = Dict[MessageSystemAttributeName, String]


class Message(TypedDict, total=False):
    MessageId: Optional[String]
    ReceiptHandle: Optional[String]
    MD5OfBody: Optional[String]
    Body: Optional[String]
    Attributes: Optional[MessageSystemAttributeMap]
    MD5OfMessageAttributes: Optional[String]
    MessageAttributes: Optional[MessageBodyAttributeMap]


MessageAttributeNameList = List[MessageAttributeName]


class MessageSystemAttributeValue(TypedDict, total=False):
    StringValue: Optional[String]
    BinaryValue: Optional[Binary]
    StringListValues: Optional[StringList]
    BinaryListValues: Optional[BinaryList]
    DataType: String


MessageBodySystemAttributeMap = Dict[
    MessageSystemAttributeNameForSends, MessageSystemAttributeValue
]
MessageList = List[Message]
MessageSystemAttributeList = List[MessageSystemAttributeName]


class PurgeQueueRequest(ServiceRequest):
    QueueUrl: String


class ReceiveMessageRequest(ServiceRequest):
    QueueUrl: String
    AttributeNames: Optional[AttributeNameList]
    MessageSystemAttributeNames: Optional[MessageSystemAttributeList]
    MessageAttributeNames: Optional[MessageAttributeNameList]
    MaxNumberOfMessages: Optional[NullableInteger]
    VisibilityTimeout: Optional[NullableInteger]
    WaitTimeSeconds: Optional[NullableInteger]
    ReceiveRequestAttemptId: Optional[String]


class ReceiveMessageResult(TypedDict, total=False):
    Messages: Optional[MessageList]


class RemovePermissionRequest(ServiceRequest):
    QueueUrl: String
    Label: String


class SendMessageBatchRequestEntry(TypedDict, total=False):
    Id: String
    MessageBody: String
    DelaySeconds: Optional[NullableInteger]
    MessageAttributes: Optional[MessageBodyAttributeMap]
    MessageSystemAttributes: Optional[MessageBodySystemAttributeMap]
    MessageDeduplicationId: Optional[String]
    MessageGroupId: Optional[String]


SendMessageBatchRequestEntryList = List[SendMessageBatchRequestEntry]


class SendMessageBatchRequest(ServiceRequest):
    QueueUrl: String
    Entries: SendMessageBatchRequestEntryList


class SendMessageBatchResultEntry(TypedDict, total=False):
    Id: String
    MessageId: String
    MD5OfMessageBody: String
    MD5OfMessageAttributes: Optional[String]
    MD5OfMessageSystemAttributes: Optional[String]
    SequenceNumber: Optional[String]


SendMessageBatchResultEntryList = List[SendMessageBatchResultEntry]


class SendMessageBatchResult(TypedDict, total=False):
    Successful: SendMessageBatchResultEntryList
    Failed: BatchResultErrorEntryList


class SendMessageRequest(ServiceRequest):
    QueueUrl: String
    MessageBody: String
    DelaySeconds: Optional[NullableInteger]
    MessageAttributes: Optional[MessageBodyAttributeMap]
    MessageSystemAttributes: Optional[MessageBodySystemAttributeMap]
    MessageDeduplicationId: Optional[String]
    MessageGroupId: Optional[String]


class SendMessageResult(TypedDict, total=False):
    MD5OfMessageBody: Optional[String]
    MD5OfMessageAttributes: Optional[String]
    MD5OfMessageSystemAttributes: Optional[String]
    MessageId: Optional[String]
    SequenceNumber: Optional[String]


class SetQueueAttributesRequest(ServiceRequest):
    QueueUrl: String
    Attributes: QueueAttributeMap


class StartMessageMoveTaskRequest(ServiceRequest):
    SourceArn: String
    DestinationArn: Optional[String]
    MaxNumberOfMessagesPerSecond: Optional[NullableInteger]


class StartMessageMoveTaskResult(TypedDict, total=False):
    TaskHandle: Optional[String]


TagKeyList = List[TagKey]


class TagQueueRequest(ServiceRequest):
    QueueUrl: String
    Tags: TagMap


class UntagQueueRequest(ServiceRequest):
    QueueUrl: String
    TagKeys: TagKeyList


class SqsApi:
    service = "sqs"
    version = "2012-11-05"

    @handler("AddPermission")
    def add_permission(
        self,
        context: RequestContext,
        queue_url: String,
        label: String,
        aws_account_ids: AWSAccountIdList,
        actions: ActionNameList,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CancelMessageMoveTask")
    def cancel_message_move_task(
        self, context: RequestContext, task_handle: String, **kwargs
    ) -> CancelMessageMoveTaskResult:
        raise NotImplementedError

    @handler("ChangeMessageVisibility")
    def change_message_visibility(
        self,
        context: RequestContext,
        queue_url: String,
        receipt_handle: String,
        visibility_timeout: NullableInteger,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ChangeMessageVisibilityBatch")
    def change_message_visibility_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: ChangeMessageVisibilityBatchRequestEntryList,
        **kwargs,
    ) -> ChangeMessageVisibilityBatchResult:
        raise NotImplementedError

    @handler("CreateQueue")
    def create_queue(
        self,
        context: RequestContext,
        queue_name: String,
        attributes: QueueAttributeMap = None,
        tags: TagMap = None,
        **kwargs,
    ) -> CreateQueueResult:
        raise NotImplementedError

    @handler("DeleteMessage")
    def delete_message(
        self, context: RequestContext, queue_url: String, receipt_handle: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMessageBatch")
    def delete_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: DeleteMessageBatchRequestEntryList,
        **kwargs,
    ) -> DeleteMessageBatchResult:
        raise NotImplementedError

    @handler("DeleteQueue")
    def delete_queue(self, context: RequestContext, queue_url: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("GetQueueAttributes")
    def get_queue_attributes(
        self,
        context: RequestContext,
        queue_url: String,
        attribute_names: AttributeNameList = None,
        **kwargs,
    ) -> GetQueueAttributesResult:
        raise NotImplementedError

    @handler("GetQueueUrl")
    def get_queue_url(
        self,
        context: RequestContext,
        queue_name: String,
        queue_owner_aws_account_id: String = None,
        **kwargs,
    ) -> GetQueueUrlResult:
        raise NotImplementedError

    @handler("ListDeadLetterSourceQueues")
    def list_dead_letter_source_queues(
        self,
        context: RequestContext,
        queue_url: String,
        next_token: Token = None,
        max_results: BoxedInteger = None,
        **kwargs,
    ) -> ListDeadLetterSourceQueuesResult:
        raise NotImplementedError

    @handler("ListMessageMoveTasks")
    def list_message_move_tasks(
        self,
        context: RequestContext,
        source_arn: String,
        max_results: NullableInteger = None,
        **kwargs,
    ) -> ListMessageMoveTasksResult:
        raise NotImplementedError

    @handler("ListQueueTags")
    def list_queue_tags(
        self, context: RequestContext, queue_url: String, **kwargs
    ) -> ListQueueTagsResult:
        raise NotImplementedError

    @handler("ListQueues")
    def list_queues(
        self,
        context: RequestContext,
        queue_name_prefix: String = None,
        next_token: Token = None,
        max_results: BoxedInteger = None,
        **kwargs,
    ) -> ListQueuesResult:
        raise NotImplementedError

    @handler("PurgeQueue")
    def purge_queue(self, context: RequestContext, queue_url: String, **kwargs) -> None:
        raise NotImplementedError

    @handler("ReceiveMessage")
    def receive_message(
        self,
        context: RequestContext,
        queue_url: String,
        attribute_names: AttributeNameList = None,
        message_system_attribute_names: MessageSystemAttributeList = None,
        message_attribute_names: MessageAttributeNameList = None,
        max_number_of_messages: NullableInteger = None,
        visibility_timeout: NullableInteger = None,
        wait_time_seconds: NullableInteger = None,
        receive_request_attempt_id: String = None,
        **kwargs,
    ) -> ReceiveMessageResult:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(
        self, context: RequestContext, queue_url: String, label: String, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("SendMessage")
    def send_message(
        self,
        context: RequestContext,
        queue_url: String,
        message_body: String,
        delay_seconds: NullableInteger = None,
        message_attributes: MessageBodyAttributeMap = None,
        message_system_attributes: MessageBodySystemAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
        **kwargs,
    ) -> SendMessageResult:
        raise NotImplementedError

    @handler("SendMessageBatch")
    def send_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: SendMessageBatchRequestEntryList,
        **kwargs,
    ) -> SendMessageBatchResult:
        raise NotImplementedError

    @handler("SetQueueAttributes")
    def set_queue_attributes(
        self, context: RequestContext, queue_url: String, attributes: QueueAttributeMap, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("StartMessageMoveTask")
    def start_message_move_task(
        self,
        context: RequestContext,
        source_arn: String,
        destination_arn: String = None,
        max_number_of_messages_per_second: NullableInteger = None,
        **kwargs,
    ) -> StartMessageMoveTaskResult:
        raise NotImplementedError

    @handler("TagQueue")
    def tag_queue(self, context: RequestContext, queue_url: String, tags: TagMap, **kwargs) -> None:
        raise NotImplementedError

    @handler("UntagQueue")
    def untag_queue(
        self, context: RequestContext, queue_url: String, tag_keys: TagKeyList, **kwargs
    ) -> None:
        raise NotImplementedError
