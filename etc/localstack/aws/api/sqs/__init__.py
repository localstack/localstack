import sys
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
BoxedInteger = int
Integer = int
MessageAttributeName = str
String = str
TagKey = str
TagValue = str
Token = str


class MessageSystemAttributeName(str):
    SenderId = "SenderId"
    SentTimestamp = "SentTimestamp"
    ApproximateReceiveCount = "ApproximateReceiveCount"
    ApproximateFirstReceiveTimestamp = "ApproximateFirstReceiveTimestamp"
    SequenceNumber = "SequenceNumber"
    MessageDeduplicationId = "MessageDeduplicationId"
    MessageGroupId = "MessageGroupId"
    AWSTraceHeader = "AWSTraceHeader"


class MessageSystemAttributeNameForSends(str):
    AWSTraceHeader = "AWSTraceHeader"


class QueueAttributeName(str):
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
    code: str = "AWS.SimpleQueueService.BatchEntryIdsNotDistinct"
    sender_fault: bool = True
    status_code: int = 400


class BatchRequestTooLong(ServiceException):
    code: str = "AWS.SimpleQueueService.BatchRequestTooLong"
    sender_fault: bool = True
    status_code: int = 400


class EmptyBatchRequest(ServiceException):
    code: str = "AWS.SimpleQueueService.EmptyBatchRequest"
    sender_fault: bool = True
    status_code: int = 400


class InvalidAttributeName(ServiceException):
    code: str = "InvalidAttributeName"
    sender_fault: bool = False
    status_code: int = 400


class InvalidBatchEntryId(ServiceException):
    code: str = "AWS.SimpleQueueService.InvalidBatchEntryId"
    sender_fault: bool = True
    status_code: int = 400


class InvalidIdFormat(ServiceException):
    code: str = "InvalidIdFormat"
    sender_fault: bool = False
    status_code: int = 400


class InvalidMessageContents(ServiceException):
    code: str = "InvalidMessageContents"
    sender_fault: bool = False
    status_code: int = 400


class MessageNotInflight(ServiceException):
    code: str = "AWS.SimpleQueueService.MessageNotInflight"
    sender_fault: bool = True
    status_code: int = 400


class OverLimit(ServiceException):
    code: str = "OverLimit"
    sender_fault: bool = True
    status_code: int = 403


class PurgeQueueInProgress(ServiceException):
    code: str = "AWS.SimpleQueueService.PurgeQueueInProgress"
    sender_fault: bool = True
    status_code: int = 403


class QueueDeletedRecently(ServiceException):
    code: str = "AWS.SimpleQueueService.QueueDeletedRecently"
    sender_fault: bool = True
    status_code: int = 400


class QueueDoesNotExist(ServiceException):
    code: str = "AWS.SimpleQueueService.NonExistentQueue"
    sender_fault: bool = True
    status_code: int = 400


class QueueNameExists(ServiceException):
    code: str = "QueueAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400


class ReceiptHandleIsInvalid(ServiceException):
    code: str = "ReceiptHandleIsInvalid"
    sender_fault: bool = False
    status_code: int = 400


class TooManyEntriesInBatchRequest(ServiceException):
    code: str = "AWS.SimpleQueueService.TooManyEntriesInBatchRequest"
    sender_fault: bool = True
    status_code: int = 400


class UnsupportedOperation(ServiceException):
    code: str = "AWS.SimpleQueueService.UnsupportedOperation"
    sender_fault: bool = True
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


class ChangeMessageVisibilityBatchRequestEntry(TypedDict, total=False):
    Id: String
    ReceiptHandle: String
    VisibilityTimeout: Optional[Integer]


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
    VisibilityTimeout: Integer


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


class PurgeQueueRequest(ServiceRequest):
    QueueUrl: String


class ReceiveMessageRequest(ServiceRequest):
    QueueUrl: String
    AttributeNames: Optional[AttributeNameList]
    MessageAttributeNames: Optional[MessageAttributeNameList]
    MaxNumberOfMessages: Optional[Integer]
    VisibilityTimeout: Optional[Integer]
    WaitTimeSeconds: Optional[Integer]
    ReceiveRequestAttemptId: Optional[String]


class ReceiveMessageResult(TypedDict, total=False):
    Messages: Optional[MessageList]


class RemovePermissionRequest(ServiceRequest):
    QueueUrl: String
    Label: String


class SendMessageBatchRequestEntry(TypedDict, total=False):
    Id: String
    MessageBody: String
    DelaySeconds: Optional[Integer]
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
    DelaySeconds: Optional[Integer]
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
    ) -> None:
        raise NotImplementedError

    @handler("ChangeMessageVisibility")
    def change_message_visibility(
        self,
        context: RequestContext,
        queue_url: String,
        receipt_handle: String,
        visibility_timeout: Integer,
    ) -> None:
        raise NotImplementedError

    @handler("ChangeMessageVisibilityBatch")
    def change_message_visibility_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: ChangeMessageVisibilityBatchRequestEntryList,
    ) -> ChangeMessageVisibilityBatchResult:
        raise NotImplementedError

    @handler("CreateQueue")
    def create_queue(
        self,
        context: RequestContext,
        queue_name: String,
        attributes: QueueAttributeMap = None,
        tags: TagMap = None,
    ) -> CreateQueueResult:
        raise NotImplementedError

    @handler("DeleteMessage")
    def delete_message(
        self, context: RequestContext, queue_url: String, receipt_handle: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMessageBatch")
    def delete_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: DeleteMessageBatchRequestEntryList,
    ) -> DeleteMessageBatchResult:
        raise NotImplementedError

    @handler("DeleteQueue")
    def delete_queue(self, context: RequestContext, queue_url: String) -> None:
        raise NotImplementedError

    @handler("GetQueueAttributes")
    def get_queue_attributes(
        self, context: RequestContext, queue_url: String, attribute_names: AttributeNameList = None
    ) -> GetQueueAttributesResult:
        raise NotImplementedError

    @handler("GetQueueUrl")
    def get_queue_url(
        self, context: RequestContext, queue_name: String, queue_owner_aws_account_id: String = None
    ) -> GetQueueUrlResult:
        raise NotImplementedError

    @handler("ListDeadLetterSourceQueues")
    def list_dead_letter_source_queues(
        self,
        context: RequestContext,
        queue_url: String,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListDeadLetterSourceQueuesResult:
        raise NotImplementedError

    @handler("ListQueueTags")
    def list_queue_tags(self, context: RequestContext, queue_url: String) -> ListQueueTagsResult:
        raise NotImplementedError

    @handler("ListQueues")
    def list_queues(
        self,
        context: RequestContext,
        queue_name_prefix: String = None,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListQueuesResult:
        raise NotImplementedError

    @handler("PurgeQueue")
    def purge_queue(self, context: RequestContext, queue_url: String) -> None:
        raise NotImplementedError

    @handler("ReceiveMessage")
    def receive_message(
        self,
        context: RequestContext,
        queue_url: String,
        attribute_names: AttributeNameList = None,
        message_attribute_names: MessageAttributeNameList = None,
        max_number_of_messages: Integer = None,
        visibility_timeout: Integer = None,
        wait_time_seconds: Integer = None,
        receive_request_attempt_id: String = None,
    ) -> ReceiveMessageResult:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(self, context: RequestContext, queue_url: String, label: String) -> None:
        raise NotImplementedError

    @handler("SendMessage")
    def send_message(
        self,
        context: RequestContext,
        queue_url: String,
        message_body: String,
        delay_seconds: Integer = None,
        message_attributes: MessageBodyAttributeMap = None,
        message_system_attributes: MessageBodySystemAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
    ) -> SendMessageResult:
        raise NotImplementedError

    @handler("SendMessageBatch")
    def send_message_batch(
        self, context: RequestContext, queue_url: String, entries: SendMessageBatchRequestEntryList
    ) -> SendMessageBatchResult:
        raise NotImplementedError

    @handler("SetQueueAttributes")
    def set_queue_attributes(
        self, context: RequestContext, queue_url: String, attributes: QueueAttributeMap
    ) -> None:
        raise NotImplementedError

    @handler("TagQueue")
    def tag_queue(self, context: RequestContext, queue_url: String, tags: TagMap) -> None:
        raise NotImplementedError

    @handler("UntagQueue")
    def untag_queue(self, context: RequestContext, queue_url: String, tag_keys: TagKeyList) -> None:
        raise NotImplementedError
