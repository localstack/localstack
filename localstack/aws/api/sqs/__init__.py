from typing import Dict, List, Optional, TypedDict

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


class BatchEntryIdsNotDistinct(ServiceException):
    """Two or more batch entries in the request have the same ``Id``."""

    pass


class BatchRequestTooLong(ServiceException):
    """The length of all the messages put together is more than the limit."""

    pass


class EmptyBatchRequest(ServiceException):
    """The batch request doesn't contain any entries."""

    pass


class InvalidAttributeName(ServiceException):
    """The specified attribute doesn't exist."""

    pass


class InvalidBatchEntryId(ServiceException):
    """The ``Id`` of a batch entry in a batch request doesn't abide by the
    specification.
    """

    pass


class InvalidIdFormat(ServiceException):
    """The specified receipt handle isn't valid for the current version."""

    pass


class InvalidMessageContents(ServiceException):
    """The message contains characters outside the allowed set."""

    pass


class MessageNotInflight(ServiceException):
    """The specified message isn't in flight."""

    pass


class OverLimit(ServiceException):
    """The specified action violates a limit. For example, ``ReceiveMessage``
    returns this error if the maximum number of inflight messages is reached
    and ``AddPermission`` returns this error if the maximum number of
    permissions for the queue is reached.
    """

    pass


class PurgeQueueInProgress(ServiceException):
    """Indicates that the specified queue previously received a ``PurgeQueue``
    request within the last 60 seconds (the time it can take to delete the
    messages in the queue).
    """

    pass


class QueueDeletedRecently(ServiceException):
    """You must wait 60 seconds after deleting a queue before you can create
    another queue with the same name.
    """

    pass


class QueueDoesNotExist(ServiceException):
    """The specified queue doesn't exist."""

    pass


class QueueNameExists(ServiceException):
    """A queue with this name already exists. Amazon SQS returns this error
    only if the request includes attributes whose values differ from those
    of the existing queue.
    """

    pass


class ReceiptHandleIsInvalid(ServiceException):
    """The specified receipt handle isn't valid."""

    pass


class TooManyEntriesInBatchRequest(ServiceException):
    """The batch request contains more entries than permissible."""

    pass


class UnsupportedOperation(ServiceException):
    """Error code 400. Unsupported operation."""

    pass


AWSAccountIdList = List[String]

ActionNameList = List[String]


class AddPermissionRequest(ServiceRequest):
    QueueUrl: String
    Label: String
    AWSAccountIds: AWSAccountIdList
    Actions: ActionNameList


AttributeNameList = List[QueueAttributeName]


class BatchResultErrorEntry(TypedDict, total=False):
    """Gives a detailed description of the result of an action on each entry in
    the request.
    """

    Id: String
    SenderFault: Boolean
    Code: String
    Message: Optional[String]


BatchResultErrorEntryList = List[BatchResultErrorEntry]

Binary = bytes
BinaryList = List[Binary]


class ChangeMessageVisibilityBatchRequestEntry(TypedDict, total=False):
    """Encloses a receipt handle and an entry id for each message in
    ``ChangeMessageVisibilityBatch.``

    All of the following list parameters must be prefixed with
    ``ChangeMessageVisibilityBatchRequestEntry.n``, where ``n`` is an
    integer value starting with ``1``. For example, a parameter list for
    this action might look like this:

    ``&ChangeMessageVisibilityBatchRequestEntry.1.Id=change_visibility_msg_2``

    ``&ChangeMessageVisibilityBatchRequestEntry.1.ReceiptHandle=your_receipt_handle``

    ``&ChangeMessageVisibilityBatchRequestEntry.1.VisibilityTimeout=45``
    """

    Id: String
    ReceiptHandle: String
    VisibilityTimeout: Optional[Integer]


ChangeMessageVisibilityBatchRequestEntryList = List[ChangeMessageVisibilityBatchRequestEntry]


class ChangeMessageVisibilityBatchRequest(ServiceRequest):
    QueueUrl: String
    Entries: ChangeMessageVisibilityBatchRequestEntryList


class ChangeMessageVisibilityBatchResultEntry(TypedDict, total=False):
    """Encloses the ``Id`` of an entry in ``ChangeMessageVisibilityBatch.``"""

    Id: String


ChangeMessageVisibilityBatchResultEntryList = List[ChangeMessageVisibilityBatchResultEntry]


class ChangeMessageVisibilityBatchResult(TypedDict, total=False):
    """For each message in the batch, the response contains a
    ``ChangeMessageVisibilityBatchResultEntry`` tag if the message succeeds
    or a ``BatchResultErrorEntry`` tag if the message fails.
    """

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
    """Returns the ``QueueUrl`` attribute of the created queue."""

    QueueUrl: Optional[String]


class DeleteMessageBatchRequestEntry(TypedDict, total=False):
    """Encloses a receipt handle and an identifier for it."""

    Id: String
    ReceiptHandle: String


DeleteMessageBatchRequestEntryList = List[DeleteMessageBatchRequestEntry]


class DeleteMessageBatchRequest(ServiceRequest):
    QueueUrl: String
    Entries: DeleteMessageBatchRequestEntryList


class DeleteMessageBatchResultEntry(TypedDict, total=False):
    """Encloses the ``Id`` of an entry in ``DeleteMessageBatch.``"""

    Id: String


DeleteMessageBatchResultEntryList = List[DeleteMessageBatchResultEntry]


class DeleteMessageBatchResult(TypedDict, total=False):
    """For each message in the batch, the response contains a
    ``DeleteMessageBatchResultEntry`` tag if the message is deleted or a
    ``BatchResultErrorEntry`` tag if the message can't be deleted.
    """

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
    """A list of returned queue attributes."""

    Attributes: Optional[QueueAttributeMap]


class GetQueueUrlRequest(ServiceRequest):
    QueueName: String
    QueueOwnerAWSAccountId: Optional[String]


class GetQueueUrlResult(TypedDict, total=False):
    """For more information, see `Interpreting
    Responses <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-api-responses.html>`__
    in the *Amazon SQS Developer Guide*.
    """

    QueueUrl: Optional[String]


class ListDeadLetterSourceQueuesRequest(ServiceRequest):
    QueueUrl: String
    NextToken: Optional[Token]
    MaxResults: Optional[BoxedInteger]


QueueUrlList = List[String]


class ListDeadLetterSourceQueuesResult(TypedDict, total=False):
    """A list of your dead letter source queues."""

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
    """A list of your queues."""

    QueueUrls: Optional[QueueUrlList]
    NextToken: Optional[Token]


StringList = List[String]


class MessageAttributeValue(TypedDict, total=False):
    """The user-specified message attribute value. For string data types, the
    ``Value`` attribute has the same restrictions on the content as the
    message body. For more information, see ``SendMessage.``

    ``Name``, ``type``, ``value`` and the message body must not be empty or
    null. All parts of the message attribute, including ``Name``, ``Type``,
    and ``Value``, are part of the message size restriction (256 KB or
    262,144 bytes).
    """

    StringValue: Optional[String]
    BinaryValue: Optional[Binary]
    StringListValues: Optional[StringList]
    BinaryListValues: Optional[BinaryList]
    DataType: String


MessageBodyAttributeMap = Dict[String, MessageAttributeValue]
MessageSystemAttributeMap = Dict[MessageSystemAttributeName, String]


class Message(TypedDict, total=False):
    """An Amazon SQS message."""

    MessageId: Optional[String]
    ReceiptHandle: Optional[String]
    MD5OfBody: Optional[String]
    Body: Optional[String]
    Attributes: Optional[MessageSystemAttributeMap]
    MD5OfMessageAttributes: Optional[String]
    MessageAttributes: Optional[MessageBodyAttributeMap]


MessageAttributeNameList = List[MessageAttributeName]


class MessageSystemAttributeValue(TypedDict, total=False):
    """The user-specified message system attribute value. For string data
    types, the ``Value`` attribute has the same restrictions on the content
    as the message body. For more information, see ``SendMessage.``

    ``Name``, ``type``, ``value`` and the message body must not be empty or
    null.
    """

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
    """A list of received messages."""

    Messages: Optional[MessageList]


class RemovePermissionRequest(ServiceRequest):
    QueueUrl: String
    Label: String


class SendMessageBatchRequestEntry(TypedDict, total=False):
    """Contains the details of a single Amazon SQS message along with an
    ``Id``.
    """

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
    """Encloses a ``MessageId`` for a successfully-enqueued message in a
    ``SendMessageBatch.``
    """

    Id: String
    MessageId: String
    MD5OfMessageBody: String
    MD5OfMessageAttributes: Optional[String]
    MD5OfMessageSystemAttributes: Optional[String]
    SequenceNumber: Optional[String]


SendMessageBatchResultEntryList = List[SendMessageBatchResultEntry]


class SendMessageBatchResult(TypedDict, total=False):
    """For each message in the batch, the response contains a
    ``SendMessageBatchResultEntry`` tag if the message succeeds or a
    ``BatchResultErrorEntry`` tag if the message fails.
    """

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
    """The ``MD5OfMessageBody`` and ``MessageId`` elements."""

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
        """Adds a permission to a queue for a specific
        `principal <https://docs.aws.amazon.com/general/latest/gr/glos-chap.html#P>`__.
        This allows sharing access to the queue.

        When you create a queue, you have full control access rights for the
        queue. Only you, the owner of the queue, can grant or deny permissions
        to the queue. For more information about these permissions, see `Allow
        Developers to Write Messages to a Shared
        Queue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-writing-an-sqs-policy.html#write-messages-to-shared-queue>`__
        in the *Amazon SQS Developer Guide*.

        -  ``AddPermission`` generates a policy for you. You can use
           ``SetQueueAttributes`` to upload your policy. For more information,
           see `Using Custom Policies with the Amazon SQS Access Policy
           Language <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html>`__
           in the *Amazon SQS Developer Guide*.

        -  An Amazon SQS policy can have a maximum of 7 actions.

        -  To remove the ability to change queue permissions, you must deny
           permission to the ``AddPermission``, ``RemovePermission``, and
           ``SetQueueAttributes`` actions in your IAM policy.

        Some actions take lists of parameters. These lists are specified using
        the ``param.n`` notation. Values of ``n`` are integers starting from 1.
        For example, a parameter list with two elements looks like this:

        ``&AttributeName.1=first``

        ``&AttributeName.2=second``

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_url: The URL of the Amazon SQS queue to which permissions are added.
        :param label: The unique identification of the permission you're setting (for example,
        ``AliceSendMessage``).
        :param aws_account_ids: The account numbers of the
        `principals <https://docs.
        :param actions: The action the client wants to allow for the specified principal.
        :raises OverLimit:
        """
        raise NotImplementedError

    @handler("ChangeMessageVisibility")
    def change_message_visibility(
        self,
        context: RequestContext,
        queue_url: String,
        receipt_handle: String,
        visibility_timeout: Integer,
    ) -> None:
        """Changes the visibility timeout of a specified message in a queue to a
        new value. The default visibility timeout for a message is 30 seconds.
        The minimum is 0 seconds. The maximum is 12 hours. For more information,
        see `Visibility
        Timeout <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>`__
        in the *Amazon SQS Developer Guide*.

        For example, you have a message with a visibility timeout of 5 minutes.
        After 3 minutes, you call ``ChangeMessageVisibility`` with a timeout of
        10 minutes. You can continue to call ``ChangeMessageVisibility`` to
        extend the visibility timeout to the maximum allowed time. If you try to
        extend the visibility timeout beyond the maximum, your request is
        rejected.

        An Amazon SQS message has three basic states:

        #. Sent to a queue by a producer.

        #. Received from the queue by a consumer.

        #. Deleted from the queue.

        A message is considered to be *stored* after it is sent to a queue by a
        producer, but not yet received from the queue by a consumer (that is,
        between states 1 and 2). There is no limit to the number of stored
        messages. A message is considered to be *in flight* after it is received
        from a queue by a consumer, but not yet deleted from the queue (that is,
        between states 2 and 3). There is a limit to the number of inflight
        messages.

        Limits that apply to inflight messages are unrelated to the *unlimited*
        number of stored messages.

        For most standard queues (depending on queue traffic and message
        backlog), there can be a maximum of approximately 120,000 inflight
        messages (received from a queue by a consumer, but not yet deleted from
        the queue). If you reach this limit, Amazon SQS returns the
        ``OverLimit`` error message. To avoid reaching the limit, you should
        delete messages from the queue after they're processed. You can also
        increase the number of queues you use to process your messages. To
        request a limit increase, `file a support
        request <https://console.aws.amazon.com/support/home#/case/create?issueType=service-limit-increase&limitType=service-code-sqs>`__.

        For FIFO queues, there can be a maximum of 20,000 inflight messages
        (received from a queue by a consumer, but not yet deleted from the
        queue). If you reach this limit, Amazon SQS returns no error messages.

        If you attempt to set the ``VisibilityTimeout`` to a value greater than
        the maximum time left, Amazon SQS returns an error. Amazon SQS doesn't
        automatically recalculate and increase the timeout to the maximum
        remaining time.

        Unlike with a queue, when you change the visibility timeout for a
        specific message the timeout value is applied immediately but isn't
        saved in memory for that message. If you don't delete a message after it
        is received, the visibility timeout for the message reverts to the
        original timeout value (not to the value you set using the
        ``ChangeMessageVisibility`` action) the next time the message is
        received.

        :param queue_url: The URL of the Amazon SQS queue whose message's visibility is changed.
        :param receipt_handle: The receipt handle associated with the message whose visibility timeout
        is changed.
        :param visibility_timeout: The new value for the message's visibility timeout (in seconds).
        :raises MessageNotInflight:
        :raises ReceiptHandleIsInvalid:
        """
        raise NotImplementedError

    @handler("ChangeMessageVisibilityBatch")
    def change_message_visibility_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: ChangeMessageVisibilityBatchRequestEntryList,
    ) -> ChangeMessageVisibilityBatchResult:
        """Changes the visibility timeout of multiple messages. This is a batch
        version of ``ChangeMessageVisibility.`` The result of the action on each
        message is reported individually in the response. You can send up to 10
        ``ChangeMessageVisibility`` requests with each
        ``ChangeMessageVisibilityBatch`` action.

        Because the batch request can result in a combination of successful and
        unsuccessful actions, you should check for batch errors even when the
        call returns an HTTP status code of ``200``.

        Some actions take lists of parameters. These lists are specified using
        the ``param.n`` notation. Values of ``n`` are integers starting from 1.
        For example, a parameter list with two elements looks like this:

        ``&AttributeName.1=first``

        ``&AttributeName.2=second``

        :param queue_url: The URL of the Amazon SQS queue whose messages' visibility is changed.
        :param entries: A list of receipt handles of the messages for which the visibility
        timeout must be changed.
        :returns: ChangeMessageVisibilityBatchResult
        :raises TooManyEntriesInBatchRequest:
        :raises EmptyBatchRequest:
        :raises BatchEntryIdsNotDistinct:
        :raises InvalidBatchEntryId:
        """
        raise NotImplementedError

    @handler("CreateQueue")
    def create_queue(
        self,
        context: RequestContext,
        queue_name: String,
        attributes: QueueAttributeMap = None,
        tags: TagMap = None,
    ) -> CreateQueueResult:
        """Creates a new standard or FIFO queue. You can pass one or more
        attributes in the request. Keep the following in mind:

        -  If you don't specify the ``FifoQueue`` attribute, Amazon SQS creates
           a standard queue.

           You can't change the queue type after you create it and you can't
           convert an existing standard queue into a FIFO queue. You must either
           create a new FIFO queue for your application or delete your existing
           standard queue and recreate it as a FIFO queue. For more information,
           see `Moving From a Standard Queue to a FIFO
           Queue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html#FIFO-queues-moving>`__
           in the *Amazon SQS Developer Guide*.

        -  If you don't provide a value for an attribute, the queue is created
           with the default value for the attribute.

        -  If you delete a queue, you must wait at least 60 seconds before
           creating a queue with the same name.

        To successfully create a new queue, you must provide a queue name that
        adheres to the `limits related to
        queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/limits-queues.html>`__
        and is unique within the scope of your queues.

        After you create a queue, you must wait at least one second after the
        queue is created to be able to use the queue.

        To get the queue URL, use the ``GetQueueUrl`` action. ``GetQueueUrl``
        requires only the ``QueueName`` parameter. be aware of existing queue
        names:

        -  If you provide the name of an existing queue along with the exact
           names and values of all the queue's attributes, ``CreateQueue``
           returns the queue URL for the existing queue.

        -  If the queue name, attribute names, or attribute values don't match
           an existing queue, ``CreateQueue`` returns an error.

        Some actions take lists of parameters. These lists are specified using
        the ``param.n`` notation. Values of ``n`` are integers starting from 1.
        For example, a parameter list with two elements looks like this:

        ``&AttributeName.1=first``

        ``&AttributeName.2=second``

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_name: The name of the new queue.
        :param attributes: A map of attributes with their corresponding values.
        :param tags: Add cost allocation tags to the specified Amazon SQS queue.
        :returns: CreateQueueResult
        :raises QueueDeletedRecently:
        :raises QueueNameExists:
        """
        raise NotImplementedError

    @handler("DeleteMessage")
    def delete_message(
        self, context: RequestContext, queue_url: String, receipt_handle: String
    ) -> None:
        """Deletes the specified message from the specified queue. To select the
        message to delete, use the ``ReceiptHandle`` of the message (*not* the
        ``MessageId`` which you receive when you send the message). Amazon SQS
        can delete a message from a queue even if a visibility timeout setting
        causes the message to be locked by another consumer. Amazon SQS
        automatically deletes messages left in a queue longer than the retention
        period configured for the queue.

        The ``ReceiptHandle`` is associated with a *specific instance* of
        receiving a message. If you receive a message more than once, the
        ``ReceiptHandle`` is different each time you receive a message. When you
        use the ``DeleteMessage`` action, you must provide the most recently
        received ``ReceiptHandle`` for the message (otherwise, the request
        succeeds, but the message might not be deleted).

        For standard queues, it is possible to receive a message even after you
        delete it. This might happen on rare occasions if one of the servers
        which stores a copy of the message is unavailable when you send the
        request to delete the message. The copy remains on the server and might
        be returned to you during a subsequent receive request. You should
        ensure that your application is idempotent, so that receiving a message
        more than once does not cause issues.

        :param queue_url: The URL of the Amazon SQS queue from which messages are deleted.
        :param receipt_handle: The receipt handle associated with the message to delete.
        :raises InvalidIdFormat:
        :raises ReceiptHandleIsInvalid:
        """
        raise NotImplementedError

    @handler("DeleteMessageBatch")
    def delete_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: DeleteMessageBatchRequestEntryList,
    ) -> DeleteMessageBatchResult:
        """Deletes up to ten messages from the specified queue. This is a batch
        version of ``DeleteMessage.`` The result of the action on each message
        is reported individually in the response.

        Because the batch request can result in a combination of successful and
        unsuccessful actions, you should check for batch errors even when the
        call returns an HTTP status code of ``200``.

        Some actions take lists of parameters. These lists are specified using
        the ``param.n`` notation. Values of ``n`` are integers starting from 1.
        For example, a parameter list with two elements looks like this:

        ``&AttributeName.1=first``

        ``&AttributeName.2=second``

        :param queue_url: The URL of the Amazon SQS queue from which messages are deleted.
        :param entries: A list of receipt handles for the messages to be deleted.
        :returns: DeleteMessageBatchResult
        :raises TooManyEntriesInBatchRequest:
        :raises EmptyBatchRequest:
        :raises BatchEntryIdsNotDistinct:
        :raises InvalidBatchEntryId:
        """
        raise NotImplementedError

    @handler("DeleteQueue")
    def delete_queue(self, context: RequestContext, queue_url: String) -> None:
        """Deletes the queue specified by the ``QueueUrl``, regardless of the
        queue's contents.

        Be careful with the ``DeleteQueue`` action: When you delete a queue, any
        messages in the queue are no longer available.

        When you delete a queue, the deletion process takes up to 60 seconds.
        Requests you send involving that queue during the 60 seconds might
        succeed. For example, a ``SendMessage`` request might succeed, but after
        60 seconds the queue and the message you sent no longer exist.

        When you delete a queue, you must wait at least 60 seconds before
        creating a queue with the same name.

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_url: The URL of the Amazon SQS queue to delete.
        """
        raise NotImplementedError

    @handler("GetQueueAttributes")
    def get_queue_attributes(
        self,
        context: RequestContext,
        queue_url: String,
        attribute_names: AttributeNameList = None,
    ) -> GetQueueAttributesResult:
        """Gets attributes for the specified queue.

        To determine whether a queue is
        `FIFO <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`__,
        you can check whether ``QueueName`` ends with the ``.fifo`` suffix.

        :param queue_url: The URL of the Amazon SQS queue whose attribute information is
        retrieved.
        :param attribute_names: A list of attributes for which to retrieve information.
        :returns: GetQueueAttributesResult
        :raises InvalidAttributeName:
        """
        raise NotImplementedError

    @handler("GetQueueUrl")
    def get_queue_url(
        self,
        context: RequestContext,
        queue_name: String,
        queue_owner_aws_account_id: String = None,
    ) -> GetQueueUrlResult:
        """Returns the URL of an existing Amazon SQS queue.

        To access a queue that belongs to another AWS account, use the
        ``QueueOwnerAWSAccountId`` parameter to specify the account ID of the
        queue's owner. The queue's owner must grant you permission to access the
        queue. For more information about shared queue access, see
        ``AddPermission`` or see `Allow Developers to Write Messages to a Shared
        Queue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-writing-an-sqs-policy.html#write-messages-to-shared-queue>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_name: The name of the queue whose URL must be fetched.
        :param queue_owner_aws_account_id: The account ID of the account that created the queue.
        :returns: GetQueueUrlResult
        :raises QueueDoesNotExist:
        """
        raise NotImplementedError

    @handler("ListDeadLetterSourceQueues")
    def list_dead_letter_source_queues(
        self,
        context: RequestContext,
        queue_url: String,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListDeadLetterSourceQueuesResult:
        """Returns a list of your queues that have the ``RedrivePolicy`` queue
        attribute configured with a dead-letter queue.

        The ``ListDeadLetterSourceQueues`` methods supports pagination. Set
        parameter ``MaxResults`` in the request to specify the maximum number of
        results to be returned in the response. If you do not set
        ``MaxResults``, the response includes a maximum of 1,000 results. If you
        set ``MaxResults`` and there are additional results to display, the
        response includes a value for ``NextToken``. Use ``NextToken`` as a
        parameter in your next request to ``ListDeadLetterSourceQueues`` to
        receive the next page of results.

        For more information about using dead-letter queues, see `Using Amazon
        SQS Dead-Letter
        Queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_url: The URL of a dead-letter queue.
        :param next_token: Pagination token to request the next set of results.
        :param max_results: Maximum number of results to include in the response.
        :returns: ListDeadLetterSourceQueuesResult
        :raises QueueDoesNotExist:
        """
        raise NotImplementedError

    @handler("ListQueueTags")
    def list_queue_tags(self, context: RequestContext, queue_url: String) -> ListQueueTagsResult:
        """List all cost allocation tags added to the specified Amazon SQS queue.
        For an overview, see `Tagging Your Amazon SQS
        Queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-tags.html>`__
        in the *Amazon SQS Developer Guide*.

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_url: The URL of the queue.
        :returns: ListQueueTagsResult
        """
        raise NotImplementedError

    @handler("ListQueues")
    def list_queues(
        self,
        context: RequestContext,
        queue_name_prefix: String = None,
        next_token: Token = None,
        max_results: BoxedInteger = None,
    ) -> ListQueuesResult:
        """Returns a list of your queues in the current region. The response
        includes a maximum of 1,000 results. If you specify a value for the
        optional ``QueueNamePrefix`` parameter, only queues with a name that
        begins with the specified value are returned.

        The ``listQueues`` methods supports pagination. Set parameter
        ``MaxResults`` in the request to specify the maximum number of results
        to be returned in the response. If you do not set ``MaxResults``, the
        response includes a maximum of 1,000 results. If you set ``MaxResults``
        and there are additional results to display, the response includes a
        value for ``NextToken``. Use ``NextToken`` as a parameter in your next
        request to ``listQueues`` to receive the next page of results.

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_name_prefix: A string to use for filtering the list results.
        :param next_token: Pagination token to request the next set of results.
        :param max_results: Maximum number of results to include in the response.
        :returns: ListQueuesResult
        """
        raise NotImplementedError

    @handler("PurgeQueue")
    def purge_queue(self, context: RequestContext, queue_url: String) -> None:
        """Deletes the messages in a queue specified by the ``QueueURL`` parameter.

        When you use the ``PurgeQueue`` action, you can't retrieve any messages
        deleted from a queue.

        The message deletion process takes up to 60 seconds. We recommend
        waiting for 60 seconds regardless of your queue's size.

        Messages sent to the queue *before* you call ``PurgeQueue`` might be
        received but are deleted within the next minute.

        Messages sent to the queue *after* you call ``PurgeQueue`` might be
        deleted while the queue is being purged.

        :param queue_url: The URL of the queue from which the ``PurgeQueue`` action deletes
        messages.
        :raises QueueDoesNotExist:
        :raises PurgeQueueInProgress:
        """
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
        """Retrieves one or more messages (up to 10), from the specified queue.
        Using the ``WaitTimeSeconds`` parameter enables long-poll support. For
        more information, see `Amazon SQS Long
        Polling <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-long-polling.html>`__
        in the *Amazon SQS Developer Guide*.

        Short poll is the default behavior where a weighted random set of
        machines is sampled on a ``ReceiveMessage`` call. Thus, only the
        messages on the sampled machines are returned. If the number of messages
        in the queue is small (fewer than 1,000), you most likely get fewer
        messages than you requested per ``ReceiveMessage`` call. If the number
        of messages in the queue is extremely small, you might not receive any
        messages in a particular ``ReceiveMessage`` response. If this happens,
        repeat the request.

        For each message returned, the response includes the following:

        -  The message body.

        -  An MD5 digest of the message body. For information about MD5, see
           `RFC1321 <https://www.ietf.org/rfc/rfc1321.txt>`__.

        -  The ``MessageId`` you received when you sent the message to the
           queue.

        -  The receipt handle.

        -  The message attributes.

        -  An MD5 digest of the message attributes.

        The receipt handle is the identifier you must provide when deleting the
        message. For more information, see `Queue and Message
        Identifiers <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-message-identifiers.html>`__
        in the *Amazon SQS Developer Guide*.

        You can provide the ``VisibilityTimeout`` parameter in your request. The
        parameter is applied to the messages that Amazon SQS returns in the
        response. If you don't include the parameter, the overall visibility
        timeout for the queue is used for the returned messages. For more
        information, see `Visibility
        Timeout <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>`__
        in the *Amazon SQS Developer Guide*.

        A message that isn't deleted or a message whose visibility isn't
        extended before the visibility timeout expires counts as a failed
        receive. Depending on the configuration of the queue, the message might
        be sent to the dead-letter queue.

        In the future, new attributes might be added. If you write code that
        calls this action, we recommend that you structure your code so that it
        can handle new attributes gracefully.

        :param queue_url: The URL of the Amazon SQS queue from which messages are received.
        :param attribute_names: A list of attributes that need to be returned along with each message.
        :param message_attribute_names: The name of the message attribute, where *N* is the index.
        :param max_number_of_messages: The maximum number of messages to return.
        :param visibility_timeout: The duration (in seconds) that the received messages are hidden from
        subsequent retrieve requests after being retrieved by a
        ``ReceiveMessage`` request.
        :param wait_time_seconds: The duration (in seconds) for which the call waits for a message to
        arrive in the queue before returning.
        :param receive_request_attempt_id: This parameter applies only to FIFO (first-in-first-out) queues.
        :returns: ReceiveMessageResult
        :raises OverLimit:
        """
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(self, context: RequestContext, queue_url: String, label: String) -> None:
        """Revokes any permissions in the queue policy that matches the specified
        ``Label`` parameter.

        -  Only the owner of a queue can remove permissions from it.

        -  Cross-account permissions don't apply to this action. For more
           information, see `Grant cross-account permissions to a role and a
           user
           name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
           in the *Amazon SQS Developer Guide*.

        -  To remove the ability to change queue permissions, you must deny
           permission to the ``AddPermission``, ``RemovePermission``, and
           ``SetQueueAttributes`` actions in your IAM policy.

        :param queue_url: The URL of the Amazon SQS queue from which permissions are removed.
        :param label: The identification of the permission to remove.
        """
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
        """Delivers a message to the specified queue.

        A message can include only XML, JSON, and unformatted text. The
        following Unicode characters are allowed:

        ``#x9`` \| ``#xA`` \| ``#xD`` \| ``#x20`` to ``#xD7FF`` \| ``#xE000`` to
        ``#xFFFD`` \| ``#x10000`` to ``#x10FFFF``

        Any characters not included in this list will be rejected. For more
        information, see the `W3C specification for
        characters <http://www.w3.org/TR/REC-xml/#charsets>`__.

        :param queue_url: The URL of the Amazon SQS queue to which a message is sent.
        :param message_body: The message to send.
        :param delay_seconds: The length of time, in seconds, for which to delay a specific message.
        :param message_attributes: Each message attribute consists of a ``Name``, ``Type``, and ``Value``.
        :param message_system_attributes: The message system attribute to send.
        :param message_deduplication_id: This parameter applies only to FIFO (first-in-first-out) queues.
        :param message_group_id: This parameter applies only to FIFO (first-in-first-out) queues.
        :returns: SendMessageResult
        :raises InvalidMessageContents:
        :raises UnsupportedOperation:
        """
        raise NotImplementedError

    @handler("SendMessageBatch")
    def send_message_batch(
        self,
        context: RequestContext,
        queue_url: String,
        entries: SendMessageBatchRequestEntryList,
    ) -> SendMessageBatchResult:
        """Delivers up to ten messages to the specified queue. This is a batch
        version of ``SendMessage.`` For a FIFO queue, multiple messages within a
        single batch are enqueued in the order they are sent.

        The result of sending each message is reported individually in the
        response. Because the batch request can result in a combination of
        successful and unsuccessful actions, you should check for batch errors
        even when the call returns an HTTP status code of ``200``.

        The maximum allowed individual message size and the maximum total
        payload size (the sum of the individual lengths of all of the batched
        messages) are both 256 KB (262,144 bytes).

        A message can include only XML, JSON, and unformatted text. The
        following Unicode characters are allowed:

        ``#x9`` \| ``#xA`` \| ``#xD`` \| ``#x20`` to ``#xD7FF`` \| ``#xE000`` to
        ``#xFFFD`` \| ``#x10000`` to ``#x10FFFF``

        Any characters not included in this list will be rejected. For more
        information, see the `W3C specification for
        characters <http://www.w3.org/TR/REC-xml/#charsets>`__.

        If you don't specify the ``DelaySeconds`` parameter for an entry, Amazon
        SQS uses the default value for the queue.

        Some actions take lists of parameters. These lists are specified using
        the ``param.n`` notation. Values of ``n`` are integers starting from 1.
        For example, a parameter list with two elements looks like this:

        ``&AttributeName.1=first``

        ``&AttributeName.2=second``

        :param queue_url: The URL of the Amazon SQS queue to which batched messages are sent.
        :param entries: A list of ``SendMessageBatchRequestEntry`` items.
        :returns: SendMessageBatchResult
        :raises TooManyEntriesInBatchRequest:
        :raises EmptyBatchRequest:
        :raises BatchEntryIdsNotDistinct:
        :raises BatchRequestTooLong:
        :raises InvalidBatchEntryId:
        :raises UnsupportedOperation:
        """
        raise NotImplementedError

    @handler("SetQueueAttributes")
    def set_queue_attributes(
        self, context: RequestContext, queue_url: String, attributes: QueueAttributeMap
    ) -> None:
        """Sets the value of one or more queue attributes. When you change a
        queue's attributes, the change can take up to 60 seconds for most of the
        attributes to propagate throughout the Amazon SQS system. Changes made
        to the ``MessageRetentionPeriod`` attribute can take up to 15 minutes.

        -  In the future, new attributes might be added. If you write code that
           calls this action, we recommend that you structure your code so that
           it can handle new attributes gracefully.

        -  Cross-account permissions don't apply to this action. For more
           information, see `Grant cross-account permissions to a role and a
           user
           name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
           in the *Amazon SQS Developer Guide*.

        -  To remove the ability to change queue permissions, you must deny
           permission to the ``AddPermission``, ``RemovePermission``, and
           ``SetQueueAttributes`` actions in your IAM policy.

        :param queue_url: The URL of the Amazon SQS queue whose attributes are set.
        :param attributes: A map of attributes to set.
        :raises InvalidAttributeName:
        """
        raise NotImplementedError

    @handler("TagQueue")
    def tag_queue(self, context: RequestContext, queue_url: String, tags: TagMap) -> None:
        """Add cost allocation tags to the specified Amazon SQS queue. For an
        overview, see `Tagging Your Amazon SQS
        Queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-tags.html>`__
        in the *Amazon SQS Developer Guide*.

        When you use queue tags, keep the following guidelines in mind:

        -  Adding more than 50 tags to a queue isn't recommended.

        -  Tags don't have any semantic meaning. Amazon SQS interprets tags as
           character strings.

        -  Tags are case-sensitive.

        -  A new tag with a key identical to that of an existing tag overwrites
           the existing tag.

        For a full list of tag restrictions, see `Quotas related to
        queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-limits.html#limits-queues>`__
        in the *Amazon SQS Developer Guide*.

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_url: The URL of the queue.
        :param tags: The list of tags to be added to the specified queue.
        """
        raise NotImplementedError

    @handler("UntagQueue")
    def untag_queue(self, context: RequestContext, queue_url: String, tag_keys: TagKeyList) -> None:
        """Remove cost allocation tags from the specified Amazon SQS queue. For an
        overview, see `Tagging Your Amazon SQS
        Queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-tags.html>`__
        in the *Amazon SQS Developer Guide*.

        Cross-account permissions don't apply to this action. For more
        information, see `Grant cross-account permissions to a role and a user
        name <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-customer-managed-policy-examples.html#grant-cross-account-permissions-to-role-and-user-name>`__
        in the *Amazon SQS Developer Guide*.

        :param queue_url: The URL of the queue.
        :param tag_keys: The list of tags to be removed from the specified queue.
        """
        raise NotImplementedError
