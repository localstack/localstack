# Valid unicode values: #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
from localstack.aws.api.sqs import QueueAttributeName

MSG_CONTENT_REGEX = "^[\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]*$"

# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html
# While not documented, umlauts seem to be allowed
ATTR_NAME_CHAR_REGEX = "^[\u00C0-\u017Fa-zA-Z0-9_.-]*$"
ATTR_NAME_PREFIX_SUFFIX_REGEX = r"^(?!(aws\.|amazon\.|\.)).*(?<!\.)$"
ATTR_TYPE_REGEX = "^(String|Number|Binary).*$"
FIFO_MSG_REGEX = "^[0-9a-zA-z!\"#$%&'()*+,./:;<=>?@[\\]^_`{|}~-]*$"

DEDUPLICATION_INTERVAL_IN_SEC = 5 * 60

# When you delete a queue, you must wait at least 60 seconds before creating a queue with the same name.
# see https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteQueue.html
RECENTLY_DELETED_TIMEOUT = 60

# the default maximum message size in SQS
DEFAULT_MAXIMUM_MESSAGE_SIZE = 262144
INTERNAL_QUEUE_ATTRIBUTES = [
    # these attributes cannot be changed by set_queue_attributes and should
    # therefore be ignored when comparing queue attributes for create_queue
    # 'FifoQueue' is handled on a per_queue basis
    QueueAttributeName.ApproximateNumberOfMessages,
    QueueAttributeName.ApproximateNumberOfMessagesDelayed,
    QueueAttributeName.ApproximateNumberOfMessagesNotVisible,
    QueueAttributeName.CreatedTimestamp,
    QueueAttributeName.LastModifiedTimestamp,
    QueueAttributeName.QueueArn,
]

# URL regexes for various endpoint strategies
STANDARD_STRATEGY_URL_REGEX = r"sqs.(?P<region_name>[a-z0-9-]{1,})\.[^:]+:\d{4,5}\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
DOMAIN_STRATEGY_URL_REGEX = r"((?P<region_name>[a-z0-9-]{1,})\.)?queue\.[^:]+:\d{4,5}\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
PATH_STRATEGY_URL_REGEX = r"[^:]+:\d{4,5}\/queue\/(?P<region_name>[a-z0-9-]{1,})\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
LEGACY_STRATEGY_URL_REGEX = (
    r"[^:]+:\d{4,5}\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
)
