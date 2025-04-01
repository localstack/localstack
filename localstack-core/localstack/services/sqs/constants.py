# Valid unicode values: #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
from localstack.aws.api.sqs import QueueAttributeName

MSG_CONTENT_REGEX = "^[\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]*$"

# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html
# While not documented, umlauts seem to be allowed
ATTR_NAME_CHAR_REGEX = "^[\u00c0-\u017fa-zA-Z0-9_.-]*$"
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

INVALID_STANDARD_QUEUE_ATTRIBUTES = [
    QueueAttributeName.FifoQueue,
    QueueAttributeName.ContentBasedDeduplication,
    *INTERNAL_QUEUE_ATTRIBUTES,
]

# URL regexes for various endpoint strategies
STANDARD_STRATEGY_URL_REGEX = r"sqs.(?P<region_name>[a-z0-9-]{1,})\.[^:]+:\d{4,5}\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
DOMAIN_STRATEGY_URL_REGEX = r"((?P<region_name>[a-z0-9-]{1,})\.)?queue\.[^:]+:\d{4,5}\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
PATH_STRATEGY_URL_REGEX = r"[^:]+:\d{4,5}\/queue\/(?P<region_name>[a-z0-9-]{1,})\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
LEGACY_STRATEGY_URL_REGEX = (
    r"[^:]+:\d{4,5}\/(?P<account_id>\d{12})\/(?P<queue_name>[a-zA-Z0-9_-]+(.fifo)?)$"
)

# HTTP headers used to override internal SQS ReceiveMessage
HEADER_LOCALSTACK_SQS_OVERRIDE_MESSAGE_COUNT = "x-localstack-sqs-override-message-count"
HEADER_LOCALSTACK_SQS_OVERRIDE_WAIT_TIME_SECONDS = "x-localstack-sqs-override-wait-time-seconds"

# response includes a default maximum of 1,000 results
MAX_RESULT_LIMIT = 1000

# SQS string seed value for uuid generation
SQS_UUID_STRING_SEED = "123e4567-e89b-12d3-a456-426614174000"
