import itertools
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, TypedDict, Union

from localstack.aws.api.sns import (
    MessageAttributeMap,
    PublishBatchRequestEntry,
    subscriptionARN,
    topicARN,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.strings import long_uid

SnsProtocols = Literal[
    "http", "https", "email", "email-json", "sms", "sqs", "application", "lambda", "firehose"
]

SnsApplicationPlatforms = Literal[
    "APNS", "APNS_SANDBOX", "ADM", "FCM", "Baidu", "GCM", "MPNS", "WNS"
]

SnsMessageProtocols = Literal[SnsProtocols, SnsApplicationPlatforms]


@dataclass
class SnsMessage:
    type: str
    message: Union[
        str, Dict
    ]  # can be Dict if after being JSON decoded for validation if structure is `json`
    message_attributes: Optional[MessageAttributeMap] = None
    message_structure: Optional[str] = None
    subject: Optional[str] = None
    message_deduplication_id: Optional[str] = None
    message_group_id: Optional[str] = None
    sequence_number: Optional[int] = None
    token: Optional[str] = None
    message_id: str = field(default_factory=long_uid)

    def __post_init__(self):
        if self.message_attributes is None:
            self.message_attributes = {}

    def message_content(self, protocol: SnsMessageProtocols) -> str:
        """
        Helper function to retrieve the message content for the right protocol if the StructureMessage is `json`
        See https://docs.aws.amazon.com/sns/latest/dg/sns-send-custom-platform-specific-payloads-mobile-devices.html
        https://docs.aws.amazon.com/sns/latest/dg/example_sns_Publish_section.html
        :param protocol:
        :return: message content as string
        """
        if self.message_structure == "json":
            return self.message.get(protocol, self.message.get("default"))

        return self.message

    @classmethod
    def from_batch_entry(cls, entry: PublishBatchRequestEntry) -> "SnsMessage":
        return cls(
            type="Notification",
            message=entry["Message"],
            subject=entry.get("Subject"),
            message_structure=entry.get("MessageStructure"),
            message_attributes=entry.get("MessageAttributes"),
            message_deduplication_id=entry.get("MessageDeduplicationId"),
            message_group_id=entry.get("MessageGroupId"),
        )


class SnsSubscription(TypedDict):
    """
    In SNS, Subscription can be represented with only TopicArn, Endpoint, Protocol, SubscriptionArn and Owner, for
    example in ListSubscriptions. However, when getting a subscription with GetSubscriptionAttributes, it will return
    the Subscription object merged with its own attributes.
    This represents this merged object, for internal use and in GetSubscriptionAttributes
    https://docs.aws.amazon.com/cli/latest/reference/sns/get-subscription-attributes.html
    """

    TopicArn: topicARN
    Endpoint: str
    Protocol: SnsProtocols
    SubscriptionArn: subscriptionARN
    PendingConfirmation: Literal["true", "false"]
    Owner: Optional[str]
    FilterPolicy: Optional[str]
    FilterPolicyScope: Literal["MessageAttributes", "MessageBody"]
    RawMessageDelivery: Literal["true", "false"]


class FifoMessageGroupIdLock:
    """This implements a functionality to lock worker threads of the ThreadPoolExecutor to be able to send FIFO
    messages in order. These will be stored in a dict in that shape:
    Dict[TopicArn, Dict[f"{queue}-{message_group-id}", FifoMessageGroupIdLock]
    This example shows that it would not lock any other publishing in a very big way, and allows other worker threads
    to successfully execute tasks.
    The SequenceNumber will be generated in the SNS `Publish` call and attached to the message context. It should
    actually be returned by the Publish call when sending to a FIFO topic. These should be an ever-increasing number
    linked to the MessageGroupId. It should be implemented in the Store as well.
    """

    def __init__(self):
        self.queue = deque()
        self.is_sequence_ready = threading.Condition()

    def _is_sequence_ready(self, sequence_number: int):
        """Predicate function for wait_for, allowing the condition to evaluate whether the sequence is ready to be
        executed
        :param sequence_number:
        :return: Boolean indicating sequence number is next to be processed
        """
        return self.queue[0] == sequence_number

    def wait_for_sequence(self, sequence_number: int) -> int:
        """
        This method will block until the sequence number is ready to be processed
        :param sequence_number:
        :return:
        """
        while True:
            with self.is_sequence_ready:
                condition = self.is_sequence_ready.wait_for(
                    lambda: self._is_sequence_ready(sequence_number), timeout=0.01
                )
            if condition:
                return condition

    def append(self, sequence_number: int):
        """Append the sequence number in the queue for it to be processed
        :param sequence_number:
        :return:
        """
        with self.is_sequence_ready:
            self.queue.append(sequence_number)
            # will unblock wait_for before timeout, avoiding busy waiting
            # we don't know which thread actually holds the next sequence number.
            # Would be more complicated to implement
            self.is_sequence_ready.notify_all()

    def pop(self):
        """Pop the first item in the queue, meaning it has been processed"""
        with self.is_sequence_ready:
            self.queue.popleft()
            # will unblock wait_for before timeout, avoiding busy waiting
            self.is_sequence_ready.notify_all()


class MessageGroupIdSequencer:
    def __init__(self):
        # creates a 20-digit number used as the start for the sequence
        start = int(time.time()) << 33
        # itertools.count is thread safe over the GIL since its getAndIncrement operation is a single python bytecode op
        self._sequencer = itertools.count(start)

    def get_next_number(self):
        return next(self._sequencer)


class SnsStore(BaseStore):
    # maps topic ARN to topic's subscriptions
    sns_subscriptions: Dict[str, List[SnsSubscription]] = LocalAttribute(default=dict)

    # maps subscription ARN to subscription status
    subscription_status: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps topic ARN to list of tags
    sns_tags: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # cache of topic ARN to platform endpoint messages (used primarily for testing)
    platform_endpoint_messages: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # list of sent SMS messages - TODO: expose via internal API
    sms_messages: List[Dict] = LocalAttribute(default=list)

    # filter policy are stored as JSON string in subscriptions, store the decoded result Dict
    subscription_filter_policy: Dict[subscriptionARN, Dict] = LocalAttribute(default=dict)

    fifo_topic_locking: Dict[topicARN, Dict[str, FifoMessageGroupIdLock]] = LocalAttribute(
        default=dict
    )
    topic_message_group_id_sequencer: Dict[str, MessageGroupIdSequencer] = LocalAttribute(
        default=dict
    )


sns_stores = AccountRegionBundle("sns", SnsStore)
