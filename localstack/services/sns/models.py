import itertools
import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, TypedDict, Union

from localstack.aws.api.sns import (
    MessageAttributeMap,
    PublishBatchRequestEntry,
    subscriptionARN,
    topicARN,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import long_uid

SnsProtocols = Literal[
    "http", "https", "email", "email-json", "sms", "sqs", "application", "lambda", "firehose"
]

SnsApplicationPlatforms = Literal[
    "APNS", "APNS_SANDBOX", "ADM", "FCM", "Baidu", "GCM", "MPNS", "WNS"
]

SnsMessageProtocols = Literal[SnsProtocols, SnsApplicationPlatforms]


@singleton_factory
def global_sns_message_sequence():
    # creates a 20-digit number used as the start for the global sequence, adds 100 for it to be different from SQS's
    # mostly for testing purpose, both global sequence would be initialized at the same and be identical
    start = int(time.time() + 100) << 33
    # itertools.count is thread safe over the GIL since its getAndIncrement operation is a single python bytecode op
    return itertools.count(start)


def get_next_sequence_number():
    return next(global_sns_message_sequence())


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
    token: Optional[str] = None
    message_id: str = field(default_factory=long_uid)
    is_fifo: Optional[bool] = False
    sequencer_number: Optional[str] = None

    def __post_init__(self):
        if self.message_attributes is None:
            self.message_attributes = {}
        if self.is_fifo:
            self.sequencer_number = str(get_next_sequence_number())

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
    def from_batch_entry(cls, entry: PublishBatchRequestEntry, is_fifo=False) -> "SnsMessage":
        return cls(
            type="Notification",
            message=entry["Message"],
            subject=entry.get("Subject"),
            message_structure=entry.get("MessageStructure"),
            message_attributes=entry.get("MessageAttributes"),
            message_deduplication_id=entry.get("MessageDeduplicationId"),
            message_group_id=entry.get("MessageGroupId"),
            is_fifo=is_fifo,
        )


class SnsSubscription(TypedDict, total=False):
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
    SubscriptionPrincipal: Optional[str]
    FilterPolicy: Optional[str]
    FilterPolicyScope: Literal["MessageAttributes", "MessageBody"]
    RawMessageDelivery: Literal["true", "false"]
    ConfirmationWasAuthenticated: Literal["true", "false"]
    SubscriptionRoleArn: Optional[str]


class SnsStore(BaseStore):
    # maps topic ARN to subscriptions ARN
    topic_subscriptions: Dict[str, List[str]] = LocalAttribute(default=dict)

    # maps subscription ARN to SnsSubscription
    subscriptions: Dict[str, SnsSubscription] = LocalAttribute(default=dict)

    # maps confirmation token to subscription ARN
    subscription_tokens: Dict[str, str] = LocalAttribute(default=dict)

    # maps topic ARN to list of tags
    sns_tags: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # cache of topic ARN to platform endpoint messages (used primarily for testing)
    platform_endpoint_messages: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # list of sent SMS messages
    sms_messages: List[Dict] = LocalAttribute(default=list)

    # filter policy are stored as JSON string in subscriptions, store the decoded result Dict
    subscription_filter_policy: Dict[subscriptionARN, Dict] = LocalAttribute(default=dict)

    def get_topic_subscriptions(self, topic_arn: str) -> List[SnsSubscription]:
        topic_subscriptions = self.topic_subscriptions.get(topic_arn, [])
        subscriptions = [
            subscription
            for subscription_arn in topic_subscriptions
            if (subscription := self.subscriptions.get(subscription_arn))
        ]
        return subscriptions


sns_stores = AccountRegionBundle("sns", SnsStore)
