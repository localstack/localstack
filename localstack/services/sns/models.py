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
    SubscriptionPrincipal: Optional[str]
    FilterPolicy: Optional[str]
    FilterPolicyScope: Literal["MessageAttributes", "MessageBody"]
    RawMessageDelivery: Literal["true", "false"]
    ConfirmationWasAuthenticated: Literal["true", "false"]


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


sns_stores = AccountRegionBundle("sns", SnsStore)
