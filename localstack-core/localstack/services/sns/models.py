import itertools
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, TypedDict

from localstack.aws.api.sns import (
    MessageAttributeMap,
    PublishBatchRequestEntry,
    subscriptionARN,
    topicARN,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.aws.arns import parse_arn
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import long_uid

SnsProtocols = Literal[
    "http", "https", "email", "email-json", "sms", "sqs", "application", "lambda", "firehose"
]

SnsApplicationPlatforms = Literal[
    "APNS", "APNS_SANDBOX", "ADM", "FCM", "Baidu", "GCM", "MPNS", "WNS"
]

SnsMessageProtocols = Literal[SnsProtocols, SnsApplicationPlatforms]


def create_default_sns_topic_policy(topic_arn: str) -> dict:
    """
    Creates the default SNS topic policy for the given topic ARN.

    :param topic_arn: The topic arn
    :return: A policy document
    """
    return {
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [
            {
                "Sid": "__default_statement_ID",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": [
                    "SNS:GetTopicAttributes",
                    "SNS:SetTopicAttributes",
                    "SNS:AddPermission",
                    "SNS:RemovePermission",
                    "SNS:DeleteTopic",
                    "SNS:Subscribe",
                    "SNS:ListSubscriptionsByTopic",
                    "SNS:Publish",
                ],
                "Resource": topic_arn,
                "Condition": {"StringEquals": {"AWS:SourceOwner": parse_arn(topic_arn)["account"]}},
            }
        ],
    }


@singleton_factory
def global_sns_message_sequence():
    # creates a 20-digit number used as the start for the global sequence, adds 100 for it to be different from SQS's
    # mostly for testing purpose, both global sequence would be initialized at the same and be identical
    start = int(time.time() + 100) << 33
    # itertools.count is thread safe over the GIL since its getAndIncrement operation is a single python bytecode op
    return itertools.count(start)


def get_next_sequence_number():
    return next(global_sns_message_sequence())


class SnsMessageType(StrEnum):
    Notification = "Notification"
    SubscriptionConfirmation = "SubscriptionConfirmation"
    UnsubscribeConfirmation = "UnsubscribeConfirmation"


@dataclass
class SnsMessage:
    type: SnsMessageType
    message: (
        str | dict
    )  # can be Dict if after being JSON decoded for validation if structure is `json`
    message_attributes: MessageAttributeMap | None = None
    message_structure: str | None = None
    subject: str | None = None
    message_deduplication_id: str | None = None
    message_group_id: str | None = None
    token: str | None = None
    message_id: str = field(default_factory=long_uid)
    is_fifo: bool | None = False
    sequencer_number: str | None = None

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
            type=SnsMessageType.Notification,
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
    Owner: str | None
    SubscriptionPrincipal: str | None
    FilterPolicy: str | None
    FilterPolicyScope: Literal["MessageAttributes", "MessageBody"]
    RawMessageDelivery: Literal["true", "false"]
    ConfirmationWasAuthenticated: Literal["true", "false"]
    SubscriptionRoleArn: str | None
    DeliveryPolicy: str | None


class SnsStore(BaseStore):
    # maps topic ARN to subscriptions ARN
    topic_subscriptions: dict[str, list[str]] = LocalAttribute(default=dict)

    # maps subscription ARN to SnsSubscription
    subscriptions: dict[str, SnsSubscription] = LocalAttribute(default=dict)

    # maps confirmation token to subscription ARN
    subscription_tokens: dict[str, str] = LocalAttribute(default=dict)

    # maps topic ARN to list of tags
    sns_tags: dict[str, list[dict]] = LocalAttribute(default=dict)

    # cache of topic ARN to platform endpoint messages (used primarily for testing)
    platform_endpoint_messages: dict[str, list[dict]] = LocalAttribute(default=dict)

    # list of sent SMS messages
    sms_messages: list[dict] = LocalAttribute(default=list)

    # filter policy are stored as JSON string in subscriptions, store the decoded result Dict
    subscription_filter_policy: dict[subscriptionARN, dict] = LocalAttribute(default=dict)

    def get_topic_subscriptions(self, topic_arn: str) -> list[SnsSubscription]:
        topic_subscriptions = self.topic_subscriptions.get(topic_arn, [])
        subscriptions = [
            subscription
            for subscription_arn in topic_subscriptions
            if (subscription := self.subscriptions.get(subscription_arn))
        ]
        return subscriptions


sns_stores = AccountRegionBundle("sns", SnsStore)
