import json
from typing import Any, TypedDict

from localstack.aws.api import RequestContext
from localstack.aws.api.sns import TopicAttributesMap
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.tagging import TaggingService


class TopicAttributes(TypedDict, total=False):
    contentBasedDeduplication: bool
    displayName: str
    fifoTopic: bool
    owner: str
    policy: dict[str, Any]
    subscriptionsConfirmed: int
    subscriptionsDeleted: int
    subscriptionsPending: int
    topicArn: str


class Topic:
    arn: str
    name: str
    region: str
    account_id: str
    attributes: dict[str, Any]

    def __init__(self, name, arn, attributes: dict, context: RequestContext):
        self.account_id = context.account_id
        self.region = context.region
        self.name = name
        self.arn = arn
        self.attributes = self.default_attributes()
        self.attributes.update(attributes or {})

    def default_attributes(self) -> TopicAttributesMap:
        default_attributes = {
            "DisplayName": "",
            "Owner": self.account_id,
            "Policy": self.create_default_topic_policy(),
            "SubscriptionsConfirmed": "0",
            "SubscriptionsDeleted": "0",
            "SubscriptionsPending": "0",
            "TopicArn": self.arn,
        }
        if self.name.endswith(".fifo"):
            default_attributes.update(
                {
                    "ContentBasedDeduplication": "false",
                    "FifoTopic": "false",
                    "SignatureVersion": "2",
                }
            )
        return default_attributes

    def create_default_topic_policy(self) -> str:  # Dict[str, Any]:
        return json.dumps(
            {
                "Version": "2008-10-17",
                "Id": "__default_policy_ID",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Sid": "__default_statement_ID",
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
                        "Resource": self.arn,
                        "Condition": {"StringEquals": {"AWS:SourceOwner": self.account_id}},
                    }
                ],
            }
        )


class SnsStore(BaseStore):
    topics: dict[str, Topic] = LocalAttribute(default=dict)

    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


sns_stores = AccountRegionBundle("sns", SnsStore)
