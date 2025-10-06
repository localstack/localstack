import json
from typing import TypedDict

from localstack.aws.api import RequestContext
from localstack.aws.api.sns import TopicAttributesMap
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws.arns import sns_topic_arn
from localstack.utils.tagging import TaggingService


class Topic(TypedDict, total=True):
    arn: str
    name: str
    region: str
    account_id: str
    attributes: TopicAttributesMap


def create_topic(name: str, attributes: dict, context: RequestContext) -> Topic:
    topic_arn = sns_topic_arn(
        topic_name=name, region_name=context.region, account_id=context.account_id
    )
    topic: Topic = {
        "name": name,
        "arn": topic_arn,
        "region": context.region,
        "account_id": context.account_id,
        "attributes": {},
    }
    attrs = default_attributes(topic)
    attrs.update(attributes or {})
    topic["attributes"] = attrs

    return topic


def default_attributes(topic: Topic) -> TopicAttributesMap:
    default_attributes = {
        "DisplayName": "",
        "Owner": topic["account_id"],
        "Policy": create_default_topic_policy(topic),
        "SubscriptionsConfirmed": "0",
        "SubscriptionsDeleted": "0",
        "SubscriptionsPending": "0",
        "TopicArn": topic["arn"],
    }
    if topic["name"].endswith(".fifo"):
        default_attributes.update(
            {
                "ContentBasedDeduplication": "false",
                "FifoTopic": "false",
                "SignatureVersion": "2",
            }
        )
    return default_attributes


def create_default_topic_policy(topic: Topic) -> str:
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
                    "Resource": topic["arn"],
                    "Condition": {"StringEquals": {"AWS:SourceOwner": topic["account_id"]}},
                }
            ],
        }
    )


class SnsStore(BaseStore):
    topics: dict[str, Topic] = LocalAttribute(default=dict)

    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


sns_stores = AccountRegionBundle("sns", SnsStore)
