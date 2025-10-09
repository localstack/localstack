import json
import logging
import re

from botocore.utils import InvalidArnException

from localstack.aws.api import RequestContext
from localstack.aws.api.sns import (
    CreateTopicResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    ListTopicsResponse,
    NotFoundException,
    SnsApi,
    TagList,
    TopicAttributesMap,
    attributeName,
    attributeValue,
    nextToken,
    topicARN,
    topicName,
)
from localstack.services.sns.v2.models import SnsStore, Topic, sns_stores
from localstack.utils.aws.arns import ArnData, parse_arn, sns_topic_arn
from localstack.utils.collections import PaginatedList

# set up logger
LOG = logging.getLogger(__name__)

SNS_TOPIC_NAME_PATTERN_FIFO = r"^[a-zA-Z0-9_-]{1,256}\.fifo$"
SNS_TOPIC_NAME_PATTERN = r"^[a-zA-Z0-9_-]{1,256}$"


class SnsProvider(SnsApi):
    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap | None = None,
        tags: TagList | None = None,
        data_protection_policy: attributeValue | None = None,
        **kwargs,
    ) -> CreateTopicResponse:
        store = self.get_store(context.account_id, context.region)
        topic_arn = sns_topic_arn(
            topic_name=name, region_name=context.region, account_id=context.account_id
        )
        topic: Topic = store.topics.get(topic_arn)
        attributes = attributes or {}
        if topic:
            attrs = topic["attributes"]
            for k, v in attributes.values():
                if not attrs.get(k) or not attrs.get(k) == v:
                    # TODO:
                    raise InvalidParameterException("Fix this Exception message and type")
            return CreateTopicResponse(TopicArn=topic_arn)

        attributes = attributes or {}
        if attributes.get("FifoTopic") and attributes["FifoTopic"].lower() == "true":
            fifo_match = re.match(SNS_TOPIC_NAME_PATTERN_FIFO, name)
            if not fifo_match:
                # TODO: check this with a separate test
                raise InvalidParameterException(
                    "Fifo Topic names must end with .fifo and must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long."
                )
        else:
            # AWS does not seem to save explicit settings of fifo = false
            attributes.pop("FifoTopic", None)
            name_match = re.match(SNS_TOPIC_NAME_PATTERN, name)
            if not name_match:
                raise InvalidParameterException("Invalid parameter: Topic Name")

        topic = _create_topic(name=name, attributes=attributes, context=context)
        store.topics[topic_arn] = topic
        # todo: tags

        return CreateTopicResponse(TopicArn=topic_arn)

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> GetTopicAttributesResponse:
        topic: Topic = self._get_topic(arn=topic_arn, context=context)
        if topic:
            attributes = topic["attributes"]
            return GetTopicAttributesResponse(Attributes=attributes)
        else:
            raise NotFoundException("Topic does not exist")

    def delete_topic(self, context: RequestContext, topic_arn: topicARN, **kwargs) -> None:
        store = self.get_store(context.account_id, context.region)

        store.topics.pop(topic_arn, None)

    def list_topics(
        self, context: RequestContext, next_token: nextToken | None = None, **kwargs
    ) -> ListTopicsResponse:
        store = self.get_store(context.account_id, context.region)
        topics = [{"TopicArn": t["arn"]} for t in list(store.topics.values())]
        topics = PaginatedList(topics)
        page, nxt = topics.get_page(
            lambda topic: topic["TopicArn"], next_token=next_token, page_size=100
        )
        topics = {"Topics": page, "NextToken": nxt}
        return ListTopicsResponse(**topics)

    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue | None = None,
        **kwargs,
    ) -> None:
        topic: Topic = self._get_topic(arn=topic_arn, context=context)
        if attribute_name == "FifoTopic":
            raise InvalidParameterException("Invalid parameter: AttributeName")
        topic["attributes"][attribute_name] = attribute_value

    @staticmethod
    def get_store(account_id: str, region: str) -> SnsStore:
        return sns_stores[account_id][region]

    # TODO: reintroduce multi-region parameter (latest before final migration from v1)
    @staticmethod
    def _get_topic(arn: str, context: RequestContext) -> Topic:
        """
        :param arn: the Topic ARN
        :param context: the RequestContext of the request
        :return: the model Topic
        """
        arn_data = parse_and_validate_topic_arn(arn)
        if context.region != arn_data["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")
        try:
            store = SnsProvider.get_store(context.account_id, context.region)
            return store.topics[arn]
        except KeyError:
            raise NotFoundException("Topic does not exist")


def parse_and_validate_topic_arn(topic_arn: str | None) -> ArnData:
    topic_arn = topic_arn or ""
    try:
        return parse_arn(topic_arn)
    except InvalidArnException:
        count = len(topic_arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not {count}"
        )


def _create_topic(name: str, attributes: dict, context: RequestContext) -> Topic:
    topic_arn = sns_topic_arn(
        topic_name=name, region_name=context.region, account_id=context.account_id
    )
    topic: Topic = {
        "name": name,
        "arn": topic_arn,
        "attributes": {},
    }
    attrs = _default_attributes(topic, context)
    attrs.update(attributes or {})
    topic["attributes"] = attrs

    return topic


def _default_attributes(topic: Topic, context: RequestContext) -> TopicAttributesMap:
    default_attributes = {
        "DisplayName": "",
        "Owner": context.account_id,
        "Policy": _create_default_topic_policy(topic, context),
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


def _create_default_topic_policy(topic: Topic, context: RequestContext) -> str:
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
                    "Condition": {"StringEquals": {"AWS:SourceOwner": context.account_id}},
                }
            ],
        }
    )
