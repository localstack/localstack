import logging
import re

from botocore.utils import InvalidArnException

from localstack.aws.api import RequestContext
from localstack.aws.api.sns import (
    CreateTopicResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    InvalidParameterValueException,
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
        topic_ARN = sns_topic_arn(
            topic_name=name, region_name=context.region, account_id=context.account_id
        )
        topic: Topic = store.topics.get(topic_ARN)
        attributes = attributes or {}
        if topic:
            attrs = topic.attributes
            for k, v in attributes.values():
                if not attrs.get(k) or not attrs.get(k) == v:
                    # TODO:
                    raise InvalidParameterException("Fix this Exception message and type")
            return CreateTopicResponse(TopicArn=topic_ARN)

        topic = Topic(name=name, attributes=attributes, arn=topic_ARN, context=context)

        if attributes is None:
            attributes = {}
        if attributes.get("FifoTopic") and attributes["FifoTopic"].lower() == "true":
            fifo_match = re.match(SNS_TOPIC_NAME_PATTERN_FIFO, name)
            if not fifo_match:
                raise InvalidParameterValueException(
                    "Fifo Topic names must end with .fifo and must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long."
                )
        else:
            name_match = re.match(SNS_TOPIC_NAME_PATTERN, name)
            if not name_match:
                raise InvalidParameterValueException(
                    "Topic names must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long."
                )

        # if attributes:
        # self.set_topic_defaults(topic, context)
        # topic["attributes"] = attributes
        store.topics[topic_ARN] = topic
        # todo: tags

        return CreateTopicResponse(TopicArn=topic_ARN)

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> GetTopicAttributesResponse:
        topic: Topic = self._get_topic(arn=topic_arn, context=context)
        if topic:
            attributes = topic.attributes
            return GetTopicAttributesResponse(Attributes=attributes)
        else:
            raise NotFoundException("Topic does not exist")

    def delete_topic(self, context: RequestContext, topic_arn: topicARN, **kwargs) -> None:
        store = self.get_store(context.account_id, context.region)

        if store.topics.get(topic_arn):
            del store.topics[topic_arn]

    def list_topics(
        self, context: RequestContext, next_token: nextToken | None = None, **kwargs
    ) -> ListTopicsResponse:
        store = self.get_store(context.account_id, context.region)

        return ListTopicsResponse(Topics=[t.arn for t in store.topics.values()])

    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue | None = None,
        **kwargs,
    ) -> None:
        topic: Topic = self._get_topic(arn=topic_arn, context=context)
        topic.attributes[attribute_name] = attribute_value

    @staticmethod
    def get_store(account_id: str, region: str) -> SnsStore:
        return sns_stores[account_id][region]

    @staticmethod
    def _get_topic(arn: str, context: RequestContext) -> Topic:
        """
        :param arn: the Topic ARN
        :param context: the RequestContext of the request
        :param multiregion: if the request can fetch the topic across regions or not (ex. Publish cannot publish to a
        topic in a different region than the request)
        :return: the Moto model Topic
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
