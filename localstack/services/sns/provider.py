from localstack.aws.api import RequestContext
from localstack.aws.api.sns import (
    CreateTopicResponse,
    SnsApi,
    TagList,
    TopicAttributesMap,
    topicARN,
    topicName,
)
from localstack.services.plugins import ServiceLifecycleHook


class SnsProvider(SnsApi, ServiceLifecycleHook):
    def delete_topic(self, context: RequestContext, topic_arn: topicARN) -> None:
        raise NotImplementedError

    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap = None,
        tags: TagList = None,
    ) -> CreateTopicResponse:
        raise NotImplementedError
