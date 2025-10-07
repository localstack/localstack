from typing import TypedDict

from localstack.aws.api.sns import TopicAttributesMap
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.tagging import TaggingService


class Topic(TypedDict, total=True):
    arn: str
    name: str
    attributes: TopicAttributesMap


class SnsStore(BaseStore):
    topics: dict[str, Topic] = LocalAttribute(default=dict)

    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


sns_stores = AccountRegionBundle("sns", SnsStore)
