from typing import TypedDict

from localstack.aws.api.sts import Tag
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


class SessionTaggingConfig(TypedDict):
    # <lower-case-tag-key> => {"Key": <case-preserved-tag-key>, "Value": <tag-value>}
    tags: dict[str, Tag]
    # list of lowercase transitive tag keys
    transitive_tags: list[str]


class STSStore(BaseStore):
    # maps access key ids to tagging config for the session they belong to
    session_tags: dict[str, SessionTaggingConfig] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)
