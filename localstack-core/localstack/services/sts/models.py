from typing import TypedDict

from localstack.aws.api.sts import Tag
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


class SessionConfig(TypedDict):
    # <lower-case-tag-key> => {"Key": <case-preserved-tag-key>, "Value": <tag-value>}
    tags: dict[str, Tag]
    # list of lowercase transitive tag keys
    transitive_tags: list[str]
    # other stored context variables
    iam_context: dict[str, str | list[str]]


class STSStore(BaseStore):
    # maps access key ids to tagging config for the session they belong to
    sessions: dict[str, SessionConfig] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)
