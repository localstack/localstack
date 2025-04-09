from typing import TypedDict

from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


class SessionTaggingConfig(TypedDict):
    tags: dict[str, str]
    transitive_tags: list[str]


class STSStore(BaseStore):
    # maps access key ids to tags for the session they belong to
    session_tags: dict[str, SessionTaggingConfig] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)
