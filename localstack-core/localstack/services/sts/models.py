from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


class STSStore(BaseStore):
    # maps access key ids to tags for the session they belong to
    session_tags: dict[str, dict[str, str]] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)
