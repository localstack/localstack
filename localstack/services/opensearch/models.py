from typing import Dict

from localstack.aws.api.opensearch import DomainStatus
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


class OpenSearchStore(BaseStore):
    # storage for domain resources (access should be protected with the _domain_mutex)
    opensearch_domains: Dict[str, DomainStatus] = LocalAttribute(default=dict)

    # static tagging service instance
    TAGS = CrossRegionAttribute(default=dict)


opensearch_stores = AccountRegionBundle("opensearch", OpenSearchStore)
