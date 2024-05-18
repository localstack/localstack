from typing import Dict

from localstack.aws.api.route53 import DelegationSet
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class Route53Store(BaseStore):
    # maps delegation set ID to reusable delegation set details
    reusable_delegation_sets: Dict[str, DelegationSet] = LocalAttribute(default=dict)


route53_stores = AccountRegionBundle("route53", Route53Store)
