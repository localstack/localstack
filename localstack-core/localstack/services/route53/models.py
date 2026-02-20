from localstack.aws.api.route53 import DelegationSet
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute
from localstack.utils.tagging import Tags


class Route53Store(BaseStore):
    # maps delegation set ID to reusable delegation set details
    reusable_delegation_sets: dict[str, DelegationSet] = LocalAttribute(default=dict)
    tags: Tags = LocalAttribute(default=Tags)


route53_stores = AccountRegionBundle("route53", Route53Store, validate=False)
