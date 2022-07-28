from typing import Dict

from localstack.aws.api.route53 import DelegationSet
from localstack.services.generic_proxy import RegionBackend


class Route53Backend(RegionBackend):
    # maps delegation set ID to reusable delegation set details
    reusable_delegation_sets: Dict[str, DelegationSet]

    def __init__(self):
        self.reusable_delegation_sets = {}
