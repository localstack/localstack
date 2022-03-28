from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

from localstack.aws.api.route53 import VPC, ChangeStatus, DelegationSet, ResourceId
from localstack.services.generic_proxy import RegionBackend


@dataclass
class HostedZoneAssociation:
    id: str
    hosted_zone_id: ResourceId
    vpc: VPC
    status: ChangeStatus
    submitted_at: datetime
    comment: str = None


class Route53Backend(RegionBackend):
    # maps zone ID to list of association details
    vpc_hosted_zone_associations: Dict[str, List[HostedZoneAssociation]]
    # maps delegation set ID to reusable delegation set details
    reusable_delegation_sets: Dict[str, DelegationSet]

    def __init__(self):
        self.vpc_hosted_zone_associations = {}
        self.reusable_delegation_sets = {}
