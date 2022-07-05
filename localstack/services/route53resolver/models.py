from typing import Dict

from localstack.aws.api.route53resolver import FirewallRuleGroup
from localstack.services.generic_proxy import RegionBackend


class Route53ResolverBackend(RegionBackend):
    # maps firewall rule groups set ID to firewall rule groups set details
    firewall_rule_groups: Dict[str, FirewallRuleGroup]

    def __init__(self):
        self.firewall_rule_groups = {}
        self.firewall_domain_lists = {}
        self.firewall_domains = {}
        self.firewall_rules = {}
