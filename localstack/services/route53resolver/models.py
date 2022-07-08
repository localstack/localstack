from typing import Dict

from localstack.aws.api.route53resolver import FirewallRuleGroup, ResourceNotFoundException
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.aws import aws_stack


class Route53ResolverBackend(RegionBackend):
    # maps firewall rule groups set ID to firewall rule groups set details
    firewall_rule_groups: Dict[str, FirewallRuleGroup]

    def __init__(self):
        self.firewall_rule_groups = {}
        self.firewall_domain_lists = {}
        self.firewall_domains = {}
        self.firewall_rules = {}
        self.firewall_rule_group_associations = {}

    def get_firewall_rule_group(self, id):
        firewall_rule_group = self.firewall_rule_groups.get(id)
        if not firewall_rule_group:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return firewall_rule_group

    def delete_firewall_rule_group(self, id):
        # if firewall_rule_groups doesn't exist it will throw an error
        firewall_rule_group = self.get_firewall_rule_group(id)
        self.firewall_rule_groups.pop(id)
        return firewall_rule_group

    def get_firewall_rule_group_association(self, id):
        firewall_rule_group_association = self.firewall_rule_group_associations.get(id)
        if not firewall_rule_group_association:
            raise ResourceNotFoundException(
                f"[RSLVR-02025] Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return self.firewall_rule_group_associations.get(id)

    def delete_firewall_rule_group_association(self, id):
        # if firewall_rule_group_associations doesn't exist it will throw an error
        firewall_rule_group_associations = self.get_firewall_rule_group_association(id)
        self.firewall_rule_group_associations.pop(id)
        return firewall_rule_group_associations

    def get_firewall_domain(self, id):
        firewall_domain = self.firewall_domains.get(id)
        if not firewall_domain:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return firewall_domain

    def delete_firewall_domain(self, id):
        # if firewall_domains doesn't exist it will throw an error
        firewall_domain = self.get_firewall_domain(id)
        self.firewall_domains.pop(id)
        return firewall_domain

    def get_firewall_domain_lists(self, id):
        firewall_domain_list = self.firewall_domain_lists.get(id)
        if not firewall_domain_list:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return firewall_domain_list

    def delete_firewall_domain_list(self, id):
        # if firewall_domain_lists doesn't exist it will throw an error
        firewall_domain_list = self.get_firewall_domain_lists(id)
        self.firewall_domain_lists.pop(id)
        return firewall_domain_list

    def get_firewall_rule(self, firewall_rule_group_id, firewall_domain_list_id):
        firewall_rule = self.firewall_rules.get(firewall_rule_group_id, {}).get(
            firewall_domain_list_id
        )
        if not firewall_rule:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return firewall_rule

    def delete_firewall_rule(self, firewall_rule_group_id, firewall_domain_list_id):
        # if firewall_rules doesn't exist it will throw an error
        firewall_rule = self.get_firewall_rule(firewall_rule_group_id, firewall_domain_list_id)
        self.firewall_rules.get(firewall_rule_group_id, {}).pop(firewall_domain_list_id)
        return firewall_rule
