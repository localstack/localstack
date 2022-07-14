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


## helper functions for the backend
def get_firewall_rule_group(id):
    """returns firewall rule group with the given id if it exists"""
    region_details = Route53ResolverBackend.get()
    firewall_rule_group = region_details.firewall_rule_groups.get(id)
    if not firewall_rule_group:
        raise ResourceNotFoundException(
            f"Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
        )
    return firewall_rule_group


def delete_firewall_rule_group(id):
    """deletes the firewall rule group with the given id"""
    # if firewall_rule_groups doesn't exist it will throw an error
    region_details = Route53ResolverBackend.get()
    firewall_rule_group = get_firewall_rule_group(id)
    region_details.firewall_rule_groups.pop(id)
    return firewall_rule_group


def get_firewall_rule_group_association(id):
    """returns firewall rule group association with the given id if it exists"""
    region_details = Route53ResolverBackend.get()
    firewall_rule_group_association = region_details.firewall_rule_group_associations.get(id)
    if not firewall_rule_group_association:
        raise ResourceNotFoundException(
            f"[RSLVR-02025] Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
        )
    return region_details.firewall_rule_group_associations.get(id)


def delete_firewall_rule_group_association(id):
    """deletes the firewall rule group association with the given id"""
    # if firewall_rule_group_associations doesn't exist it will throw an error
    region_details = Route53ResolverBackend.get()
    firewall_rule_group_associations = get_firewall_rule_group_association(id)
    region_details.firewall_rule_group_associations.pop(id)
    return firewall_rule_group_associations


def get_firewall_domain(id):
    """returns firewall domain with the given id if it exists"""
    # firewall_domain can return none
    region_details = Route53ResolverBackend.get()
    firewall_domain = region_details.firewall_domains.get(id)
    return firewall_domain


def get_firewall_domain_list(id):
    """returns firewall domain list with the given id if it exists"""
    region_details = Route53ResolverBackend.get()
    firewall_domain_list = region_details.firewall_domain_lists.get(id)
    if not firewall_domain_list:
        raise ResourceNotFoundException(
            f"Can't find the resource with ID '{id}'. Trace Id: '{aws_stack.get_trace_id()}'"
        )
    return firewall_domain_list


def delete_firewall_domain_list(id):
    """deletes the firewall domain list with the given id"""
    # if firewall_domain_lists doesn't exist it will throw an error
    region_details = Route53ResolverBackend.get()
    firewall_domain_list = get_firewall_domain_list(id)
    region_details.firewall_domain_lists.pop(id)
    return firewall_domain_list


def get_firewall_rule(firewall_rule_group_id, firewall_domain_list_id):
    """returns firewall rule with the given id if it exists"""
    region_details = Route53ResolverBackend.get()
    firewall_rule = region_details.firewall_rules.get(firewall_rule_group_id, {}).get(
        firewall_domain_list_id
    )
    if not firewall_rule:
        raise ResourceNotFoundException(
            f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
        )
    return firewall_rule


def delete_firewall_rule(firewall_rule_group_id, firewall_domain_list_id):
    """deletes the firewall rule with the given id"""
    # if firewall_rules doesn't exist it will throw an error
    region_details = Route53ResolverBackend.get()
    firewall_rule = get_firewall_rule(firewall_rule_group_id, firewall_domain_list_id)
    region_details.firewall_rules.get(firewall_rule_group_id, {}).pop(firewall_domain_list_id)
    return firewall_rule
