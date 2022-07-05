from datetime import datetime, timezone
from typing import Optional

from moto.route53resolver.models import Route53ResolverBackend as MotoRoute53ResolverBackend
from moto.route53resolver.models import route53resolver_backends as moto_route53resolver_backends

from localstack.aws.api import RequestContext
from localstack.aws.api.route53resolver import (
    Action,
    BlockOverrideDnsType,
    BlockOverrideDomain,
    BlockOverrideTtl,
    BlockResponse,
    CreateFirewallDomainListResponse,
    CreateFirewallRuleGroupResponse,
    CreateFirewallRuleResponse,
    CreatorRequestId,
    DeleteFirewallDomainListResponse,
    DeleteFirewallRuleGroupResponse,
    DeleteFirewallRuleResponse,
    FirewallDomainList,
    FirewallDomainListMetadata,
    FirewallDomainName,
    FirewallDomains,
    FirewallDomainUpdateOperation,
    FirewallRule,
    FirewallRuleGroup,
    FirewallRuleGroupMetadata,
    GetFirewallDomainListResponse,
    GetFirewallRuleGroupResponse,
    ListDomainMaxResults,
    ListFirewallDomainListsResponse,
    ListFirewallDomainsResponse,
    ListFirewallRuleGroupsResponse,
    ListFirewallRulesResponse,
    MaxResults,
    Name,
    NextToken,
    Priority,
    ResourceId,
    ResourceNotFoundException,
    Route53ResolverApi,
    TagList,
    UpdateFirewallDomainsResponse,
    UpdateFirewallRuleResponse,
    ValidationException,
)
from localstack.services.route53resolver.models import Route53ResolverBackend
from localstack.utils.aws import aws_stack
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.patch import patch
from localstack.utils.strings import get_random_hex


def get_route53_resolver_firewall_rule_group_id():
    return f"rslvr-frg-{get_random_hex(17)}"


def get_route53_resolver_firewall_domain_list_id():
    return f"rslvr-fdl-{get_random_hex(17)}"


class Route53ResolverProvider(Route53ResolverApi):
    def create_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList = None,
    ) -> CreateFirewallRuleGroupResponse:
        region_details = Route53ResolverBackend.get()
        id = get_route53_resolver_firewall_rule_group_id()
        arn = aws_stack.get_route53_resolver_firewall_rule_group_arn(id)
        firewall_rule_group: Optional[FirewallRuleGroup] = FirewallRuleGroup(
            Id=id,
            Arn=arn,
            Name=name,
            RuleCount=0,
            Status="COMPLETE",
            OwnerId=context.account_id,
            ShareStatus="NOT_SHARED",
            StatusMessage="Created Firewall Rule Group",
            CreatorRequestId=creator_request_id,
            CreationTime=datetime.now(timezone.utc).isoformat(),
            ModificationTime=datetime.now(timezone.utc).isoformat(),
        )
        region_details.firewall_rule_groups[id] = firewall_rule_group
        moto_route53resolver_backends[context.region].tagger.tag_resource(arn, tags or [])
        return CreateFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def delete_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId
    ) -> DeleteFirewallRuleGroupResponse:
        region_details = Route53ResolverBackend.get()
        if not region_details.firewall_rule_groups.get(firewall_rule_group_id):
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '1-{get_random_hex(8)}-{get_random_hex(24)}'"
            )
        firewall_rule_group: Optional[FirewallRuleGroup] = region_details.firewall_rule_groups.pop(
            firewall_rule_group_id
        )
        return DeleteFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def get_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId
    ) -> GetFirewallRuleGroupResponse:
        region_details = Route53ResolverBackend.get()
        firewall_rule_group: Optional[FirewallRuleGroup] = region_details.firewall_rule_groups.get(
            firewall_rule_group_id
        )
        if not firewall_rule_group:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '1-{get_random_hex(8)}-{get_random_hex(24)}'"
            )
        return GetFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def list_firewall_rule_groups(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallRuleGroupsResponse:
        region_details = Route53ResolverBackend.get()
        firewall_rule_groups = []
        for firewall_rule_group in region_details.firewall_rule_groups.values():
            firewall_rule_groups.append(
                select_from_typed_dict(FirewallRuleGroupMetadata, firewall_rule_group)
            )
        return ListFirewallRuleGroupsResponse(FirewallRuleGroups=firewall_rule_groups)

    def create_firewall_domain_list(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList = None,
    ) -> CreateFirewallDomainListResponse:
        region_details = Route53ResolverBackend.get()
        id = get_route53_resolver_firewall_domain_list_id()
        arn = aws_stack.get_route53_resolver_firewall_domain_list_arn(id)
        firewall_domain_list = FirewallDomainList(
            Id=id,
            Arn=arn,
            Name=name,
            DomainCount=0,
            Status="COMPLETE",
            StatusMessage="Created Firewall Domain List",
            ManagedOwnerName=context.account_id,
            CreatorRequestId=creator_request_id,
            CreationTime=datetime.now(timezone.utc).isoformat(),
            ModificationTime=datetime.now(timezone.utc).isoformat(),
        )
        region_details.firewall_domain_lists[id] = firewall_domain_list
        moto_route53resolver_backends[context.region].tagger.tag_resource(arn, tags or [])
        return CreateFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def delete_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId
    ) -> DeleteFirewallDomainListResponse:
        region_details = Route53ResolverBackend.get()
        if not region_details.firewall_domain_lists.get(firewall_domain_list_id):
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_domain_list_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        firewall_domain_list: Optional[
            FirewallDomainList
        ] = region_details.firewall_domain_lists.pop(firewall_domain_list_id)
        return DeleteFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def get_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId
    ) -> GetFirewallDomainListResponse:
        region_details = Route53ResolverBackend.get()
        firewall_domain_list: Optional[
            FirewallDomainList
        ] = region_details.firewall_domain_lists.get(firewall_domain_list_id)
        if not firewall_domain_list:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_domain_list_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return GetFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def list_firewall_domain_lists(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallDomainListsResponse:
        region_details = Route53ResolverBackend.get()
        firewall_domain_lists = []
        for firewall_domain_list in region_details.firewall_domain_lists.values():
            firewall_domain_list.append(
                select_from_typed_dict(FirewallDomainListMetadata, firewall_domain_list)
            )
        return ListFirewallDomainListsResponse(FirewallDomainLists=firewall_domain_lists)

    def update_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        operation: FirewallDomainUpdateOperation,
        domains: FirewallDomains,
    ) -> UpdateFirewallDomainsResponse:
        region_details = Route53ResolverBackend.get()
        firewall_domain_list: FirewallDomainList = region_details.firewall_domain_lists.get(
            firewall_domain_list_id
        )
        if not firewall_domain_list:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_domain_list_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        firewall_domains = region_details.firewall_domains.get(firewall_domain_list_id)
        if operation == FirewallDomainUpdateOperation.ADD:
            if not firewall_domains:
                region_details.firewall_domains[firewall_domain_list_id] = domains
            else:
                region_details.firewall_domains[firewall_domain_list_id].append(domains)
        if operation == FirewallDomainUpdateOperation.REMOVE:
            if firewall_domains:
                for domain in domains:
                    if domain in firewall_domains:
                        firewall_domains.remove(domain)
                    else:
                        raise ValidationException(
                            f"[RSLVR-02502] The following domains don't exist in the DNS Firewall domain list '{firewall_domain_list_id}'. You can't delete a domain that isn't in a domain list. Example unknown domain: '{domain}'. Trace Id: '{aws_stack.get_trace_id()}'"
                        )
        if operation == FirewallDomainUpdateOperation.REPLACE:
            region_details.firewall_domains[firewall_domain_list_id] = domains
        firewall_domain_list["StatusMessage"] = "Finished domain list update"
        return UpdateFirewallDomainsResponse(
            Id=firewall_domain_list.get("Id"),
            Name=firewall_domain_list.get("Name"),
            Status=firewall_domain_list.get("Status"),
            StatusMessage=firewall_domain_list.get("StatusMessage"),
        )

    def list_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        max_results: ListDomainMaxResults = None,
        next_token: NextToken = None,
    ) -> ListFirewallDomainsResponse:
        region_details = Route53ResolverBackend.get()
        firewall_domains: FirewallDomains[FirewallDomainName] = []
        if region_details.firewall_domains.get(firewall_domain_list_id):
            for firewall_domain in region_details.firewall_domains.get(firewall_domain_list_id):
                firewall_domains.append(FirewallDomainName(firewall_domain))
        return ListFirewallDomainsResponse(Domains=firewall_domains)

    def create_firewall_rule(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId,
        priority: Priority,
        action: Action,
        name: Name,
        block_response: BlockResponse = None,
        block_override_domain: BlockOverrideDomain = None,
        block_override_dns_type: BlockOverrideDnsType = None,
        block_override_ttl: BlockOverrideTtl = None,
    ) -> CreateFirewallRuleResponse:
        region_details = Route53ResolverBackend.get()
        firewall_rule = FirewallRule(
            FirewallRuleGroupId=firewall_rule_group_id,
            FirewallDomainListId=firewall_domain_list_id,
            Name=name,
            Priority=priority,
            Action=action,
            BlockResponse=block_response,
            BlockOverrideDomain=block_override_domain,
            BlockOverrideDnsType=block_override_dns_type,
            BlockOverrideTtl=block_override_ttl,
            CreatorRequestId=creator_request_id,
            CreationTime=datetime.now(timezone.utc).isoformat(),
            ModificationTime=datetime.now(timezone.utc).isoformat(),
        )
        if region_details.firewall_rules.get(firewall_rule_group_id):
            region_details.firewall_rules[firewall_rule_group_id][
                firewall_domain_list_id
            ] = firewall_rule
        else:
            region_details.firewall_rules[firewall_rule_group_id] = {}
            region_details.firewall_rules[firewall_rule_group_id][
                firewall_domain_list_id
            ] = firewall_rule
        return CreateFirewallRuleResponse(FirewallRule=firewall_rule)

    def delete_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId,
    ) -> DeleteFirewallRuleResponse:
        region_details = Route53ResolverBackend.get()
        if not region_details.firewall_rules.get(firewall_rule_group_id, {}).get(
            firewall_domain_list_id
        ):
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        firewall_rule: FirewallRule = region_details.firewall_rules.get(
            firewall_rule_group_id, {}
        ).pop(firewall_domain_list_id)
        return DeleteFirewallRuleResponse(
            FirewallRule=firewall_rule,
        )

    def list_firewall_rules(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        priority: Priority = None,
        action: Action = None,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListFirewallRulesResponse:
        region_details = Route53ResolverBackend.get()
        firewall_rules = []
        for firewall_rule in region_details.firewall_rules.get(firewall_rule_group_id, {}).values():
            firewall_rules.append(FirewallRule(firewall_rule))
        if len(firewall_rules) == 0:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        return ListFirewallRulesResponse(
            FirewallRules=firewall_rules,
        )

    def update_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId,
        priority: Priority = None,
        action: Action = None,
        block_response: BlockResponse = None,
        block_override_domain: BlockOverrideDomain = None,
        block_override_dns_type: BlockOverrideDnsType = None,
        block_override_ttl: BlockOverrideTtl = None,
        name: Name = None,
    ) -> UpdateFirewallRuleResponse:
        region_details = Route53ResolverBackend.get()
        firewall_rule: FirewallRule = region_details.firewall_rules.get(
            firewall_rule_group_id, {}
        ).get(firewall_domain_list_id)
        if not firewall_rule:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
        if priority:
            firewall_rule["Priority"] = priority
        if action:
            firewall_rule["Action"] = action
        if block_response:
            firewall_rule["BlockResponse"] = block_response
        if block_override_domain:
            firewall_rule["BlockOverrideDomain"] = block_override_domain
        if block_override_dns_type:
            firewall_rule["BlockOverrideDnsType"] = block_override_dns_type
        if block_override_ttl:
            firewall_rule["BlockOverrideTtl"] = block_override_ttl
        if name:
            firewall_rule["Name"] = name
        return UpdateFirewallRuleResponse(
            FirewallRule=firewall_rule,
        )


@patch(MotoRoute53ResolverBackend._matched_arn)
def Route53ResolverBackend_matched_arn(fn, self, resource_arn):
    """Given ARN, raise exception if there is no corresponding resource."""
    region_details = Route53ResolverBackend.get()
    for firewall_rule_group in region_details.firewall_rule_groups.values():
        if firewall_rule_group.get("Arn") == resource_arn:
            return
    for firewall_domain_list in region_details.firewall_domain_lists.values():
        if firewall_domain_list.get("Arn") == resource_arn:
            return
    fn(self, resource_arn)
