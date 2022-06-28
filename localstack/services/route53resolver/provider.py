from datetime import datetime, timezone
from typing import Optional

from moto.route53resolver.models import Route53ResolverBackend as MotoRoute53ResolverBackend
from moto.route53resolver.models import route53resolver_backends as moto_route53resolver_backends

from localstack.aws.api import RequestContext
from localstack.aws.api.route53resolver import (
    CreateFirewallRuleGroupResponse,
    CreatorRequestId,
    DeleteFirewallRuleGroupResponse,
    FirewallRuleGroup,
    FirewallRuleGroupMetadataList,
    GetFirewallRuleGroupResponse,
    ListFirewallRuleGroupsResponse,
    MaxResults,
    Name,
    NextToken,
    ResourceId,
    ResourceNotFoundException,
    Route53ResolverApi,
    TagList,
)
from localstack.services.route53resolver.models import Route53ResolverBackend
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch
from localstack.utils.strings import get_random_hex


def get_route53_resolver_firewall_rule_group_id():
    return f"rslvr-frg-{get_random_hex(17)}"


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
        return DeleteFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def list_firewall_rule_groups(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallRuleGroupsResponse:
        region_details = Route53ResolverBackend.get()
        firewall_group_rules: Optional[
            FirewallRuleGroupMetadataList
        ] = region_details.firewall_rule_groups.values()
        return ListFirewallRuleGroupsResponse(FirewallRuleGroups=firewall_group_rules)


@patch(MotoRoute53ResolverBackend._matched_arn)
def Route53ResolverBackend_matched_arn(fn, self, resource_arn):
    """Given ARN, raise exception if there is no corresponding resource."""
    region_details = Route53ResolverBackend.get()
    for firewall_rule_group in region_details.firewall_rule_groups.values():
        if firewall_rule_group.get("Arn") == resource_arn:
            return
    fn(self, resource_arn)
