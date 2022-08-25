from datetime import datetime, timezone

from moto.ec2.models import ec2_backends
from moto.route53resolver.models import Route53ResolverBackend as MotoRoute53ResolverBackend
from moto.route53resolver.models import route53resolver_backends

from localstack.aws.api import RequestContext
from localstack.aws.api.route53resolver import (
    Action,
    AssociateFirewallRuleGroupResponse,
    AssociateResolverQueryLogConfigResponse,
    BlockOverrideDnsType,
    BlockOverrideDomain,
    BlockOverrideTtl,
    BlockResponse,
    CreateFirewallDomainListResponse,
    CreateFirewallRuleGroupResponse,
    CreateFirewallRuleResponse,
    CreateResolverQueryLogConfigResponse,
    CreatorRequestId,
    DeleteFirewallDomainListResponse,
    DeleteFirewallRuleGroupResponse,
    DeleteFirewallRuleResponse,
    DeleteResolverQueryLogConfigResponse,
    DestinationArn,
    DisassociateFirewallRuleGroupResponse,
    DisassociateResolverQueryLogConfigResponse,
    Filters,
    FirewallConfig,
    FirewallDomainList,
    FirewallDomainListMetadata,
    FirewallDomainName,
    FirewallDomains,
    FirewallDomainUpdateOperation,
    FirewallFailOpenStatus,
    FirewallRule,
    FirewallRuleGroup,
    FirewallRuleGroupAssociation,
    FirewallRuleGroupMetadata,
    GetFirewallConfigResponse,
    GetFirewallDomainListResponse,
    GetFirewallRuleGroupAssociationResponse,
    GetFirewallRuleGroupResponse,
    GetResolverQueryLogConfigAssociationResponse,
    GetResolverQueryLogConfigResponse,
    ListDomainMaxResults,
    ListFirewallConfigsMaxResult,
    ListFirewallConfigsResponse,
    ListFirewallDomainListsResponse,
    ListFirewallDomainsResponse,
    ListFirewallRuleGroupsResponse,
    ListFirewallRulesResponse,
    ListResolverQueryLogConfigAssociationsResponse,
    ListResolverQueryLogConfigsResponse,
    MaxResults,
    MutationProtectionStatus,
    Name,
    NextToken,
    Priority,
    ResolverQueryLogConfig,
    ResolverQueryLogConfigAssociation,
    ResolverQueryLogConfigName,
    ResourceId,
    ResourceNotFoundException,
    Route53ResolverApi,
    SortByKey,
    SortOrder,
    TagList,
    UpdateFirewallConfigResponse,
    UpdateFirewallDomainsResponse,
    UpdateFirewallRuleGroupAssociationResponse,
    UpdateFirewallRuleResponse,
    ValidationException,
)
from localstack.services.route53resolver.models import Route53ResolverBackend
from localstack.services.route53resolver.utils import (
    get_resolver_query_log_config_id,
    get_route53_resolver_firewall_domain_list_id,
    get_route53_resolver_firewall_rule_group_association_id,
    get_route53_resolver_firewall_rule_group_id,
    get_route53_resolver_query_log_config_association_id,
    validate_destination_arn,
    validate_mutation_protection,
    validate_priority,
)
from localstack.utils.aws import aws_stack
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.patch import patch


class Route53ResolverProvider(Route53ResolverApi):
    def create_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList = None,
    ) -> CreateFirewallRuleGroupResponse:
        """Create a Firewall Rule Group."""
        region_details = Route53ResolverBackend.get()
        id = get_route53_resolver_firewall_rule_group_id()
        arn = aws_stack.get_route53_resolver_firewall_rule_group_arn(id)
        firewall_rule_group = FirewallRuleGroup(
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
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return CreateFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def delete_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId
    ) -> DeleteFirewallRuleGroupResponse:
        region_details = Route53ResolverBackend.get()
        """Delete a Firewall Rule Group."""
        firewall_rule_group: FirewallRuleGroup = region_details.delete_firewall_rule_group(
            firewall_rule_group_id
        )
        return DeleteFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def get_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId
    ) -> GetFirewallRuleGroupResponse:
        region_details = Route53ResolverBackend.get()
        """Get the details of a Firewall Rule Group."""
        firewall_rule_group: FirewallRuleGroup = region_details.get_firewall_rule_group(
            firewall_rule_group_id
        )
        return GetFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def list_firewall_rule_groups(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallRuleGroupsResponse:
        """List Firewall Rule Groups."""
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
        """Create a Firewall Domain List."""
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
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return CreateFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def delete_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId
    ) -> DeleteFirewallDomainListResponse:
        region_details = Route53ResolverBackend.get()
        """Delete a Firewall Domain List."""
        firewall_domain_list: FirewallDomainList = region_details.delete_firewall_domain_list(
            firewall_domain_list_id
        )
        return DeleteFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def get_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId
    ) -> GetFirewallDomainListResponse:
        region_details = Route53ResolverBackend.get()
        """Get the details of a Firewall Domain List."""
        firewall_domain_list: FirewallDomainList = region_details.get_firewall_domain_list(
            firewall_domain_list_id
        )
        return GetFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def list_firewall_domain_lists(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListFirewallDomainListsResponse:
        """List all Firewall Domain Lists."""
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
        """Update the domains in a Firewall Domain List."""
        region_details = Route53ResolverBackend.get()
        firewall_domain_list: FirewallDomainList = region_details.get_firewall_domain_list(
            firewall_domain_list_id
        )

        firewall_domain_list: FirewallDomainList = region_details.get_firewall_domain_list(
            firewall_domain_list_id
        )
        firewall_domains = region_details.get_firewall_domain(firewall_domain_list_id)

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
        firewall_domain_list["ModificationTime"] = datetime.now(timezone.utc).isoformat()
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
        """List the domains in a DNS Firewall domain list."""
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
        """Create a new firewall rule"""
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
        """Delete a firewall rule"""
        firewall_rule: FirewallRule = region_details.delete_firewall_rule(
            firewall_rule_group_id, firewall_domain_list_id
        )
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
        """List all the firewall rules in a firewall rule group."""
        # TODO: implement priority and action filtering
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
        """Updates a firewall rule"""
        firewall_rule: FirewallRule = region_details.get_firewall_rule(
            firewall_rule_group_id, firewall_domain_list_id
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

    def associate_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        vpc_id: ResourceId,
        priority: Priority,
        name: Name,
        mutation_protection: MutationProtectionStatus = None,
        tags: TagList = None,
    ) -> AssociateFirewallRuleGroupResponse:
        """Associate a firewall rule group with a VPC."""
        region_details = Route53ResolverBackend.get()
        validate_priority(priority=priority)
        validate_mutation_protection(mutation_protection=mutation_protection)

        for (
            firewall_rule_group_association
        ) in region_details.firewall_rule_group_associations.values():
            if (
                firewall_rule_group_association.get("VpcId") == vpc_id
                and firewall_rule_group_association.get("FirewallRuleGroupId")
                == firewall_rule_group_id
            ):
                raise ValidationException(
                    f"[RSLVR-02302] This DNS Firewall rule group can't be associated to a VPC: '{vpc_id}'. It is already associated to VPC '{firewall_rule_group_id}'. Try again with another VPC or DNS Firewall rule group. Trace Id: '{aws_stack.get_trace_id()}'"
                )

        id = get_route53_resolver_firewall_rule_group_association_id()
        arn = aws_stack.get_route53_resolver_firewall_rule_group_associations_arn(id)

        firewall_rule_group_association = FirewallRuleGroupAssociation(
            Id=id,
            Arn=arn,
            FirewallRuleGroupId=firewall_rule_group_id,
            VpcId=vpc_id,
            Name=name,
            Priority=priority,
            MutationProtection=mutation_protection or "DISABLED",
            Status="COMPLETE",
            StatusMessage="Creating Firewall Rule Group Association",
            CreatorRequestId=creator_request_id,
            CreationTime=datetime.now(timezone.utc).isoformat(),
            ModificationTime=datetime.now(timezone.utc).isoformat(),
        )
        region_details.firewall_rule_group_associations[id] = firewall_rule_group_association
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return AssociateFirewallRuleGroupResponse(
            FirewallRuleGroupAssociation=firewall_rule_group_association
        )

    def disassociate_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId
    ) -> DisassociateFirewallRuleGroupResponse:
        region_details = Route53ResolverBackend.get()
        """Disassociate a DNS Firewall rule group from a VPC."""
        firewall_rule_group_association: FirewallRuleGroupAssociation = (
            region_details.delete_firewall_rule_group_association(
                firewall_rule_group_association_id
            )
        )
        return DisassociateFirewallRuleGroupResponse(
            FirewallRuleGroupAssociation=firewall_rule_group_association
        )

    def get_firewall_rule_group_association(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId
    ) -> GetFirewallRuleGroupAssociationResponse:
        region_details = Route53ResolverBackend.get()
        """Returns the Firewall Rule Group Association that you specified."""
        firewall_rule_group_association: FirewallRuleGroupAssociation = (
            region_details.get_firewall_rule_group_association(firewall_rule_group_association_id)
        )
        return GetFirewallRuleGroupAssociationResponse(
            FirewallRuleGroupAssociation=firewall_rule_group_association
        )

    def update_firewall_rule_group_association(
        self,
        context: RequestContext,
        firewall_rule_group_association_id: ResourceId,
        priority: Priority = None,
        mutation_protection: MutationProtectionStatus = None,
        name: Name = None,
    ) -> UpdateFirewallRuleGroupAssociationResponse:
        region_details = Route53ResolverBackend.get()
        """Updates the specified Firewall Rule Group Association."""
        validate_priority(priority=priority)
        validate_mutation_protection(mutation_protection=mutation_protection)

        firewall_rule_group_association: FirewallRuleGroupAssociation = (
            region_details.get_firewall_rule_group_association(firewall_rule_group_association_id)
        )

        if priority:
            firewall_rule_group_association["Priority"] = priority
        if mutation_protection:
            firewall_rule_group_association["MutationProtection"] = mutation_protection
        if name:
            firewall_rule_group_association["Name"] = name

        return UpdateFirewallRuleGroupAssociationResponse(
            FirewallRuleGroupAssociation=firewall_rule_group_association
        )

    def create_resolver_query_log_config(
        self,
        context: RequestContext,
        name: ResolverQueryLogConfigName,
        destination_arn: DestinationArn,
        creator_request_id: CreatorRequestId,
        tags: TagList = None,
    ) -> CreateResolverQueryLogConfigResponse:
        validate_destination_arn(destination_arn)
        region_details = Route53ResolverBackend.get()
        id = get_resolver_query_log_config_id()
        arn = aws_stack.get_resolver_query_log_config_arn(id)
        resolver_query_log_config: ResolverQueryLogConfig = ResolverQueryLogConfig(
            Id=id,
            Arn=arn,
            Name=name,
            AssociationCount=0,
            Status="CREATED",
            OwnerId=context.account_id,
            ShareStatus="NOT_SHARED",
            DestinationArn=destination_arn,
            CreatorRequestId=creator_request_id,
            CreationTime=datetime.now(timezone.utc).isoformat(),
        )
        region_details.resolver_query_log_configs[id] = resolver_query_log_config
        route53resolver_backends[context.region].tagger.tag_resource(arn, tags or [])
        return CreateResolverQueryLogConfigResponse(
            ResolverQueryLogConfig=resolver_query_log_config
        )

    def get_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId
    ) -> GetResolverQueryLogConfigResponse:
        region_details = Route53ResolverBackend.get()
        resolver_query_log_config: ResolverQueryLogConfig = (
            region_details.get_resolver_query_log_config(resolver_query_log_config_id)
        )
        return GetResolverQueryLogConfigResponse(ResolverQueryLogConfig=resolver_query_log_config)

    def delete_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId
    ) -> DeleteResolverQueryLogConfigResponse:
        region_details = Route53ResolverBackend.get()
        resolver_query_log_config: ResolverQueryLogConfig = (
            region_details.delete_resolver_query_log_config(resolver_query_log_config_id)
        )
        return DeleteResolverQueryLogConfigResponse(
            ResolverQueryLogConfig=resolver_query_log_config
        )

    def list_resolver_query_log_configs(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
        sort_by: SortByKey = None,
        sort_order: SortOrder = None,
    ) -> ListResolverQueryLogConfigsResponse:
        region_details = Route53ResolverBackend.get()
        resolver_query_log_configs = []
        for resolver_query_log_config in region_details.resolver_query_log_configs.values():
            resolver_query_log_configs.append(ResolverQueryLogConfig(resolver_query_log_config))
        return ListResolverQueryLogConfigsResponse(
            ResolverQueryLogConfigs=resolver_query_log_configs,
            TotalCount=len(resolver_query_log_configs),
        )

    def associate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
    ) -> AssociateResolverQueryLogConfigResponse:

        region_details = Route53ResolverBackend.get()
        id = get_route53_resolver_query_log_config_association_id()

        resolver_query_log_config_association: ResolverQueryLogConfigAssociation = (
            ResolverQueryLogConfigAssociation(
                Id=id,
                ResolverQueryLogConfigId=resolver_query_log_config_id,
                ResourceId=resource_id,
                Status="ACTIVE",
                Error="NONE",
                ErrorMessage="",
                CreationTime=datetime.now(timezone.utc).isoformat(),
            )
        )

        region_details.resolver_query_log_config_associations[
            id
        ] = resolver_query_log_config_association

        return AssociateResolverQueryLogConfigResponse(
            ResolverQueryLogConfigAssociation=resolver_query_log_config_association
        )

    def disassociate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
    ) -> DisassociateResolverQueryLogConfigResponse:
        region_details = Route53ResolverBackend.get()
        resolver_query_log_config_association = (
            region_details.delete_resolver_query_log_config_associations(
                resolver_query_log_config_id, resource_id
            )
        )

        return DisassociateResolverQueryLogConfigResponse(
            ResolverQueryLogConfigAssociation=resolver_query_log_config_association
        )

    def get_resolver_query_log_config_association(
        self, context: RequestContext, resolver_query_log_config_association_id: ResourceId
    ) -> GetResolverQueryLogConfigAssociationResponse:
        region_details = Route53ResolverBackend.get()
        resolver_query_log_config_association: ResolverQueryLogConfigAssociation = (
            region_details.get_resolver_query_log_config_associations(
                resolver_query_log_config_association_id
            )
        )
        return GetResolverQueryLogConfigAssociationResponse(
            ResolverQueryLogConfigAssociation=resolver_query_log_config_association
        )

    def list_resolver_query_log_config_associations(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        filters: Filters = None,
        sort_by: SortByKey = None,
        sort_order: SortOrder = None,
    ) -> ListResolverQueryLogConfigAssociationsResponse:
        region_details = Route53ResolverBackend.get()

        resolver_query_log_config_associations = []
        for (
            resolver_query_log_config_association
        ) in region_details.resolver_query_log_config_associations.values():
            resolver_query_log_config_associations.append(
                ResolverQueryLogConfigAssociation(resolver_query_log_config_association)
            )
        return ListResolverQueryLogConfigAssociationsResponse(
            TotalCount=len(resolver_query_log_config_associations),
            ResolverQueryLogConfigAssociations=resolver_query_log_config_associations,
        )

    def get_firewall_config(
        self, context: RequestContext, resource_id: ResourceId
    ) -> GetFirewallConfigResponse:
        region_details = Route53ResolverBackend.get()
        firewall_config = region_details.get_or_create_firewall_config(
            resource_id, context.region, context.account_id
        )
        return GetFirewallConfigResponse(FirewallConfig=firewall_config)

    def list_firewall_configs(
        self,
        context: RequestContext,
        max_results: ListFirewallConfigsMaxResult = None,
        next_token: NextToken = None,
    ) -> ListFirewallConfigsResponse:
        region_details = Route53ResolverBackend.get()
        firewall_configs = []
        backend = ec2_backends[context.region]
        for vpc in backend.vpcs:
            if vpc not in region_details.firewall_configs:
                region_details.get_or_create_firewall_config(
                    vpc, context.region, context.account_id
                )
        for firewall_config in region_details.firewall_configs.values():
            firewall_configs.append(select_from_typed_dict(FirewallConfig, firewall_config))
        return ListFirewallConfigsResponse(FirewallConfigs=firewall_configs)

    def update_firewall_config(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        firewall_fail_open: FirewallFailOpenStatus,
    ) -> UpdateFirewallConfigResponse:
        region_details = Route53ResolverBackend.get()
        backend = ec2_backends[context.region]
        for resource_id in backend.vpcs:
            if resource_id not in region_details.firewall_configs:
                firewall_config = region_details.get_or_create_firewall_config(
                    resource_id, context.region, context.account_id
                )
                firewall_config["FirewallFailOpen"] = firewall_fail_open
            else:
                firewall_config = region_details.firewall_configs[resource_id]
                firewall_config["FirewallFailOpen"] = firewall_fail_open
        return UpdateFirewallConfigResponse(FirewallConfig=firewall_config)


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
    for firewall_rule_group_association in region_details.firewall_rule_group_associations.values():
        if firewall_rule_group_association.get("Arn") == resource_arn:
            return
    for resolver_query_log_config in region_details.resolver_query_log_configs.values():
        if resolver_query_log_config.get("Arn") == resource_arn:
            return
    fn(self, resource_arn)
