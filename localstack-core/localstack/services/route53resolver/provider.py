from datetime import datetime, timezone

from moto.route53resolver.models import Route53ResolverBackend as MotoRoute53ResolverBackend
from moto.route53resolver.models import route53resolver_backends

import localstack.services.route53resolver.utils
from localstack.aws.api import RequestContext
from localstack.aws.api.route53resolver import (
    Action,
    AssociateFirewallRuleGroupResponse,
    AssociateResolverQueryLogConfigResponse,
    BlockOverrideDnsType,
    BlockOverrideDomain,
    BlockOverrideTtl,
    BlockResponse,
    ConfidenceThreshold,
    CreateFirewallDomainListResponse,
    CreateFirewallRuleGroupResponse,
    CreateFirewallRuleResponse,
    CreateResolverEndpointResponse,
    CreateResolverQueryLogConfigResponse,
    CreatorRequestId,
    DeleteFirewallDomainListResponse,
    DeleteFirewallRuleGroupResponse,
    DeleteFirewallRuleResponse,
    DeleteResolverQueryLogConfigResponse,
    DestinationArn,
    DisassociateFirewallRuleGroupResponse,
    DisassociateResolverQueryLogConfigResponse,
    DnsThreatProtection,
    Filters,
    FirewallConfig,
    FirewallDomainList,
    FirewallDomainListMetadata,
    FirewallDomainName,
    FirewallDomainRedirectionAction,
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
    InvalidParameterException,
    InvalidRequestException,
    IpAddressesRequest,
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
    OutpostArn,
    OutpostInstanceType,
    Priority,
    ProtocolList,
    Qtype,
    ResolverEndpointDirection,
    ResolverEndpointType,
    ResolverQueryLogConfig,
    ResolverQueryLogConfigAssociation,
    ResolverQueryLogConfigName,
    ResolverQueryLogConfigStatus,
    ResourceId,
    ResourceNotFoundException,
    Route53ResolverApi,
    SecurityGroupIds,
    SortByKey,
    SortOrder,
    TagList,
    UpdateFirewallConfigResponse,
    UpdateFirewallDomainsResponse,
    UpdateFirewallRuleGroupAssociationResponse,
    UpdateFirewallRuleResponse,
    ValidationException,
)
from localstack.services.ec2.models import get_ec2_backend
from localstack.services.moto import call_moto
from localstack.services.route53resolver.models import Route53ResolverStore, route53resolver_stores
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
from localstack.utils.aws import arns
from localstack.utils.aws.arns import extract_account_id_from_arn, extract_region_from_arn
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.patch import patch


class Route53ResolverProvider(Route53ResolverApi):
    @staticmethod
    def get_store(account_id: str, region: str) -> Route53ResolverStore:
        return route53resolver_stores[account_id][region]

    def create_firewall_rule_group(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        name: Name,
        tags: TagList = None,
        **kwargs,
    ) -> CreateFirewallRuleGroupResponse:
        """Create a Firewall Rule Group."""
        store = self.get_store(context.account_id, context.region)
        firewall_rule_group_id = get_route53_resolver_firewall_rule_group_id()
        arn = arns.route53_resolver_firewall_rule_group_arn(
            firewall_rule_group_id, context.account_id, context.region
        )
        firewall_rule_group = FirewallRuleGroup(
            Id=firewall_rule_group_id,
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
        store.firewall_rule_groups[firewall_rule_group_id] = firewall_rule_group
        store.firewall_rules[firewall_rule_group_id] = {}
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return CreateFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def delete_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId, **kwargs
    ) -> DeleteFirewallRuleGroupResponse:
        """Delete a Firewall Rule Group."""
        store = self.get_store(context.account_id, context.region)
        firewall_rule_group: FirewallRuleGroup = store.delete_firewall_rule_group(
            firewall_rule_group_id
        )
        return DeleteFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def get_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_id: ResourceId, **kwargs
    ) -> GetFirewallRuleGroupResponse:
        """Get the details of a Firewall Rule Group."""
        store = self.get_store(context.account_id, context.region)
        firewall_rule_group: FirewallRuleGroup = store.get_firewall_rule_group(
            firewall_rule_group_id
        )
        return GetFirewallRuleGroupResponse(FirewallRuleGroup=firewall_rule_group)

    def list_firewall_rule_groups(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListFirewallRuleGroupsResponse:
        """List Firewall Rule Groups."""
        store = self.get_store(context.account_id, context.region)
        firewall_rule_groups = []
        for firewall_rule_group in store.firewall_rule_groups.values():
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
        **kwargs,
    ) -> CreateFirewallDomainListResponse:
        """Create a Firewall Domain List."""
        store = self.get_store(context.account_id, context.region)
        id = get_route53_resolver_firewall_domain_list_id()
        arn = arns.route53_resolver_firewall_domain_list_arn(id, context.account_id, context.region)
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
        store.firewall_domain_lists[id] = firewall_domain_list
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return CreateFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def delete_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId, **kwargs
    ) -> DeleteFirewallDomainListResponse:
        """Delete a Firewall Domain List."""
        store = self.get_store(context.account_id, context.region)
        firewall_domain_list: FirewallDomainList = store.delete_firewall_domain_list(
            firewall_domain_list_id
        )
        return DeleteFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def get_firewall_domain_list(
        self, context: RequestContext, firewall_domain_list_id: ResourceId, **kwargs
    ) -> GetFirewallDomainListResponse:
        """Get the details of a Firewall Domain List."""
        store = self.get_store(context.account_id, context.region)
        firewall_domain_list: FirewallDomainList = store.get_firewall_domain_list(
            firewall_domain_list_id
        )
        return GetFirewallDomainListResponse(FirewallDomainList=firewall_domain_list)

    def list_firewall_domain_lists(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListFirewallDomainListsResponse:
        """List all Firewall Domain Lists."""
        store = self.get_store(context.account_id, context.region)
        firewall_domain_lists = []
        for firewall_domain_list in store.firewall_domain_lists.values():
            firewall_domain_lists.append(
                select_from_typed_dict(FirewallDomainListMetadata, firewall_domain_list)
            )
        return ListFirewallDomainListsResponse(FirewallDomainLists=firewall_domain_lists)

    def update_firewall_domains(
        self,
        context: RequestContext,
        firewall_domain_list_id: ResourceId,
        operation: FirewallDomainUpdateOperation,
        domains: FirewallDomains,
        **kwargs,
    ) -> UpdateFirewallDomainsResponse:
        """Update the domains in a Firewall Domain List."""
        store = self.get_store(context.account_id, context.region)

        firewall_domain_list: FirewallDomainList = store.get_firewall_domain_list(
            firewall_domain_list_id
        )
        firewall_domains = store.get_firewall_domain(firewall_domain_list_id)

        if operation == FirewallDomainUpdateOperation.ADD:
            if not firewall_domains:
                store.firewall_domains[firewall_domain_list_id] = domains
            else:
                store.firewall_domains[firewall_domain_list_id].append(domains)

        if operation == FirewallDomainUpdateOperation.REMOVE:
            if firewall_domains:
                for domain in domains:
                    if domain in firewall_domains:
                        firewall_domains.remove(domain)
                    else:
                        raise ValidationException(
                            f"[RSLVR-02502] The following domains don't exist in the DNS Firewall domain list '{firewall_domain_list_id}'. You can't delete a domain that isn't in a domain list. Example unknown domain: '{domain}'. Trace Id: '{localstack.services.route53resolver.utils.get_trace_id()}'"
                        )

        if operation == FirewallDomainUpdateOperation.REPLACE:
            store.firewall_domains[firewall_domain_list_id] = domains

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
        **kwargs,
    ) -> ListFirewallDomainsResponse:
        """List the domains in a DNS Firewall domain list."""
        store = self.get_store(context.account_id, context.region)
        firewall_domains: FirewallDomains[FirewallDomainName] = []
        if store.firewall_domains.get(firewall_domain_list_id):
            for firewall_domain in store.firewall_domains.get(firewall_domain_list_id):
                firewall_domains.append(FirewallDomainName(firewall_domain))
        return ListFirewallDomainsResponse(Domains=firewall_domains)

    def create_firewall_rule(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        firewall_rule_group_id: ResourceId,
        priority: Priority,
        action: Action,
        name: Name,
        firewall_domain_list_id: ResourceId = None,
        block_response: BlockResponse = None,
        block_override_domain: BlockOverrideDomain = None,
        block_override_dns_type: BlockOverrideDnsType = None,
        block_override_ttl: BlockOverrideTtl = None,
        firewall_domain_redirection_action: FirewallDomainRedirectionAction = None,
        qtype: Qtype = None,
        dns_threat_protection: DnsThreatProtection = None,
        confidence_threshold: ConfidenceThreshold = None,
        **kwargs,
    ) -> CreateFirewallRuleResponse:
        """Create a new firewall rule"""
        # TODO add support for firewall_domain_list_id, dns_threat_protection, and confidence_threshold
        store = self.get_store(context.account_id, context.region)
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
            FirewallDomainRedirectionAction=firewall_domain_redirection_action,
            Qtype=qtype,
        )
        if firewall_rule_group_id in store.firewall_rules:
            store.firewall_rules[firewall_rule_group_id][firewall_domain_list_id] = firewall_rule
        # TODO: handle missing firewall-rule-group-id
        return CreateFirewallRuleResponse(FirewallRule=firewall_rule)

    def delete_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId = None,
        firewall_threat_protection_id: ResourceId = None,
        qtype: Qtype = None,
        **kwargs,
    ) -> DeleteFirewallRuleResponse:
        """Delete a firewall rule"""
        store = self.get_store(context.account_id, context.region)
        firewall_rule: FirewallRule = store.delete_firewall_rule(
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
        **kwargs,
    ) -> ListFirewallRulesResponse:
        """List firewall rules in a firewall rule group.

        Rules will be filtered by priority and action if values for these params are provided.

        Raises:
            ResourceNotFound: If a firewall group by the provided id does not exist.
        """
        store = self.get_store(context.account_id, context.region)
        firewall_rule_group = store.firewall_rules.get(firewall_rule_group_id)
        if firewall_rule_group is None:
            raise ResourceNotFoundException(
                f"Can't find the resource with ID '{firewall_rule_group_id}'. Trace Id: '{localstack.services.route53resolver.utils.get_trace_id()}'"
            )

        firewall_rules = [
            FirewallRule(rule)
            for rule in firewall_rule_group.values()
            if (action is None or action == rule["Action"])
            and (priority is None or priority == rule["Priority"])
        ]

        # TODO: implement max_results filtering and next_token handling
        return ListFirewallRulesResponse(FirewallRules=firewall_rules)

    def update_firewall_rule(
        self,
        context: RequestContext,
        firewall_rule_group_id: ResourceId,
        firewall_domain_list_id: ResourceId = None,
        firewall_threat_protection_id: ResourceId = None,
        priority: Priority = None,
        action: Action = None,
        block_response: BlockResponse = None,
        block_override_domain: BlockOverrideDomain = None,
        block_override_dns_type: BlockOverrideDnsType = None,
        block_override_ttl: BlockOverrideTtl = None,
        name: Name = None,
        firewall_domain_redirection_action: FirewallDomainRedirectionAction = None,
        qtype: Qtype = None,
        dns_threat_protection: DnsThreatProtection = None,
        confidence_threshold: ConfidenceThreshold = None,
        **kwargs,
    ) -> UpdateFirewallRuleResponse:
        """Updates a firewall rule"""
        store = self.get_store(context.account_id, context.region)
        firewall_rule: FirewallRule = store.get_firewall_rule(
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
        if firewall_domain_redirection_action:
            firewall_rule["FirewallDomainRedirectionAction"] = firewall_domain_redirection_action
        if qtype:
            firewall_rule["Qtype"] = qtype
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
        **kwargs,
    ) -> AssociateFirewallRuleGroupResponse:
        """Associate a firewall rule group with a VPC."""
        store = self.get_store(context.account_id, context.region)
        validate_priority(priority=priority)
        validate_mutation_protection(mutation_protection=mutation_protection)

        for firewall_rule_group_association in store.firewall_rule_group_associations.values():
            if (
                firewall_rule_group_association.get("VpcId") == vpc_id
                and firewall_rule_group_association.get("FirewallRuleGroupId")
                == firewall_rule_group_id
            ):
                raise ValidationException(
                    f"[RSLVR-02302] This DNS Firewall rule group can't be associated to a VPC: '{vpc_id}'. It is already associated to VPC '{firewall_rule_group_id}'. Try again with another VPC or DNS Firewall rule group. Trace Id: '{localstack.services.route53resolver.utils.get_trace_id()}'"
                )

        id = get_route53_resolver_firewall_rule_group_association_id()
        arn = arns.route53_resolver_firewall_rule_group_associations_arn(
            id, context.account_id, context.region
        )

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
        store.firewall_rule_group_associations[id] = firewall_rule_group_association
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return AssociateFirewallRuleGroupResponse(
            FirewallRuleGroupAssociation=firewall_rule_group_association
        )

    def disassociate_firewall_rule_group(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId, **kwargs
    ) -> DisassociateFirewallRuleGroupResponse:
        """Disassociate a DNS Firewall rule group from a VPC."""
        store = self.get_store(context.account_id, context.region)
        firewall_rule_group_association: FirewallRuleGroupAssociation = (
            store.delete_firewall_rule_group_association(firewall_rule_group_association_id)
        )
        return DisassociateFirewallRuleGroupResponse(
            FirewallRuleGroupAssociation=firewall_rule_group_association
        )

    def get_firewall_rule_group_association(
        self, context: RequestContext, firewall_rule_group_association_id: ResourceId, **kwargs
    ) -> GetFirewallRuleGroupAssociationResponse:
        """Returns the Firewall Rule Group Association that you specified."""
        store = self.get_store(context.account_id, context.region)
        firewall_rule_group_association: FirewallRuleGroupAssociation = (
            store.get_firewall_rule_group_association(firewall_rule_group_association_id)
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
        **kwargs,
    ) -> UpdateFirewallRuleGroupAssociationResponse:
        """Updates the specified Firewall Rule Group Association."""
        store = self.get_store(context.account_id, context.region)
        validate_priority(priority=priority)
        validate_mutation_protection(mutation_protection=mutation_protection)

        firewall_rule_group_association: FirewallRuleGroupAssociation = (
            store.get_firewall_rule_group_association(firewall_rule_group_association_id)
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
        **kwargs,
    ) -> CreateResolverQueryLogConfigResponse:
        store = self.get_store(context.account_id, context.region)
        validate_destination_arn(destination_arn)
        id = get_resolver_query_log_config_id()
        arn = arns.route53_resolver_query_log_config_arn(id, context.account_id, context.region)
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
        store.resolver_query_log_configs[id] = resolver_query_log_config
        route53resolver_backends[context.account_id][context.region].tagger.tag_resource(
            arn, tags or []
        )
        return CreateResolverQueryLogConfigResponse(
            ResolverQueryLogConfig=resolver_query_log_config
        )

    def create_resolver_endpoint(
        self,
        context: RequestContext,
        creator_request_id: CreatorRequestId,
        security_group_ids: SecurityGroupIds,
        direction: ResolverEndpointDirection,
        ip_addresses: IpAddressesRequest,
        name: Name = None,
        outpost_arn: OutpostArn = None,
        preferred_instance_type: OutpostInstanceType = None,
        tags: TagList = None,
        resolver_endpoint_type: ResolverEndpointType = None,
        protocols: ProtocolList = None,
        **kwargs,
    ) -> CreateResolverEndpointResponse:
        create_resolver_endpoint_resp = call_moto(context)
        create_resolver_endpoint_resp["ResolverEndpoint"]["Status"] = (
            ResolverQueryLogConfigStatus.CREATING
        )
        return create_resolver_endpoint_resp

    def get_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId, **kwargs
    ) -> GetResolverQueryLogConfigResponse:
        store = self.get_store(context.account_id, context.region)
        resolver_query_log_config: ResolverQueryLogConfig = store.get_resolver_query_log_config(
            resolver_query_log_config_id
        )
        return GetResolverQueryLogConfigResponse(ResolverQueryLogConfig=resolver_query_log_config)

    def delete_resolver_query_log_config(
        self, context: RequestContext, resolver_query_log_config_id: ResourceId, **kwargs
    ) -> DeleteResolverQueryLogConfigResponse:
        store = self.get_store(context.account_id, context.region)
        resolver_query_log_config: ResolverQueryLogConfig = store.delete_resolver_query_log_config(
            resolver_query_log_config_id
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
        **kwargs,
    ) -> ListResolverQueryLogConfigsResponse:
        store = self.get_store(context.account_id, context.region)
        resolver_query_log_configs = []
        for resolver_query_log_config in store.resolver_query_log_configs.values():
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
        **kwargs,
    ) -> AssociateResolverQueryLogConfigResponse:
        store = self.get_store(context.account_id, context.region)
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

        store.resolver_query_log_config_associations[id] = resolver_query_log_config_association

        return AssociateResolverQueryLogConfigResponse(
            ResolverQueryLogConfigAssociation=resolver_query_log_config_association
        )

    def disassociate_resolver_query_log_config(
        self,
        context: RequestContext,
        resolver_query_log_config_id: ResourceId,
        resource_id: ResourceId,
        **kwargs,
    ) -> DisassociateResolverQueryLogConfigResponse:
        store = self.get_store(context.account_id, context.region)
        resolver_query_log_config_association = store.delete_resolver_query_log_config_associations(
            resolver_query_log_config_id, resource_id
        )

        return DisassociateResolverQueryLogConfigResponse(
            ResolverQueryLogConfigAssociation=resolver_query_log_config_association
        )

    def get_resolver_query_log_config_association(
        self,
        context: RequestContext,
        resolver_query_log_config_association_id: ResourceId,
        **kwargs,
    ) -> GetResolverQueryLogConfigAssociationResponse:
        store = self.get_store(context.account_id, context.region)
        resolver_query_log_config_association: ResolverQueryLogConfigAssociation = (
            store.get_resolver_query_log_config_associations(
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
        **kwargs,
    ) -> ListResolverQueryLogConfigAssociationsResponse:
        store = self.get_store(context.account_id, context.region)
        resolver_query_log_config_associations = []
        for (
            resolver_query_log_config_association
        ) in store.resolver_query_log_config_associations.values():
            resolver_query_log_config_associations.append(
                ResolverQueryLogConfigAssociation(resolver_query_log_config_association)
            )
        return ListResolverQueryLogConfigAssociationsResponse(
            TotalCount=len(resolver_query_log_config_associations),
            ResolverQueryLogConfigAssociations=resolver_query_log_config_associations,
        )

    def get_firewall_config(
        self, context: RequestContext, resource_id: ResourceId, **kwargs
    ) -> GetFirewallConfigResponse:
        store = self.get_store(context.account_id, context.region)
        firewall_config = store.get_or_create_firewall_config(
            resource_id, context.region, context.account_id
        )
        return GetFirewallConfigResponse(FirewallConfig=firewall_config)

    def list_firewall_configs(
        self,
        context: RequestContext,
        max_results: ListFirewallConfigsMaxResult = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListFirewallConfigsResponse:
        store = self.get_store(context.account_id, context.region)
        firewall_configs = []
        backend = get_ec2_backend(context.account_id, context.region)
        for vpc in backend.vpcs:
            if vpc not in store.firewall_configs:
                store.get_or_create_firewall_config(vpc, context.region, context.account_id)
        for firewall_config in store.firewall_configs.values():
            firewall_configs.append(select_from_typed_dict(FirewallConfig, firewall_config))
        return ListFirewallConfigsResponse(FirewallConfigs=firewall_configs)

    def update_firewall_config(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        firewall_fail_open: FirewallFailOpenStatus,
        **kwargs,
    ) -> UpdateFirewallConfigResponse:
        store = self.get_store(context.account_id, context.region)
        backend = get_ec2_backend(context.account_id, context.region)
        for resource_id in backend.vpcs:
            if resource_id not in store.firewall_configs:
                firewall_config = store.get_or_create_firewall_config(
                    resource_id, context.region, context.account_id
                )
                firewall_config["FirewallFailOpen"] = firewall_fail_open
            else:
                firewall_config = store.firewall_configs[resource_id]
                firewall_config["FirewallFailOpen"] = firewall_fail_open
        return UpdateFirewallConfigResponse(FirewallConfig=firewall_config)


@patch(MotoRoute53ResolverBackend._matched_arn)
def Route53ResolverBackend_matched_arn(fn, self, resource_arn):
    """Given ARN, raise exception if there is no corresponding resource."""
    account_id = extract_account_id_from_arn(resource_arn)
    region_name = extract_region_from_arn(resource_arn)
    store = Route53ResolverProvider.get_store(account_id, region_name)

    for firewall_rule_group in store.firewall_rule_groups.values():
        if firewall_rule_group.get("Arn") == resource_arn:
            return
    for firewall_domain_list in store.firewall_domain_lists.values():
        if firewall_domain_list.get("Arn") == resource_arn:
            return
    for firewall_rule_group_association in store.firewall_rule_group_associations.values():
        if firewall_rule_group_association.get("Arn") == resource_arn:
            return
    for resolver_query_log_config in store.resolver_query_log_configs.values():
        if resolver_query_log_config.get("Arn") == resource_arn:
            return
    fn(self, resource_arn)


@patch(MotoRoute53ResolverBackend.disassociate_resolver_rule)
def moto_disassociate_resolver_rule(fn, self, resolver_rule_id, vpc_id):
    if resolver_rule_id not in self.resolver_rules:
        raise ResourceNotFoundException(
            f'[RSLVR-00703] Resolver rule with ID "{resolver_rule_id}" does not exist.'
        )
    return fn(self, resolver_rule_id, vpc_id)


@patch(MotoRoute53ResolverBackend.create_resolver_endpoint)
def moto_create_resolver_endpoint(fn, self, *args, **kwargs):
    for group_id in kwargs.get("security_group_ids"):
        if not group_id.startswith("sg-"):
            raise InvalidParameterException(
                f'[RSLVR-00408] Malformed security group ID: "Invalid id: "{group_id}" '
                f'(expecting "sg-...")".'
            )
    return fn(self, *args, **kwargs)


@patch(MotoRoute53ResolverBackend.delete_resolver_rule)
def moto_delete_resolver_endpoint(fn, self, resolver_rule_id):
    if resolver_rule_id not in self.resolver_rules:
        raise ResourceNotFoundException(
            f'[RSLVR-00703] Resolver rule with ID "{resolver_rule_id}" does not exist.'
        )
    return fn(self, resolver_rule_id)


@patch(MotoRoute53ResolverBackend.create_resolver_rule)
def moto_create_resolver_rule(fn, self, *args, **kwargs):
    direction = [
        x.direction
        for x in self.resolver_endpoints.values()
        if x.id == kwargs.get("resolver_endpoint_id")
    ]
    if direction and direction[0] == ResolverEndpointDirection.INBOUND:
        raise InvalidRequestException(
            "[RSLVR-00700] Resolver rules can only be associated to OUTBOUND resolver endpoints."
        )
    return fn(self, *args, **kwargs)
