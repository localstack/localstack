from localstack.aws.api import RequestContext
from localstack.aws.api.opensearch import (
    AdvancedOptions,
    AdvancedSecurityOptionsInput,
    AutoTuneOptionsInput,
    ClusterConfig,
    CognitoOptions,
    CreateDomainResponse,
    DeleteDomainResponse,
    DescribeDomainResponse,
    DescribeDomainsResponse,
    DomainEndpointOptions,
    DomainName,
    DomainNameList,
    EBSOptions,
    EncryptionAtRestOptions,
    EngineType,
    GetCompatibleVersionsResponse,
    ListDomainNamesResponse,
    ListVersionsResponse,
    LogPublishingOptions,
    MaxResults,
    NextToken,
    NodeToNodeEncryptionOptions,
    OpensearchApi,
    PolicyDocument,
    SnapshotOptions,
    TagList,
    VersionString,
    VPCOptions,
)


class OpensearchProvider(OpensearchApi):
    def create_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        engine_version: VersionString = None,
        cluster_config: ClusterConfig = None,
        ebs_options: EBSOptions = None,
        access_policies: PolicyDocument = None,
        snapshot_options: SnapshotOptions = None,
        vpc_options: VPCOptions = None,
        cognito_options: CognitoOptions = None,
        encryption_at_rest_options: EncryptionAtRestOptions = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions = None,
        advanced_options: AdvancedOptions = None,
        log_publishing_options: LogPublishingOptions = None,
        domain_endpoint_options: DomainEndpointOptions = None,
        advanced_security_options: AdvancedSecurityOptionsInput = None,
        tag_list: TagList = None,
        auto_tune_options: AutoTuneOptionsInput = None,
    ) -> CreateDomainResponse:
        return CreateDomainResponse()

    def delete_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainResponse:
        return DeleteDomainResponse()

    def describe_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeDomainResponse:
        return DescribeDomainResponse()

    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeDomainsResponse:
        return DescribeDomainsResponse()

    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        return ListDomainNamesResponse()

    # TODO get domain status?

    def list_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListVersionsResponse:
        return ListVersionsResponse()

    def get_compatible_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleVersionsResponse:
        return GetCompatibleVersionsResponse()
