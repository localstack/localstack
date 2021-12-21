from localstack.aws.api import RequestContext
from localstack.aws.api.opensearch import (
    AdvancedOptions,
    AdvancedSecurityOptions,
    AdvancedSecurityOptionsInput,
    AutoTuneOptions,
    AutoTuneOptionsInput,
    AutoTuneOptionsOutput,
    AutoTuneState,
    ClusterConfig,
    CognitoOptions,
    ColdStorageOptions,
    CreateDomainResponse,
    DeleteDomainResponse,
    DeploymentStatus,
    DescribeDomainResponse,
    DescribeDomainsResponse,
    DomainEndpointOptions,
    DomainName,
    DomainNameList,
    DomainStatus,
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
    OpenSearchPartitionInstanceType,
    PolicyDocument,
    ServiceSoftwareOptions,
    SnapshotOptions,
    TagList,
    TLSSecurityPolicy,
    VersionString,
    VolumeType,
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
        status = DomainStatus(
            DomainId=f"0000000000000/{domain_name}",
            DomainName=domain_name,
            Created=True,
            Deleted=False,
            Processing=True,
            UpgradeProcessing=False,
            EngineVersion="OpenSearch_1.0",
            ClusterConfig=ClusterConfig(
                InstanceType=OpenSearchPartitionInstanceType.t2_medium_search,
                InstanceCount=1,
                DedicatedMasterEnabled=False,
                ZoneAwarenessEnabled=False,
                WarmEnabled=False,
                ColdStorageOptions=ColdStorageOptions(Enabled=False),
            ),
            EBSOptions=EBSOptions(EBSEnabled=True, VolumeType=VolumeType.gp2, VolumeSize=10),
            AccessPolicies="",
            SnapshotOptions=SnapshotOptions(AutomatedSnapshotStartHour=0),
            CognitoOptions=CognitoOptions(Enabled=False),
            EncryptionAtRestOptions=EncryptionAtRestOptions(Enabled=False),
            NodeToNodeEncryptionOptions=NodeToNodeEncryptionOptions(Enabled=False),
            AdvancedOptions={
                "override_main_response_version": "false",
                "rest.action.multi.allow_explicit_index": "true",
            },
            ServiceSoftwareOptions=ServiceSoftwareOptions(
                CurrentVersion="",
                NewVersion="",
                UpdateAvailable=False,
                Cancellable=False,
                UpdateStatus=DeploymentStatus.COMPLETED,
                Description="There is no software update available for this domain.",
                AutomatedUpdateDate="0.0",
                OptionalDeployment=True,
            ),
            DomainEndpointOptions=DomainEndpointOptions(
                EnforceHTTPS=False,
                TLSSecurityPolicy=TLSSecurityPolicy.Policy_Min_TLS_1_0_2019_07,
                CustomEndpointEnabled=False,
            ),
            AdvancedSecurityOptions=AdvancedSecurityOptions(
                Enabled=False, InternalUserDatabaseEnabled=False
            ),
            AutoTuneOptions=AutoTuneOptionsOutput(State=AutoTuneState.ENABLE_IN_PROGRESS),
        )
        return CreateDomainResponse(DomainStatus=status)

    def delete_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainResponse:
        status = DomainStatus(
            DomainId=f"0000000000000/{domain_name}", DomainName=domain_name, Deleted=True
        )
        return DeleteDomainResponse(DomainStatus=status)

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
