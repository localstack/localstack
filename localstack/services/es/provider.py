import logging

from mypy_boto3_opensearch import OpenSearchServiceClient

from localstack.aws.api import RequestContext
from localstack.aws.api.es import (
    ARN,
    AdvancedOptions,
    AdvancedSecurityOptions,
    AdvancedSecurityOptionsInput,
    AutoTuneOptionsInput,
    AutoTuneOptionsOutput,
    CognitoOptions,
    CreateElasticsearchDomainResponse,
    DeleteElasticsearchDomainResponse,
    DescribeElasticsearchDomainConfigResponse,
    DescribeElasticsearchDomainResponse,
    DescribeElasticsearchDomainsResponse,
    DomainEndpointOptions,
    DomainInfo,
    DomainName,
    DomainNameList,
    EBSOptions,
    ElasticsearchClusterConfig,
    ElasticsearchDomainStatus,
    ElasticsearchVersionString,
    EncryptionAtRestOptions,
    EngineType,
    EsApi,
    ESPartitionInstanceType,
    GetCompatibleElasticsearchVersionsResponse,
    ListDomainNamesResponse,
    ListElasticsearchVersionsResponse,
    ListTagsResponse,
    LogPublishingOptions,
    MaxResults,
    NextToken,
    NodeToNodeEncryptionOptions,
    PolicyDocument,
    ServiceSoftwareOptions,
    SnapshotOptions,
    StringList,
    TagList,
    VPCOptions,
)
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)

DEFAULT_ELASTICSEARCH_CLUSTER_CONFIG = ElasticsearchClusterConfig(
    InstanceType=ESPartitionInstanceType.m3_medium_elasticsearch,
    InstanceCount=1,
    DedicatedMasterEnabled=True,
    ZoneAwarenessEnabled=False,
    DedicatedMasterType=ESPartitionInstanceType.m3_medium_elasticsearch,
    DedicatedMasterCount=1,
)


def _transform_version_to_opensearch(version: ElasticsearchVersionString) -> str:
    if version.startswith("OpenSearch_"):
        return version
    else:
        return f"Elasticsearch_{version}"


def _transform_version_from_opensearch(version: str) -> ElasticsearchVersionString:
    if version.startswith("Elasticsearch_"):
        return version.split("_")[1]
    else:
        return version


# TODO try to simplify this
def _transform_status(status) -> ElasticsearchDomainStatus:
    return ElasticsearchDomainStatus(
        ARN=status["ARN"],
        Created=status["Created"],
        Deleted=status["Deleted"],
        Processing=status["Processing"],
        DomainId=status["DomainId"],
        DomainName=status["DomainName"],
        ElasticsearchClusterConfig=ElasticsearchClusterConfig(
            DedicatedMasterCount=status["ClusterConfig"]["DedicatedMasterCount"],
            DedicatedMasterEnabled=status["ClusterConfig"]["DedicatedMasterEnabled"],
            DedicatedMasterType=status["ClusterConfig"]["DedicatedMasterType"],
            InstanceCount=status["ClusterConfig"]["InstanceCount"],
            InstanceType=status["ClusterConfig"]["InstanceType"],
            ZoneAwarenessEnabled=status["ClusterConfig"]["ZoneAwarenessEnabled"],
            WarmEnabled=status["ClusterConfig"]["WarmEnabled"],
            ColdStorageOptions=status["ClusterConfig"]["ColdStorageOptions"],
        ),
        ElasticsearchVersion=_transform_version_from_opensearch(status["EngineVersion"]),
        Endpoint=status["Endpoint"],
        EBSOptions=EBSOptions(
            EBSEnabled=status["EBSOptions"]["EBSEnabled"],
            VolumeType=status["EBSOptions"]["VolumeType"],
            VolumeSize=status["EBSOptions"]["VolumeSize"],
            Iops=status["EBSOptions"]["Iops"],
        ),
        CognitoOptions=CognitoOptions(Enabled=status["CognitoOptions"]["Enabled"]),
        UpgradeProcessing=status["UpgradeProcessing"],
        AccessPolicies=status["AccessPolicies"],
        SnapshotOptions=SnapshotOptions(
            AutomatedSnapshotStartHour=status["SnapshotOptions"]["AutomatedSnapshotStartHour"]
        ),
        EncryptionAtRestOptions=EncryptionAtRestOptions(
            Enabled=status["EncryptionAtRestOptions"]["Enabled"]
        ),
        NodeToNodeEncryptionOptions=NodeToNodeEncryptionOptions(
            Enabled=status["NodeToNodeEncryptionOptions"]["Enabled"]
        ),
        AdvancedOptions=status["AdvancedOptions"],
        ServiceSoftwareOptions=ServiceSoftwareOptions(
            CurrentVersion=status["ServiceSoftwareOptions"]["CurrentVersion"],
            NewVersion=status["ServiceSoftwareOptions"]["NewVersion"],
            UpdateAvailable=status["ServiceSoftwareOptions"]["UpdateAvailable"],
            Cancellable=status["ServiceSoftwareOptions"]["Cancellable"],
            UpdateStatus=status["ServiceSoftwareOptions"]["UpdateStatus"],
            Description=status["ServiceSoftwareOptions"]["Description"],
            AutomatedUpdateDate=status["ServiceSoftwareOptions"]["AutomatedUpdateDate"],
            OptionalDeployment=status["ServiceSoftwareOptions"]["OptionalDeployment"],
        ),
        DomainEndpointOptions=DomainEndpointOptions(
            EnforceHTTPS=status["DomainEndpointOptions"]["EnforceHTTPS"],
            TLSSecurityPolicy=status["DomainEndpointOptions"]["TLSSecurityPolicy"],
            CustomEndpointEnabled=status["DomainEndpointOptions"]["CustomEndpointEnabled"],
        ),
        AdvancedSecurityOptions=AdvancedSecurityOptions(
            Enabled=status["AdvancedSecurityOptions"]["Enabled"],
            InternalUserDatabaseEnabled=status["AdvancedSecurityOptions"][
                "InternalUserDatabaseEnabled"
            ],
        ),
        AutoTuneOptions=AutoTuneOptionsOutput(State=status["AutoTuneOptions"]["State"]),
    )


class EsProvider(EsApi):
    def create_elasticsearch_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        elasticsearch_version: ElasticsearchVersionString = None,
        elasticsearch_cluster_config: ElasticsearchClusterConfig = None,
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
        auto_tune_options: AutoTuneOptionsInput = None,
        tag_list: TagList = None,
    ) -> CreateElasticsearchDomainResponse:
        opensearch_client: OpenSearchServiceClient = aws_stack.connect_to_service(
            "opensearch", region_name=context.region
        )

        # TODO add other parameters
        opensearch_status = opensearch_client.create_domain(
            DomainName=domain_name,
            EngineVersion=_transform_version_to_opensearch(elasticsearch_version),
        )["DomainStatus"]

        status = _transform_status(opensearch_status)

        # record event
        event_publisher.fire_event(
            event_publisher.EVENT_ES_CREATE_DOMAIN,
            payload={"n": event_publisher.get_hash(domain_name)},
        )

        return CreateElasticsearchDomainResponse(DomainStatus=status)

    def delete_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteElasticsearchDomainResponse:
        opensearch_client: OpenSearchServiceClient = aws_stack.connect_to_service(
            "opensearch", region_name=context.region
        )

        opensearch_status = opensearch_client.delete_domain(
            DomainName=domain_name,
        )["DomainStatus"]

        status = _transform_status(opensearch_status)

        # record event
        event_publisher.fire_event(
            event_publisher.EVENT_ES_DELETE_DOMAIN,
            payload={"n": event_publisher.get_hash(domain_name)},
        )

        return DeleteElasticsearchDomainResponse(DomainStatus=status)

    def describe_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainResponse:
        opensearch_client: OpenSearchServiceClient = aws_stack.connect_to_service(
            "opensearch", region_name=context.region
        )

        opensearch_status = opensearch_client.describe_domain(
            DomainName=domain_name,
        )["DomainStatus"]

        status = _transform_status(opensearch_status)

        return DescribeElasticsearchDomainResponse(DomainStatus=status)

    def describe_elasticsearch_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeElasticsearchDomainsResponse:
        opensearch_client: OpenSearchServiceClient = aws_stack.connect_to_service(
            "opensearch", region_name=context.region
        )

        opensearch_status_list = opensearch_client.describe_domains(DomainNames=domain_names)[
            "DomainStatusList"
        ]

        status_list = [_transform_status(s) for s in opensearch_status_list]

        return DescribeElasticsearchDomainsResponse(DomainStatusList=status_list)

    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        opensearch_client: OpenSearchServiceClient = aws_stack.connect_to_service(
            "opensearch", region_name=context.region
        )

        opensearch_domain_names = opensearch_client.list_domain_names()["DomainNames"]

        domain_names = [
            DomainInfo(DomainName=n["DomainName"], EngineType=EngineType(n["EngineType"]))
            for n in opensearch_domain_names
        ]

        return ListDomainNamesResponse(DomainNames=domain_names)

    def list_elasticsearch_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListElasticsearchVersionsResponse:
        # TODO implement translation from OpenSearch
        return ListElasticsearchVersionsResponse(ElasticsearchVersions=[])

    def get_compatible_elasticsearch_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleElasticsearchVersionsResponse:
        # TODO implement translation from OpenSearch
        return GetCompatibleElasticsearchVersionsResponse()

    def describe_elasticsearch_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainConfigResponse:
        # TODO implement translation from OpenSearch
        return DescribeElasticsearchDomainConfigResponse(DomainConfig={})

    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        # TODO implement translation from OpenSearch
        pass

    def list_tags(self, context: RequestContext, arn: ARN) -> ListTagsResponse:
        # TODO implement translation from OpenSearch
        return ListTagsResponse(TagList=[])

    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        # TODO implement translation from OpenSearch
        pass
