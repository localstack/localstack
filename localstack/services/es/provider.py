from contextlib import contextmanager
from typing import Dict, Optional, cast

from botocore.exceptions import ClientError

from localstack import constants
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.es import (
    ARN,
    AccessDeniedException,
    AdvancedOptions,
    AdvancedSecurityOptionsInput,
    AutoTuneOptionsInput,
    CognitoOptions,
    CompatibleElasticsearchVersionsList,
    CompatibleVersionsMap,
    ConflictException,
    CreateElasticsearchDomainResponse,
    DeleteElasticsearchDomainResponse,
    DescribeElasticsearchDomainConfigResponse,
    DescribeElasticsearchDomainResponse,
    DescribeElasticsearchDomainsResponse,
    DisabledOperationException,
    DomainEndpointOptions,
    DomainInfoList,
    DomainName,
    DomainNameList,
    EBSOptions,
    ElasticsearchClusterConfig,
    ElasticsearchClusterConfigStatus,
    ElasticsearchDomainConfig,
    ElasticsearchDomainStatus,
    ElasticsearchVersionStatus,
    ElasticsearchVersionString,
    EncryptionAtRestOptions,
    EngineType,
    EsApi,
    GetCompatibleElasticsearchVersionsResponse,
    InternalException,
    InvalidPaginationTokenException,
    InvalidTypeException,
    LimitExceededException,
    ListDomainNamesResponse,
    ListElasticsearchVersionsResponse,
    ListTagsResponse,
    LogPublishingOptions,
    MaxResults,
    NextToken,
    NodeToNodeEncryptionOptions,
    OptionStatus,
    PolicyDocument,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    SnapshotOptions,
    StringList,
    TagList,
    UpdateElasticsearchDomainConfigRequest,
    UpdateElasticsearchDomainConfigResponse,
    ValidationException,
    VPCOptions,
)
from localstack.aws.api.es import BaseException as EsBaseException
from localstack.aws.api.opensearch import (
    ClusterConfig,
    CompatibleVersionsList,
    DomainConfig,
    DomainStatus,
    VersionString,
)
from localstack.aws.connect import connect_to


def _version_to_opensearch(
    version: Optional[ElasticsearchVersionString],
) -> Optional[VersionString]:
    if version is not None:
        if version.startswith("OpenSearch_"):
            return version
        else:
            return f"Elasticsearch_{version}"


def _version_from_opensearch(
    version: Optional[VersionString],
) -> Optional[ElasticsearchVersionString]:
    if version is not None:
        if version.startswith("Elasticsearch_"):
            return version.split("_")[1]
        else:
            return version


def _instancetype_to_opensearch(instance_type: Optional[str]) -> Optional[str]:
    if instance_type is not None:
        return instance_type.replace("elasticsearch", "search")


def _instancetype_from_opensearch(instance_type: Optional[str]) -> Optional[str]:
    if instance_type is not None:
        return instance_type.replace("search", "elasticsearch")


def _clusterconfig_from_opensearch(
    cluster_config: Optional[ClusterConfig],
) -> Optional[ElasticsearchClusterConfig]:
    if cluster_config is not None:
        # Just take the whole typed dict and typecast it to our target type
        result = cast(ElasticsearchClusterConfig, cluster_config)

        # Adjust the instance type names
        result["InstanceType"] = _instancetype_from_opensearch(cluster_config.get("InstanceType"))
        result["DedicatedMasterType"] = _instancetype_from_opensearch(
            cluster_config.get("DedicatedMasterType")
        )
        result["WarmType"] = _instancetype_from_opensearch(cluster_config.get("WarmType"))
        return result


def _domainstatus_from_opensearch(
    domain_status: Optional[DomainStatus],
) -> Optional[ElasticsearchDomainStatus]:
    if domain_status is not None:
        # Just take the whole typed dict and typecast it to our target type
        result = cast(ElasticsearchDomainStatus, domain_status)
        # Only specifically handle keys which are named differently or their values differ (version and clusterconfig)
        result["ElasticsearchVersion"] = _version_from_opensearch(
            domain_status.get("EngineVersion")
        )
        result["ElasticsearchClusterConfig"] = _clusterconfig_from_opensearch(
            domain_status.get("ClusterConfig")
        )
        result.pop("EngineVersion", None)
        result.pop("ClusterConfig", None)
        return result


def _clusterconfig_to_opensearch(
    elasticsearch_cluster_config: Optional[ElasticsearchClusterConfig],
) -> Optional[ClusterConfig]:
    if elasticsearch_cluster_config is not None:
        result = cast(ClusterConfig, elasticsearch_cluster_config)
        if instance_type := result.get("InstanceType"):
            result["InstanceType"] = _instancetype_to_opensearch(instance_type)
        if dedicated_master_type := result.get("DedicatedMasterType"):
            result["DedicatedMasterType"] = _instancetype_to_opensearch(dedicated_master_type)
        if warm_type := result.get("WarmType"):
            result["WarmType"] = _instancetype_to_opensearch(warm_type)
        return result


def _domainconfig_from_opensearch(
    domain_config: Optional[DomainConfig],
) -> Optional[ElasticsearchDomainConfig]:
    if domain_config is not None:
        result = cast(ElasticsearchDomainConfig, domain_config)
        engine_version = domain_config.get("EngineVersion", {})
        result["ElasticsearchVersion"] = ElasticsearchVersionStatus(
            Options=_version_from_opensearch(engine_version.get("Options")),
            Status=cast(OptionStatus, engine_version.get("Status")),
        )
        cluster_config = domain_config.get("ClusterConfig", {})
        result["ElasticsearchClusterConfig"] = ElasticsearchClusterConfigStatus(
            Options=_clusterconfig_from_opensearch(cluster_config.get("Options")),
            Status=cluster_config.get("Status"),
        )
        result.pop("EngineVersion", None)
        result.pop("ClusterConfig", None)
        return result


def _compatible_version_list_from_opensearch(
    compatible_version_list: Optional[CompatibleVersionsList],
) -> Optional[CompatibleElasticsearchVersionsList]:
    if compatible_version_list is not None:
        return [
            CompatibleVersionsMap(
                SourceVersion=_version_from_opensearch(version_map["SourceVersion"]),
                TargetVersions=[
                    _version_from_opensearch(target_version)
                    for target_version in version_map["TargetVersions"]
                ],
            )
            for version_map in compatible_version_list
        ]


@contextmanager
def exception_mapper():
    """Maps an exception thrown by the OpenSearch client to an exception thrown by the ElasticSearch API."""
    try:
        yield
    except ClientError as err:
        exception_types = {
            "AccessDeniedException": AccessDeniedException,
            "BaseException": EsBaseException,
            "ConflictException": ConflictException,
            "DisabledOperationException": DisabledOperationException,
            "InternalException": InternalException,
            "InvalidPaginationTokenException": InvalidPaginationTokenException,
            "InvalidTypeException": InvalidTypeException,
            "LimitExceededException": LimitExceededException,
            "ResourceAlreadyExistsException": ResourceAlreadyExistsException,
            "ResourceNotFoundException": ResourceNotFoundException,
            "ValidationException": ValidationException,
        }
        mapped_exception_type = exception_types.get(err.response["Error"]["Code"], EsBaseException)
        raise mapped_exception_type(err.response["Error"]["Message"])


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
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch
        # If no version is given, we set our default elasticsearch version
        engine_version = (
            _version_to_opensearch(elasticsearch_version)
            if elasticsearch_version
            else constants.ELASTICSEARCH_DEFAULT_VERSION
        )
        kwargs = {
            "DomainName": domain_name,
            "EngineVersion": engine_version,
            "ClusterConfig": _clusterconfig_to_opensearch(elasticsearch_cluster_config),
            "EBSOptions": ebs_options,
            "AccessPolicies": access_policies,
            "SnapshotOptions": snapshot_options,
            "VPCOptions": vpc_options,
            "CognitoOptions": cognito_options,
            "EncryptionAtRestOptions": encryption_at_rest_options,
            "NodeToNodeEncryptionOptions": node_to_node_encryption_options,
            "AdvancedOptions": advanced_options,
            "LogPublishingOptions": log_publishing_options,
            "DomainEndpointOptions": domain_endpoint_options,
            "AdvancedSecurityOptions": advanced_security_options,
            "AutoTuneOptions": auto_tune_options,
            "TagList": tag_list,
        }

        # Filter the kwargs to not set None values at all (boto doesn't like that)
        kwargs = {key: value for key, value in kwargs.items() if value is not None}

        with exception_mapper():
            domain_status = opensearch_client.create_domain(**kwargs)["DomainStatus"]

        status = _domainstatus_from_opensearch(domain_status)
        return CreateElasticsearchDomainResponse(DomainStatus=status)

    def delete_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteElasticsearchDomainResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            domain_status = opensearch_client.delete_domain(
                DomainName=domain_name,
            )["DomainStatus"]

        status = _domainstatus_from_opensearch(domain_status)
        return DeleteElasticsearchDomainResponse(DomainStatus=status)

    def describe_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            opensearch_status = opensearch_client.describe_domain(
                DomainName=domain_name,
            )["DomainStatus"]

        status = _domainstatus_from_opensearch(opensearch_status)
        return DescribeElasticsearchDomainResponse(DomainStatus=status)

    @handler("UpdateElasticsearchDomainConfig", expand=False)
    def update_elasticsearch_domain_config(
        self, context: RequestContext, payload: UpdateElasticsearchDomainConfigRequest
    ) -> UpdateElasticsearchDomainConfigResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        payload: Dict
        if "ElasticsearchClusterConfig" in payload:
            payload["ClusterConfig"] = payload["ElasticsearchClusterConfig"]
            payload["ClusterConfig"]["InstanceType"] = _instancetype_to_opensearch(
                payload["ClusterConfig"]["InstanceType"]
            )
            payload.pop("ElasticsearchClusterConfig")

        with exception_mapper():
            opensearch_config = opensearch_client.update_domain_config(**payload)["DomainConfig"]

        config = _domainconfig_from_opensearch(opensearch_config)
        return UpdateElasticsearchDomainConfigResponse(DomainConfig=config)

    def describe_elasticsearch_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeElasticsearchDomainsResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            opensearch_status_list = opensearch_client.describe_domains(
                DomainNames=domain_names,
            )["DomainStatusList"]

        status_list = [_domainstatus_from_opensearch(s) for s in opensearch_status_list]
        return DescribeElasticsearchDomainsResponse(DomainStatusList=status_list)

    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch
        # Only hand the EngineType param to boto if it's set
        kwargs = {}
        if engine_type:
            kwargs["EngineType"] = engine_type

        with exception_mapper():
            domain_names = opensearch_client.list_domain_names(**kwargs)["DomainNames"]

        return ListDomainNamesResponse(DomainNames=cast(Optional[DomainInfoList], domain_names))

    def list_elasticsearch_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListElasticsearchVersionsResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch
        # Construct the arguments as kwargs to not set None values at all (boto doesn't like that)
        kwargs = {
            key: value
            for key, value in {"MaxResults": max_results, "NextToken": next_token}.items()
            if value is not None
        }
        with exception_mapper():
            versions = opensearch_client.list_versions(**kwargs)

        return ListElasticsearchVersionsResponse(
            ElasticsearchVersions=[
                _version_from_opensearch(version) for version in versions["Versions"]
            ],
            NextToken=versions.get(next_token),
        )

    def get_compatible_elasticsearch_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleElasticsearchVersionsResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch
        # Only hand the DomainName param to boto if it's set
        kwargs = {}
        if domain_name:
            kwargs["DomainName"] = domain_name

        with exception_mapper():
            compatible_versions_response = opensearch_client.get_compatible_versions(**kwargs)

        compatible_versions = compatible_versions_response.get("CompatibleVersions")
        return GetCompatibleElasticsearchVersionsResponse(
            CompatibleElasticsearchVersions=_compatible_version_list_from_opensearch(
                compatible_versions
            )
        )

    def describe_elasticsearch_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainConfigResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            domain_config = opensearch_client.describe_domain_config(DomainName=domain_name).get(
                "DomainConfig"
            )

        return DescribeElasticsearchDomainConfigResponse(
            DomainConfig=_domainconfig_from_opensearch(domain_config)
        )

    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            opensearch_client.add_tags(ARN=arn, TagList=tag_list)

    def list_tags(self, context: RequestContext, arn: ARN) -> ListTagsResponse:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            response = opensearch_client.list_tags(ARN=arn)

        return ListTagsResponse(TagList=response.get("TagList"))

    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        opensearch_client = connect_to(
            region_name=context.region, aws_access_key_id=context.account_id
        ).opensearch

        with exception_mapper():
            opensearch_client.remove_tags(ARN=arn, TagKeys=tag_keys)
