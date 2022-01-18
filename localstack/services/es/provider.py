import logging
import threading
from datetime import datetime, timezone
from random import randint
from typing import Dict

from localstack.aws.api import RequestContext
from localstack.aws.api.es import (
    ARN,
    AccessPoliciesStatus,
    AdvancedOptions,
    AdvancedOptionsStatus,
    AdvancedSecurityOptions,
    AdvancedSecurityOptionsInput,
    AdvancedSecurityOptionsStatus,
    AutoTuneDesiredState,
    AutoTuneOptions,
    AutoTuneOptionsInput,
    AutoTuneOptionsOutput,
    AutoTuneOptionsStatus,
    AutoTuneState,
    AutoTuneStatus,
    CognitoOptions,
    CognitoOptionsStatus,
    ColdStorageOptions,
    CreateElasticsearchDomainResponse,
    DeleteElasticsearchDomainResponse,
    DeploymentStatus,
    DescribeElasticsearchDomainConfigResponse,
    DescribeElasticsearchDomainResponse,
    DescribeElasticsearchDomainsResponse,
    DomainEndpointOptions,
    DomainEndpointOptionsStatus,
    DomainInfo,
    DomainName,
    DomainNameList,
    EBSOptions,
    EBSOptionsStatus,
    ElasticsearchClusterConfig,
    ElasticsearchClusterConfigStatus,
    ElasticsearchDomainConfig,
    ElasticsearchDomainStatus,
    ElasticsearchVersionStatus,
    ElasticsearchVersionString,
    EncryptionAtRestOptions,
    EncryptionAtRestOptionsStatus,
    EngineType,
    EsApi,
    ESPartitionInstanceType,
    GetCompatibleElasticsearchVersionsResponse,
    ListDomainNamesResponse,
    ListElasticsearchVersionsResponse,
    ListTagsResponse,
    LogPublishingOptions,
    LogPublishingOptionsStatus,
    MaxResults,
    NextToken,
    NodeToNodeEncryptionOptions,
    NodeToNodeEncryptionOptionsStatus,
    OptionState,
    OptionStatus,
    PolicyDocument,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RollbackOnDisable,
    ServiceSoftwareOptions,
    SnapshotOptions,
    SnapshotOptionsStatus,
    StringList,
    TagList,
    TLSSecurityPolicy,
    ValidationException,
    VolumeType,
    VPCDerivedInfoStatus,
    VPCOptions,
)
from localstack.constants import ELASTICSEARCH_DEFAULT_VERSION
from localstack.services.es import versions
from localstack.services.es.cluster_manager import ClusterManager, DomainKey, create_cluster_manager
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.common import synchronized
from localstack.utils.serving import Server
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)

# timeout in seconds when giving up on waiting for the cluster to start
CLUSTER_STARTUP_TIMEOUT = 600

# mutex for modifying domains
_domain_mutex = threading.RLock()

DEFAULT_ELASTICSEARCH_CLUSTER_CONFIG = ElasticsearchClusterConfig(
    InstanceType=ESPartitionInstanceType.m3_medium_elasticsearch,
    InstanceCount=1,
    DedicatedMasterEnabled=True,
    ZoneAwarenessEnabled=False,
    DedicatedMasterType=ESPartitionInstanceType.m3_medium_elasticsearch,
    DedicatedMasterCount=1,
)

# cluster manager singleton
_cluster_manager = None


@synchronized(_domain_mutex)
def cluster_manager() -> ClusterManager:
    global _cluster_manager
    if not _cluster_manager:
        _cluster_manager = create_cluster_manager()
    return _cluster_manager


def _run_cluster_startup_monitor(cluster: Server, domain_name: str, region: str):
    LOG.debug("running cluster startup monitor for cluster %s", cluster)

    # wait until the cluster is started, or the timeout is reached
    # NOTE: does not work when DNS rebind protection is active for localhost.localstack.cloud
    is_up = cluster.wait_is_up(CLUSTER_STARTUP_TIMEOUT)

    LOG.debug("cluster state polling for %s returned! status = %s", domain_name, is_up)
    with _domain_mutex:
        status = EsServiceBackend.get(region).elasticsearch_domains[domain_name]
        status["Processing"] = False


def _create_cluster(
    domain_key: DomainKey, engine_version: str, domain_endpoint_options: DomainEndpointOptions
):
    """
    Uses the ClusterManager to create a new cluster for the given domain_name in the region of the current request
    context. NOT thread safe, needs to be called around _domain_mutex.
    """
    region = EsServiceBackend.get(domain_key.region)

    manager = cluster_manager()
    cluster = manager.create(domain_key.arn, domain_endpoint_options or {})

    region.elasticsearch_clusters[domain_key.domain_name] = cluster

    # FIXME: in AWS, the Endpoint is set once the cluster is running, not before (like here), but our tests and
    #  in particular cloudformation currently relies on the assumption that it is set when the domain is created.
    status = region.elasticsearch_domains[domain_key.domain_name]
    status["Endpoint"] = cluster.url.split("://")[-1]
    status["ElasticsearchVersion"] = engine_version

    if cluster.is_up():
        status["Processing"] = False
    else:
        # run a background thread that will update all domains that use this cluster to set
        # the cluster state once it is started, or the CLUSTER_STARTUP_TIMEOUT is reached
        threading.Thread(
            target=_run_cluster_startup_monitor,
            args=(cluster, domain_key.domain_name, region.name),
            daemon=True,
        ).start()


def _remove_cluster(domain_key: DomainKey):
    region = EsServiceBackend.get(domain_key.region)
    cluster_manager().remove(domain_key.arn)
    del region.elasticsearch_clusters[domain_key.domain_name]


class EsServiceBackend(RegionBackend):
    # maps cluster names to cluster details
    elasticsearch_clusters: Dict[str, Server]
    # storage for domain resources (access should be protected with the _domain_mutex)
    elasticsearch_domains: Dict[str, ElasticsearchDomainStatus]
    # static tagging service instance
    TAGS = TaggingService()

    def __init__(self):
        self.elasticsearch_clusters = {}
        self.elasticsearch_domains = {}


def get_domain_config(domain_key) -> ElasticsearchDomainConfig:
    status = get_domain_status(domain_key)
    cluster_cfg = status.get("ElasticsearchClusterConfig") or {}
    default_cfg = DEFAULT_ELASTICSEARCH_CLUSTER_CONFIG
    config_status = get_domain_config_status()
    return ElasticsearchDomainConfig(
        AccessPolicies=AccessPoliciesStatus(
            Options=PolicyDocument(""),
            Status=config_status,
        ),
        AdvancedOptions=AdvancedOptionsStatus(
            Options={
                "override_main_response_version": "false",
                "rest.action.multi.allow_explicit_index": "true",
            },
            Status=config_status,
        ),
        EBSOptions=EBSOptionsStatus(
            Options=EBSOptions(
                EBSEnabled=True,
                VolumeSize=100,
                VolumeType=VolumeType.gp2,
            ),
            Status=config_status,
        ),
        ElasticsearchClusterConfig=ElasticsearchClusterConfigStatus(
            Options=ElasticsearchClusterConfig(
                DedicatedMasterCount=cluster_cfg.get(
                    "DedicatedMasterCount", default_cfg["DedicatedMasterCount"]
                ),
                DedicatedMasterEnabled=cluster_cfg.get(
                    "DedicatedMasterEnabled", default_cfg["DedicatedMasterEnabled"]
                ),
                DedicatedMasterType=cluster_cfg.get(
                    "DedicatedMasterType", default_cfg["DedicatedMasterType"]
                ),
                InstanceCount=cluster_cfg.get("InstanceCount", default_cfg["InstanceCount"]),
                InstanceType=cluster_cfg.get("InstanceType", default_cfg["InstanceType"]),
                ZoneAwarenessEnabled=cluster_cfg.get(
                    "ZoneAwarenessEnabled", default_cfg["ZoneAwarenessEnabled"]
                ),
            ),
            Status=config_status,
        ),
        CognitoOptions=CognitoOptionsStatus(
            Options=CognitoOptions(Enabled=False), Status=config_status
        ),
        ElasticsearchVersion=ElasticsearchVersionStatus(
            Options=status.get("ElasticsearchVersion"), Status=config_status
        ),
        EncryptionAtRestOptions=EncryptionAtRestOptionsStatus(
            Options=EncryptionAtRestOptions(Enabled=False),
            Status=config_status,
        ),
        LogPublishingOptions=LogPublishingOptionsStatus(
            Options={},
            Status=config_status,
        ),
        SnapshotOptions=SnapshotOptionsStatus(
            Options=SnapshotOptions(AutomatedSnapshotStartHour=randint(0, 23)),
            Status=config_status,
        ),
        VPCOptions=VPCDerivedInfoStatus(
            Options={},
            Status=config_status,
        ),
        DomainEndpointOptions=DomainEndpointOptionsStatus(
            Options=status.get("DomainEndpointOptions", {}),
            Status=config_status,
        ),
        NodeToNodeEncryptionOptions=NodeToNodeEncryptionOptionsStatus(
            Options=NodeToNodeEncryptionOptions(Enabled=False),
            Status=config_status,
        ),
        AdvancedSecurityOptions=AdvancedSecurityOptionsStatus(
            Options=status.get("AdvancedSecurityOptions", {}), Status=config_status
        ),
        AutoTuneOptions=AutoTuneOptionsStatus(
            Options=AutoTuneOptions(
                DesiredState=AutoTuneDesiredState.ENABLED,
                RollbackOnDisable=RollbackOnDisable.NO_ROLLBACK,
                MaintenanceSchedules=[],
            ),
            Status=AutoTuneStatus(
                CreationDate=config_status.get("CreationDate"),
                UpdateDate=config_status.get("UpdateDate"),
                UpdateVersion=config_status.get("UpdateVersion"),
                State=AutoTuneState.ENABLED,
                PendingDeletion=config_status.get("PendingDeletion"),
            ),
        ),
    )


def get_domain_config_status() -> OptionStatus:
    return OptionStatus(
        CreationDate=datetime.now(),
        PendingDeletion=False,
        State=OptionState.Active,
        UpdateDate=datetime.now(),
        UpdateVersion=randint(1, 100),
    )


def get_domain_status(domain_key: DomainKey, deleted=False) -> ElasticsearchDomainStatus:
    region = EsServiceBackend.get(domain_key.region)
    stored_status: ElasticsearchDomainStatus = (
        region.elasticsearch_domains.get(domain_key.domain_name) or ElasticsearchDomainStatus()
    )
    cluster_cfg = stored_status.get("ElasticsearchClusterConfig") or {}
    default_cfg = DEFAULT_ELASTICSEARCH_CLUSTER_CONFIG

    new_status = ElasticsearchDomainStatus(
        ARN=domain_key.arn,
        Created=True,
        Deleted=deleted,
        Processing=stored_status.get("Processing", True),
        DomainId=f"{domain_key.account}/{domain_key.domain_name}",
        DomainName=domain_key.domain_name,
        ElasticsearchClusterConfig=ElasticsearchClusterConfig(
            DedicatedMasterCount=cluster_cfg.get(
                "DedicatedMasterCount", default_cfg["DedicatedMasterCount"]
            ),
            DedicatedMasterEnabled=cluster_cfg.get(
                "DedicatedMasterEnabled", default_cfg["DedicatedMasterEnabled"]
            ),
            DedicatedMasterType=cluster_cfg.get(
                "DedicatedMasterType", default_cfg["DedicatedMasterType"]
            ),
            InstanceCount=cluster_cfg.get("InstanceCount", default_cfg["InstanceCount"]),
            InstanceType=cluster_cfg.get("InstanceType", default_cfg["InstanceType"]),
            ZoneAwarenessEnabled=cluster_cfg.get(
                "ZoneAwarenessEnabled", default_cfg["ZoneAwarenessEnabled"]
            ),
            WarmEnabled=False,
            ColdStorageOptions=ColdStorageOptions(Enabled=False),
        ),
        ElasticsearchVersion=stored_status.get("ElasticsearchVersion")
        or ELASTICSEARCH_DEFAULT_VERSION,
        Endpoint=stored_status.get("Endpoint", None),
        EBSOptions=EBSOptions(EBSEnabled=True, VolumeType=VolumeType.gp2, VolumeSize=10, Iops=0),
        CognitoOptions=CognitoOptions(Enabled=False),
        UpgradeProcessing=False,
        AccessPolicies="",
        SnapshotOptions=SnapshotOptions(AutomatedSnapshotStartHour=0),
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
            AutomatedUpdateDate=datetime.fromtimestamp(0, tz=timezone.utc),
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
    if stored_status.get("Endpoint"):
        new_status["Endpoint"] = new_status.get("Endpoint")
    return new_status


def _ensure_domain_exists(arn: ARN) -> None:
    """
    Checks if the domain for the given ARN exists. Otherwise, a ValidationException is raised.

    :param arn: ARN string to look up the domain for
    :return: None if the domain exists, otherwise raises an exception
    :raises: ValidationException if the domain for the given ARN cannot be found
    """
    domain_key = DomainKey.from_arn(arn)
    region = EsServiceBackend.get(domain_key.region)
    domain_status = region.elasticsearch_domains.get(domain_key.domain_name)
    if domain_status is None:
        raise ValidationException("Invalid ARN. Domain not found.")


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
        region = EsServiceBackend.get()
        with _domain_mutex:
            if domain_name in region.elasticsearch_domains:
                raise ResourceAlreadyExistsException(
                    f"domain {domain_name} already exists in region {region.name}"
                )
            domain_key = DomainKey(
                domain_name=domain_name,
                region=context.region,
                account=context.account_id,
            )

            # "create" domain data
            region.elasticsearch_domains[domain_name] = get_domain_status(domain_key)

            # lazy-init the cluster (sets the Endpoint and Processing flag of the domain status)
            engine_version = elasticsearch_version or ELASTICSEARCH_DEFAULT_VERSION
            _create_cluster(domain_key, engine_version, domain_endpoint_options)

            # get the (updated) status
            status = get_domain_status(domain_key)

        # record event
        event_publisher.fire_event(
            event_publisher.EVENT_ES_CREATE_DOMAIN,
            payload={"n": event_publisher.get_hash(domain_name)},
        )

        return CreateElasticsearchDomainResponse(DomainStatus=status)

    def delete_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteElasticsearchDomainResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        region = EsServiceBackend.get(domain_key.region)
        with _domain_mutex:
            if domain_name not in region.elasticsearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")

            status = get_domain_status(domain_key, deleted=True)
            del region.elasticsearch_domains[domain_name]
            _remove_cluster(domain_key)

        # record event
        event_publisher.fire_event(
            event_publisher.EVENT_ES_DELETE_DOMAIN,
            payload={"n": event_publisher.get_hash(domain_name)},
        )

        return DeleteElasticsearchDomainResponse(DomainStatus=status)

    def describe_elasticsearch_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        region = EsServiceBackend.get(domain_key.region)
        with _domain_mutex:
            if domain_name not in region.elasticsearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")

            status = get_domain_status(domain_key)
        return DescribeElasticsearchDomainResponse(DomainStatus=status)

    def describe_elasticsearch_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeElasticsearchDomainsResponse:
        status_list = []
        with _domain_mutex:
            for domain_name in domain_names:
                domain_key = DomainKey(
                    domain_name=domain_name,
                    region=context.region,
                    account=context.account_id,
                )

                status_list.append(get_domain_status(domain_key))
        return DescribeElasticsearchDomainsResponse(DomainStatusList=status_list)

    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        region = EsServiceBackend.get(context.region)
        domain_names = [
            DomainInfo(DomainName=DomainName(domain_name), EngineType=EngineType.Elasticsearch)
            for domain_name in region.elasticsearch_domains.keys()
        ]
        return ListDomainNamesResponse(DomainNames=domain_names)

    def list_elasticsearch_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListElasticsearchVersionsResponse:
        # TODO this implementation currently only handles the ElasticSearch engine.
        # Therefore this function only returns the ElasticSearch version(s).
        # In later iterations, this implementation should handle both engines (OpenSearch and ElasticSearch).
        # Then the response would also contain OpenSearch versions.
        return ListElasticsearchVersionsResponse(
            ElasticsearchVersions=list(versions.install_versions.keys())
        )

    def get_compatible_elasticsearch_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleElasticsearchVersionsResponse:
        # TODO this implementation currently only handles the ElasticSearch engine.
        # In later iterations, this implementation should handle both engines (OpenSearch and ElasticSearch).
        version_filter = None
        if domain_name:
            region = EsServiceBackend.get(context.region)
            with _domain_mutex:
                domain = region.elasticsearch_domains.get(domain_name)
                if not domain:
                    raise ResourceNotFoundException(f"Domain not found: {domain_name}")
                version_filter = domain.get("ElasticsearchVersion")
        compatible_versions = list(versions.compatible_versions)
        if version_filter is not None:
            compatible_versions = [
                comp
                for comp in versions.compatible_versions
                if comp["SourceVersion"] == version_filter
            ]
        return GetCompatibleElasticsearchVersionsResponse(
            CompatibleElasticsearchVersions=compatible_versions
        )

    def describe_elasticsearch_domain_config(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeElasticsearchDomainConfigResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        region = EsServiceBackend.get(domain_key.region)
        with _domain_mutex:
            if domain_name not in region.elasticsearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")
            domain_config = get_domain_config(domain_key)
        return DescribeElasticsearchDomainConfigResponse(DomainConfig=domain_config)

    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList) -> None:
        _ensure_domain_exists(arn)
        EsServiceBackend.TAGS.tag_resource(arn, tag_list)

    def list_tags(self, context: RequestContext, arn: ARN) -> ListTagsResponse:
        _ensure_domain_exists(arn)

        # The tagging service returns a dictionary with the given root name
        tags = EsServiceBackend.TAGS.list_tags_for_resource(arn=arn, root_name="root")
        # Extract the actual list of tags for the typed response
        tag_list: TagList = tags["root"]
        return ListTagsResponse(TagList=tag_list)

    def remove_tags(self, context: RequestContext, arn: ARN, tag_keys: StringList) -> None:
        _ensure_domain_exists(arn)
        EsServiceBackend.TAGS.untag_resource(arn, tag_keys)
