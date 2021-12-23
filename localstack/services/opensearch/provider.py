import logging
import threading
from typing import Dict

from localstack.aws.api import RequestContext
from localstack.aws.api.opensearch import (
    AdvancedOptions,
    AdvancedSecurityOptions,
    AdvancedSecurityOptionsInput,
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
    DomainInfo,
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
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    ServiceSoftwareOptions,
    SnapshotOptions,
    TagList,
    TLSSecurityPolicy,
    VersionString,
    VolumeType,
    VPCOptions,
)

# mutex for domains
from localstack.constants import OPENSEARCH_DEFAULT_VERSION
from localstack.services.generic_proxy import RegionBackend
from localstack.services.opensearch import versions
from localstack.services.opensearch.cluster_manager import (
    ClusterManager,
    DomainKey,
    create_cluster_manager,
)
from localstack.utils.common import synchronized
from localstack.utils.serving import Server
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)

# timeout in seconds when giving up on waiting for the cluster to start
CLUSTER_STARTUP_TIMEOUT = 600

# mutex for modifying domains
_domain_mutex = threading.RLock()

DEFAULT_OPENSEARCH_CLUSTER_CONFIG = ClusterConfig(
    InstanceType=OpenSearchPartitionInstanceType.m3_medium_search,
    InstanceCount=1,
    DedicatedMasterEnabled=True,
    ZoneAwarenessEnabled=False,
    DedicatedMasterType=OpenSearchPartitionInstanceType.m3_medium_search,
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

    # TODO / Initial Implementation: Currently the health check here is never successful.
    #  Therefore the status is never updated.

    # wait until the cluster is started, or the timeout is reached
    is_up = cluster.wait_is_up(CLUSTER_STARTUP_TIMEOUT)

    LOG.debug("cluster state polling for %s returned! status = %s", domain_name, is_up)
    with _domain_mutex:
        status = OpenSearchServiceBackend.get(region).opensearch_domains[domain_name]
        status["Processing"] = False


def _create_cluster(
    domain_key: DomainKey, engine_version: str, domain_endpoint_options: DomainEndpointOptions
):
    """
    Uses the ClusterManager to create a new cluster for the given domain_name in the region of the current request
    context. NOT thread safe, needs to be called around _domain_mutex.
    """
    region = OpenSearchServiceBackend.get(domain_key.region)

    manager = cluster_manager()
    cluster = manager.create(domain_key.arn, engine_version, domain_endpoint_options)

    region.opensearch_clusters[domain_key.domain_name] = cluster

    # FIXME: in AWS, the Endpoint is set once the cluster is running, not before (like here), but our tests and
    #  in particular cloudformation currently relies on the assumption that it is set when the domain is created.
    status = region.opensearch_domains[domain_key.domain_name]
    status["Endpoint"] = cluster.url.split("://")[-1]

    if cluster.is_up():
        status["Processing"] = False
    else:
        # run a background thread that will update all domains that use this cluster to set
        # the cluster state once it is started, or the CLUSTER_STARTUP_TIMEOUT is reached
        threading.Thread(
            target=_run_cluster_startup_monitor,
            args=(cluster, domain_key.arn, region.name),
            daemon=True,
        ).start()


def _remove_cluster(domain_key: DomainKey):
    region = OpenSearchServiceBackend.get(domain_key.region)
    cluster_manager().remove(domain_key.arn)
    del region.opensearch_clusters[domain_key.domain_name]


class OpenSearchServiceBackend(RegionBackend):
    # maps cluster names to cluster details
    opensearch_clusters: Dict[str, Server]
    # storage for domain resources (access should be protected with the _domain_mutex)
    opensearch_domains: Dict[str, DomainStatus]
    # static tagging service instance
    TAGS = TaggingService()

    def __init__(self):
        self.opensearch_clusters = {}
        self.opensearch_domains = {}


def get_domain_status(domain_key: DomainKey, deleted=False) -> DomainStatus:
    region = OpenSearchServiceBackend.get(domain_key.region)
    stored_status: DomainStatus = (
        region.opensearch_domains.get(domain_key.domain_name) or DomainStatus()
    )
    cluster_cfg = stored_status.get("ClusterConfig") or {}
    default_cfg = DEFAULT_OPENSEARCH_CLUSTER_CONFIG

    new_status = DomainStatus(
        ARN=domain_key.arn,
        Created=True,
        Deleted=deleted,
        Processing=stored_status.get("Processing", True),
        DomainId=f"{domain_key.account}/{domain_key.domain_name}",
        DomainName=domain_key.domain_name,
        ClusterConfig=ClusterConfig(
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
            # TODO check if these two should be handled (they aren't handled in our elasticsearch implementation)
            WarmEnabled=False,
            ColdStorageOptions=ColdStorageOptions(Enabled=False),
        ),
        EngineVersion=stored_status.get("EngineVersion")
        or f"OpenSearch_{OPENSEARCH_DEFAULT_VERSION}",
        EBSOptions=EBSOptions(EBSEnabled=True, VolumeType=VolumeType.gp2, VolumeSize=10, Iops=0),
        CognitoOptions=CognitoOptions(Enabled=False),
        # TODO check if the values below should be handled (they aren't handled in our elasticsearch implementation)
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
    if stored_status.get("Endpoint"):
        new_status["Endpoint"] = new_status.get("Endpoint")
    return new_status


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
        region = OpenSearchServiceBackend.get()
        with _domain_mutex:
            if domain_name in region.opensearch_domains:
                raise ResourceAlreadyExistsException(
                    f"domain {domain_name} already exists in region {region.name}"
                )
            domain_key = DomainKey(
                domain_name=domain_name,
                region=context.region,
                account=context.account_id,
            )

            # "create" domain data
            region.opensearch_domains[domain_name] = get_domain_status(domain_key)

            # lazy-init the cluster (sets the Endpoint and Processing flag of the domain status)
            _create_cluster(domain_key, engine_version, domain_endpoint_options)

            # get the (updated) status
            status = get_domain_status(domain_key)

        # TODO publish event

        return CreateDomainResponse(DomainStatus=status)

    def delete_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        region = OpenSearchServiceBackend.get(domain_key.region)
        with _domain_mutex:
            if domain_name not in region.opensearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")

            status = get_domain_status(domain_key, deleted=True)
            del region.opensearch_domains[domain_name]
            _remove_cluster(domain_key)

        # TODO publish event

        return DeleteDomainResponse(DomainStatus=status)

    def describe_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeDomainResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        region = OpenSearchServiceBackend.get(domain_key.region)
        with _domain_mutex:
            if domain_name not in region.opensearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")

            status = get_domain_status(domain_key)
        return DescribeDomainResponse(DomainStatus=status)

    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList
    ) -> DescribeDomainsResponse:
        status_list = []
        with _domain_mutex:
            for domain_name in domain_names:
                domain_key = DomainKey(
                    domain_name=domain_name,
                    region=context.region,
                    account=context.account_id,
                )

                status_list.append(get_domain_status(domain_key))
        return DescribeDomainsResponse(DomainStatusList=status_list)

    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None
    ) -> ListDomainNamesResponse:
        region = OpenSearchServiceBackend.get(context.region)
        domain_names = [
            DomainInfo(DomainName=DomainName(domain_name), EngineType=EngineType.OpenSearch)
            for domain_name in region.opensearch_domains.keys()
        ]
        return ListDomainNamesResponse(DomainNames=domain_names)

    def list_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListVersionsResponse:
        # TODO this currently returns more versions than the actual AWS API.
        # TODO this implementation currently only handles the OpenSearch engine.
        # Therefore this function only returns the OpenSearch version(s).
        # In later iterations, this implementation should handle both engines (OpenSearch and ElasticSearch).
        # Then the response would also contain ElasticSearch versions.
        return ListVersionsResponse(
            Versions=[f"OpenSearch_{version}" for version in versions.install_versions.keys()]
        )

    def get_compatible_versions(
        self, context: RequestContext, domain_name: DomainName = None
    ) -> GetCompatibleVersionsResponse:
        # TODO this implementation currently only handles the OpenSearch engine.
        # Since there is only a single version of opensearch supported yet (1.0), there is no compatibility matrix.
        # In later iterations, this implementation should handle both engines (OpenSearch and ElasticSearch).
        # In that case, a compatibility matrix would make sense.
        return GetCompatibleVersionsResponse()
