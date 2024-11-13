import logging
import os
import re
import threading
from datetime import datetime, timezone
from random import randint
from typing import Dict, Optional
from urllib.parse import urlparse

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.opensearch import (
    ARN,
    AccessPoliciesStatus,
    AdvancedOptions,
    AdvancedOptionsStatus,
    AdvancedSecurityOptions,
    AdvancedSecurityOptionsInput,
    AdvancedSecurityOptionsStatus,
    AIMLOptionsInput,
    AutoTuneDesiredState,
    AutoTuneOptions,
    AutoTuneOptionsInput,
    AutoTuneOptionsOutput,
    AutoTuneOptionsStatus,
    AutoTuneState,
    AutoTuneStatus,
    ClusterConfig,
    ClusterConfigStatus,
    CognitoOptions,
    CognitoOptionsStatus,
    ColdStorageOptions,
    CreateDomainResponse,
    DeleteDomainResponse,
    DeploymentStatus,
    DescribeDomainConfigResponse,
    DescribeDomainResponse,
    DescribeDomainsResponse,
    DomainConfig,
    DomainEndpointOptions,
    DomainEndpointOptionsStatus,
    DomainInfo,
    DomainName,
    DomainNameList,
    DomainStatus,
    EBSOptions,
    EBSOptionsStatus,
    EncryptionAtRestOptions,
    EncryptionAtRestOptionsStatus,
    EngineType,
    GetCompatibleVersionsResponse,
    IdentityCenterOptionsInput,
    IPAddressType,
    ListDomainNamesResponse,
    ListTagsResponse,
    ListVersionsResponse,
    LogPublishingOptions,
    LogPublishingOptionsStatus,
    MaxResults,
    NextToken,
    NodeToNodeEncryptionOptions,
    NodeToNodeEncryptionOptionsStatus,
    OffPeakWindowOptions,
    OpensearchApi,
    OpenSearchPartitionInstanceType,
    OptionState,
    OptionStatus,
    PolicyDocument,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RollbackOnDisable,
    ServiceSoftwareOptions,
    SnapshotOptions,
    SnapshotOptionsStatus,
    SoftwareUpdateOptions,
    StringList,
    TagList,
    TLSSecurityPolicy,
    UpdateDomainConfigRequest,
    UpdateDomainConfigResponse,
    ValidationException,
    VersionStatus,
    VersionString,
    VolumeType,
    VPCDerivedInfoStatus,
    VPCOptions,
)
from localstack.constants import OPENSEARCH_DEFAULT_VERSION
from localstack.services.opensearch import versions
from localstack.services.opensearch.cluster import SecurityOptions
from localstack.services.opensearch.cluster_manager import (
    ClusterManager,
    DomainKey,
    create_cluster_manager,
)
from localstack.services.opensearch.models import OpenSearchStore, opensearch_stores
from localstack.services.plugins import ServiceLifecycleHook
from localstack.state import AssetDirectory, StateVisitor
from localstack.utils.aws.arns import parse_arn
from localstack.utils.collections import PaginatedList, remove_none_values_from_dict
from localstack.utils.serving import Server
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

# The singleton for the ClusterManager instance.
# The singleton is implemented this way only to be able to overwrite its value during tests.
__CLUSTER_MANAGER = None

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

DEFAULT_OPENSEARCH_DOMAIN_ENDPOINT_OPTIONS = DomainEndpointOptions(
    EnforceHTTPS=False,
    TLSSecurityPolicy=TLSSecurityPolicy.Policy_Min_TLS_1_0_2019_07,
    CustomEndpointEnabled=False,
)


def cluster_manager() -> ClusterManager:
    global __CLUSTER_MANAGER
    if __CLUSTER_MANAGER is None:
        __CLUSTER_MANAGER = create_cluster_manager()
    return __CLUSTER_MANAGER


def _run_cluster_startup_monitor(cluster: Server, domain_name: str, region: str):
    LOG.debug("running cluster startup monitor for cluster %s", cluster)

    # wait until the cluster is started
    # NOTE: does not work when DNS rebind protection is active for localhost.localstack.cloud
    is_up = cluster.wait_is_up()

    LOG.debug("cluster state polling for %s returned! status = %s", domain_name, is_up)
    with _domain_mutex:
        store = OpensearchProvider.get_store(cluster.account_id, cluster.region_name)
        status = store.opensearch_domains.get(domain_name)
        if status is not None:
            status["Processing"] = False


def create_cluster(
    domain_key: DomainKey,
    engine_version: str,
    domain_endpoint_options: Optional[DomainEndpointOptions],
    security_options: Optional[SecurityOptions],
    preferred_port: Optional[int] = None,
):
    """
    Uses the ClusterManager to create a new cluster for the given domain key. NOT thread safe, needs to be called
    around _domain_mutex.
    If the preferred_port is given, this port will be preferred (if OPENSEARCH_ENDPOINT_STRATEGY == "port").
    """
    store = opensearch_stores[domain_key.account][domain_key.region]

    manager = cluster_manager()
    engine_version = engine_version or OPENSEARCH_DEFAULT_VERSION
    cluster = manager.create(
        arn=domain_key.arn,
        version=engine_version,
        endpoint_options=domain_endpoint_options,
        security_options=security_options,
        preferred_port=preferred_port,
    )

    # FIXME: in AWS, the Endpoint is set once the cluster is running, not before (like here), but our tests and
    #  in particular cloudformation currently relies on the assumption that it is set when the domain is created.
    status = store.opensearch_domains[domain_key.domain_name]
    # Replacing only 0.0.0.0 here as usage of this bind address mostly means running in docker which is used locally
    # If another bind address is used we want to keep it in the endpoint as this is a conscious user decision to
    # access from another device on the network.
    status["Endpoint"] = cluster.url.split("://")[-1].replace("0.0.0.0", localstack_host().host)
    status["EngineVersion"] = engine_version

    if cluster.is_up():
        status["Processing"] = False
    else:
        # run a background thread that will update all domains that use this cluster to set
        # the cluster state once it is started, or the CLUSTER_STARTUP_TIMEOUT is reached
        threading.Thread(
            target=_run_cluster_startup_monitor,
            args=(cluster, domain_key.domain_name, domain_key.region),
            daemon=True,
        ).start()


def _remove_cluster(domain_key: DomainKey):
    parsed_arn = parse_arn(domain_key.arn)
    store = OpensearchProvider.get_store(parsed_arn["account"], parsed_arn["region"])
    cluster_manager().remove(domain_key.arn)
    del store.opensearch_domains[domain_key.domain_name]


def get_domain_config(domain_key) -> DomainConfig:
    status = get_domain_status(domain_key)
    return _status_to_config(status)


def _status_to_config(status: DomainStatus) -> DomainConfig:
    cluster_cfg = status.get("ClusterConfig") or {}
    default_cfg = DEFAULT_OPENSEARCH_CLUSTER_CONFIG
    config_status = get_domain_config_status()
    return DomainConfig(
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
        ClusterConfig=ClusterConfigStatus(
            Options=ClusterConfig(
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
        EngineVersion=VersionStatus(Options=status.get("EngineVersion"), Status=config_status),
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


def get_domain_status(domain_key: DomainKey, deleted=False) -> DomainStatus:
    parsed_arn = parse_arn(domain_key.arn)
    store = OpensearchProvider.get_store(parsed_arn["account"], parsed_arn["region"])
    stored_status: DomainStatus = (
        store.opensearch_domains.get(domain_key.domain_name) or DomainStatus()
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
            WarmEnabled=False,
            ColdStorageOptions=ColdStorageOptions(Enabled=False),
        ),
        EngineVersion=stored_status.get("EngineVersion") or OPENSEARCH_DEFAULT_VERSION,
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
        DomainEndpointOptions=stored_status.get("DomainEndpointOptions")
        or DEFAULT_OPENSEARCH_DOMAIN_ENDPOINT_OPTIONS,
        AdvancedSecurityOptions=AdvancedSecurityOptions(
            Enabled=False, InternalUserDatabaseEnabled=False
        ),
        AutoTuneOptions=AutoTuneOptionsOutput(State=AutoTuneState.ENABLE_IN_PROGRESS),
    )
    return new_status


def _ensure_domain_exists(arn: ARN) -> None:
    """
    Checks if the domain for the given ARN exists. Otherwise, a ValidationException is raised.

    :param arn: ARN string to lookup the domain for
    :return: None if the domain exists, otherwise raises an exception
    :raises: ValidationException if the domain for the given ARN cannot be found
    """
    parsed_arn = parse_arn(arn)
    store = OpensearchProvider.get_store(parsed_arn["account"], parsed_arn["region"])
    domain_key = DomainKey.from_arn(arn)
    domain_status = store.opensearch_domains.get(domain_key.domain_name)
    if domain_status is None:
        raise ValidationException("Invalid ARN. Domain not found.")


def _update_domain_config_request_to_status(request: UpdateDomainConfigRequest) -> DomainStatus:
    request: Dict
    request.pop("DryRun", None)
    request.pop("DomainName", None)
    return request


_domain_name_pattern = re.compile(r"[a-z][a-z0-9\\-]{3,28}")


def is_valid_domain_name(name: str) -> bool:
    return True if _domain_name_pattern.match(name) else False


def validate_endpoint_options(endpoint_options: DomainEndpointOptions):
    custom_endpoint = endpoint_options.get("CustomEndpoint", "")
    custom_endpoint_enabled = endpoint_options.get("CustomEndpointEnabled", False)

    if custom_endpoint and not custom_endpoint_enabled:
        raise ValidationException(
            "CustomEndpointEnabled flag should be set in order to use CustomEndpoint."
        )
    if custom_endpoint_enabled and not custom_endpoint:
        raise ValidationException(
            "Please provide CustomEndpoint field to create a custom endpoint."
        )


class OpensearchProvider(OpensearchApi, ServiceLifecycleHook):
    @staticmethod
    def get_store(account_id: str, region_name: str) -> OpenSearchStore:
        return opensearch_stores[account_id][region_name]

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(opensearch_stores)
        visitor.visit(AssetDirectory(self.service, os.path.join(config.dirs.data, "opensearch")))
        visitor.visit(AssetDirectory(self.service, os.path.join(config.dirs.data, "elasticsearch")))

    def on_after_state_load(self):
        """Starts clusters whose metadata has been restored."""
        for account_id, region, store in opensearch_stores.iter_stores():
            for domain_name, domain_status in store.opensearch_domains.items():
                domain_key = DomainKey(domain_name, region, account_id)
                if cluster_manager().get(domain_key.arn):
                    # cluster already restored in previous call to on_after_state_load
                    continue

                LOG.info("Restoring domain %s in region %s.", domain_name, region)
                try:
                    preferred_port = None
                    if config.OPENSEARCH_ENDPOINT_STRATEGY == "port":
                        # try to parse the previous port to re-use it for the re-created cluster
                        if "Endpoint" in domain_status:
                            preferred_port = urlparse(f"http://{domain_status['Endpoint']}").port

                    engine_version = domain_status.get("EngineVersion")
                    domain_endpoint_options = domain_status.get("DomainEndpointOptions", {})
                    security_options = SecurityOptions.from_input(
                        domain_status.get("AdvancedSecurityOptions")
                    )

                    create_cluster(
                        domain_key=domain_key,
                        engine_version=engine_version,
                        domain_endpoint_options=domain_endpoint_options,
                        security_options=security_options,
                        preferred_port=preferred_port,
                    )
                except Exception:
                    LOG.exception(
                        "Could not restore domain %s in region %s.",
                        domain_name,
                        region,
                    )

    def on_before_state_reset(self):
        self._stop_clusters()

    def on_before_stop(self):
        self._stop_clusters()

    def _stop_clusters(self):
        for account_id, region, store in opensearch_stores.iter_stores():
            for domain_name in store.opensearch_domains.keys():
                cluster_manager().remove(DomainKey(domain_name, region, account_id).arn)

    def create_domain(
        self,
        context: RequestContext,
        domain_name: DomainName,
        engine_version: VersionString = None,
        cluster_config: ClusterConfig = None,
        ebs_options: EBSOptions = None,
        access_policies: PolicyDocument = None,
        ip_address_type: IPAddressType = None,
        snapshot_options: SnapshotOptions = None,
        vpc_options: VPCOptions = None,
        cognito_options: CognitoOptions = None,
        encryption_at_rest_options: EncryptionAtRestOptions = None,
        node_to_node_encryption_options: NodeToNodeEncryptionOptions = None,
        advanced_options: AdvancedOptions = None,
        log_publishing_options: LogPublishingOptions = None,
        domain_endpoint_options: DomainEndpointOptions = None,
        advanced_security_options: AdvancedSecurityOptionsInput = None,
        identity_center_options: IdentityCenterOptionsInput = None,
        tag_list: TagList = None,
        auto_tune_options: AutoTuneOptionsInput = None,
        off_peak_window_options: OffPeakWindowOptions = None,
        software_update_options: SoftwareUpdateOptions = None,
        aiml_options: AIMLOptionsInput = None,
        **kwargs,
    ) -> CreateDomainResponse:
        store = self.get_store(context.account_id, context.region)

        if not is_valid_domain_name(domain_name):
            # TODO: this should use the server-side validation framework at some point.
            raise ValidationException(
                "Member must satisfy regular expression pattern: [a-z][a-z0-9\\-]+"
            )

        if domain_endpoint_options:
            validate_endpoint_options(domain_endpoint_options)

        with _domain_mutex:
            if domain_name in store.opensearch_domains:
                raise ResourceAlreadyExistsException(
                    f"domain {domain_name} already exists in region {context.region}"
                )
            domain_key = DomainKey(
                domain_name=domain_name,
                region=context.region,
                account=context.account_id,
            )
            security_options = SecurityOptions.from_input(advanced_security_options)

            # "create" domain data
            store.opensearch_domains[domain_name] = get_domain_status(domain_key)
            if domain_endpoint_options:
                store.opensearch_domains[domain_name]["DomainEndpointOptions"] = (
                    DEFAULT_OPENSEARCH_DOMAIN_ENDPOINT_OPTIONS | domain_endpoint_options
                )

            # lazy-init the cluster (sets the Endpoint and Processing flag of the domain status)
            # TODO handle additional parameters (cluster config,...)
            create_cluster(domain_key, engine_version, domain_endpoint_options, security_options)

            # set the tags
            self.add_tags(context, domain_key.arn, tag_list)

            # get the (updated) status
            status = get_domain_status(domain_key)

        return CreateDomainResponse(DomainStatus=status)

    def delete_domain(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DeleteDomainResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        store = self.get_store(context.account_id, context.region)
        with _domain_mutex:
            if domain_name not in store.opensearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")

            status = get_domain_status(domain_key, deleted=True)
            _remove_cluster(domain_key)

        return DeleteDomainResponse(DomainStatus=status)

    def describe_domain(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeDomainResponse:
        store = self.get_store(context.account_id, context.region)
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        with _domain_mutex:
            if domain_name not in store.opensearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")

            status = get_domain_status(domain_key)
        return DescribeDomainResponse(DomainStatus=status)

    @handler("UpdateDomainConfig", expand=False)
    def update_domain_config(
        self, context: RequestContext, payload: UpdateDomainConfigRequest
    ) -> UpdateDomainConfigResponse:
        domain_key = DomainKey(
            domain_name=payload["DomainName"],
            region=context.region,
            account=context.account_id,
        )
        store = self.get_store(context.account_id, context.region)
        with _domain_mutex:
            domain_status = store.opensearch_domains.get(domain_key.domain_name, None)
            if domain_status is None:
                raise ResourceNotFoundException(f"Domain not found: {domain_key.domain_name}")

            status_update: Dict = _update_domain_config_request_to_status(payload)
            domain_status.update(status_update)

        return UpdateDomainConfigResponse(DomainConfig=_status_to_config(domain_status))

    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList, **kwargs
    ) -> DescribeDomainsResponse:
        status_list = []
        with _domain_mutex:
            for domain_name in domain_names:
                try:
                    domain_status = self.describe_domain(context, domain_name)["DomainStatus"]
                    status_list.append(domain_status)
                except ResourceNotFoundException:
                    # ResourceNotFoundExceptions are ignored, we just look for the next domain.
                    # If no domain can be found, the result will just be empty.
                    pass
        return DescribeDomainsResponse(DomainStatusList=status_list)

    def list_domain_names(
        self, context: RequestContext, engine_type: EngineType = None, **kwargs
    ) -> ListDomainNamesResponse:
        store = self.get_store(context.account_id, context.region)
        domain_names = [
            DomainInfo(
                DomainName=DomainName(domain_name),
                EngineType=versions.get_engine_type(domain["EngineVersion"]),
            )
            for domain_name, domain in store.opensearch_domains.items()
            if engine_type is None
            or versions.get_engine_type(domain["EngineVersion"]) == engine_type
        ]
        return ListDomainNamesResponse(DomainNames=domain_names)

    def list_versions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListVersionsResponse:
        version_list = PaginatedList(versions.install_versions.keys())
        page, nxt = version_list.get_page(
            lambda x: x,
            next_token=next_token,
            page_size=max_results,
        )
        response = ListVersionsResponse(Versions=page, NextToken=nxt)
        return remove_none_values_from_dict(response)

    def get_compatible_versions(
        self, context: RequestContext, domain_name: DomainName = None, **kwargs
    ) -> GetCompatibleVersionsResponse:
        version_filter = None
        if domain_name:
            store = self.get_store(context.account_id, context.region)
            with _domain_mutex:
                domain = store.opensearch_domains.get(domain_name)
                if not domain:
                    raise ResourceNotFoundException(f"Domain not found: {domain_name}")
                version_filter = domain.get("EngineVersion")
        compatible_versions = list(versions.compatible_versions)
        if version_filter is not None:
            compatible_versions = [
                comp
                for comp in versions.compatible_versions
                if comp["SourceVersion"] == version_filter
            ]
        return GetCompatibleVersionsResponse(CompatibleVersions=compatible_versions)

    def describe_domain_config(
        self, context: RequestContext, domain_name: DomainName, **kwargs
    ) -> DescribeDomainConfigResponse:
        domain_key = DomainKey(
            domain_name=domain_name,
            region=context.region,
            account=context.account_id,
        )
        store = self.get_store(context.account_id, context.region)
        with _domain_mutex:
            if domain_name not in store.opensearch_domains:
                raise ResourceNotFoundException(f"Domain not found: {domain_name}")
            domain_config = get_domain_config(domain_key)
        return DescribeDomainConfigResponse(DomainConfig=domain_config)

    def add_tags(self, context: RequestContext, arn: ARN, tag_list: TagList, **kwargs) -> None:
        _ensure_domain_exists(arn)
        self.get_store(context.account_id, context.region).TAGS.tag_resource(arn, tag_list)

    def list_tags(self, context: RequestContext, arn: ARN, **kwargs) -> ListTagsResponse:
        _ensure_domain_exists(arn)

        # The tagging service returns a dictionary with the given root name
        store = self.get_store(context.account_id, context.region)
        tags = store.TAGS.list_tags_for_resource(arn=arn, root_name="root")
        # Extract the actual list of tags for the typed response
        tag_list: TagList = tags["root"]
        return ListTagsResponse(TagList=tag_list)

    def remove_tags(
        self, context: RequestContext, arn: ARN, tag_keys: StringList, **kwargs
    ) -> None:
        _ensure_domain_exists(arn)
        self.get_store(context.account_id, context.region).TAGS.untag_resource(arn, tag_keys)
