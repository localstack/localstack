import dataclasses
import logging
import threading
from typing import Dict, Optional

from botocore.utils import ArnParser

from localstack import config
from localstack.aws.api.opensearch import DomainEndpointOptions, EngineType
from localstack.constants import LOCALHOST
from localstack.services.opensearch import versions
from localstack.services.opensearch.cluster import (
    CustomEndpoint,
    EdgeProxiedElasticsearchCluster,
    EdgeProxiedOpensearchCluster,
    ElasticsearchCluster,
    EndpointProxy,
    FakeEndpointProxyServer,
    OpensearchCluster,
    SecurityOptions,
)
from localstack.utils.aws.arns import get_partition
from localstack.utils.common import (
    PortNotAvailableException,
    call_safe,
    external_service_ports,
    get_free_tcp_port,
    start_thread,
)
from localstack.utils.serving import Server
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)


def create_cluster_manager() -> "ClusterManager":
    """Creates the cluster manager according to the configuration."""

    # If we have an external cluster, we always use the CustomBackendManager.
    if config.OPENSEARCH_CUSTOM_BACKEND:
        return CustomBackendManager()

    # If we are using a localstack-managed multi-cluster-setup, we use the MultiClusterManager.
    if config.OPENSEARCH_MULTI_CLUSTER:
        return MultiClusterManager()
    else:
        # Otherwise, we use a single cluster
        if config.OPENSEARCH_ENDPOINT_STRATEGY != "port":
            # and multiplex domains with the MultiplexingClusterManager.
            return MultiplexingClusterManager()
        else:
            # with a single port.
            return SingletonClusterManager()


@dataclasses.dataclass
class DomainKey:
    """Uniquely identifies an OpenSearch/Elasticsearch domain."""

    domain_name: str
    region: str
    account: str

    @property
    def arn(self):
        return f"arn:{get_partition(self.region)}:es:{self.region}:{self.account}:domain/{self.domain_name}"

    @staticmethod
    def from_arn(arn: str) -> "DomainKey":
        parsed = ArnParser().parse_arn(arn)
        if parsed["service"] != "es":
            raise ValueError("not an opensearch/es arn: %s", arn)

        return DomainKey(
            domain_name=parsed["resource"][7:],  # strip 'domain/'
            region=parsed["region"],
            account=parsed["account"],
        )


def build_cluster_endpoint(
    domain_key: DomainKey,
    custom_endpoint: Optional[CustomEndpoint] = None,
    engine_type: EngineType = EngineType.OpenSearch,
    preferred_port: Optional[int] = None,
) -> str:
    """
    Builds the cluster endpoint from and optional custom_endpoint and the localstack opensearch config. Example
    values:

    - my-domain.us-east-1.opensearch.localhost.localstack.cloud:4566 (endpoint strategy = domain (default))
    - localhost:4566/us-east-1/my-domain (endpoint strategy = path)
    - localhost:[port-from-range] (endpoint strategy = port (or deprecated 'off'))
    - my.domain:443/foo (arbitrary endpoints (technically not allowed by AWS, but there are no rules in localstack))

    If preferred_port is not None, it is tried to reserve the given port. If the port is already bound, another port
    will be used.
    """
    # If we have a CustomEndpoint, we directly take its endpoint.
    if custom_endpoint and custom_endpoint.enabled:
        return custom_endpoint.endpoint

    # different endpoints based on engine type
    engine_domain = "opensearch" if engine_type == EngineType.OpenSearch else "es"

    # Otherwise, the endpoint is either routed through the edge proxy via a sub-path (localhost:4566/opensearch/...)
    if config.OPENSEARCH_ENDPOINT_STRATEGY == "port":
        if preferred_port is not None:
            try:
                # if the preferred port is given, we explicitly try to reserve it
                assigned_port = external_service_ports.reserve_port(preferred_port)
            except PortNotAvailableException:
                LOG.warning(
                    f"Preferred port {preferred_port} is not available, trying to reserve another port."
                )
                assigned_port = external_service_ports.reserve_port()
        else:
            assigned_port = external_service_ports.reserve_port()

        host_definition = localstack_host(custom_port=assigned_port)
        return host_definition.host_and_port()
    if config.OPENSEARCH_ENDPOINT_STRATEGY == "path":
        host_definition = localstack_host()
        return f"{host_definition.host_and_port()}/{engine_domain}/{domain_key.region}/{domain_key.domain_name}"

    # or through a subdomain (domain-name.region.opensearch.localhost.localstack.cloud)
    host_definition = localstack_host()
    return f"{domain_key.domain_name}.{domain_key.region}.{engine_domain}.{host_definition.host_and_port()}"


def determine_custom_endpoint(
    domain_endpoint_options: DomainEndpointOptions,
) -> Optional[CustomEndpoint]:
    if not domain_endpoint_options:
        return

    custom_endpoint = domain_endpoint_options.get("CustomEndpoint")
    enabled = domain_endpoint_options.get("CustomEndpointEnabled", False)

    if not custom_endpoint:
        # No custom endpoint to determine
        return

    return CustomEndpoint(enabled, custom_endpoint)


class ClusterManager:
    clusters: Dict[str, Server]

    def __init__(self) -> None:
        self.clusters = {}

    def create(
        self,
        arn: str,
        version: str,
        endpoint_options: Optional[DomainEndpointOptions] = None,
        security_options: Optional[SecurityOptions] = None,
        preferred_port: Optional[int] = None,
    ) -> Server:
        """
        Creates a new cluster.

        :param arn: of the cluster to create
        :param version: of the cluster to start (string including the EngineType)
        :param endpoint_options: DomainEndpointOptions (may contain information about a custom endpoint url)
        :param security_options: SecurityOptions (may contain info on the security plugin config)
        :param preferred_port: port which should be preferred (only if OPENSEARCH_ENDPOINT_STRATEGY == "port")
        :return: None
        """

        # determine custom domain endpoint
        custom_endpoint = determine_custom_endpoint(endpoint_options)

        # determine engine type
        engine_type = versions.get_engine_type(version)

        # build final endpoint and cluster url
        endpoint = build_cluster_endpoint(
            DomainKey.from_arn(arn), custom_endpoint, engine_type, preferred_port
        )
        url = f"http://{endpoint}" if "://" not in endpoint else endpoint

        # call abstract cluster factory
        cluster = self._create_cluster(arn, url, version, custom_endpoint, security_options)
        cluster.start()

        # save cluster into registry and return
        self.clusters[arn] = cluster
        return cluster

    def get(self, arn: str) -> Optional[Server]:
        return self.clusters.get(arn)

    def remove(self, arn: str):
        if arn in self.clusters:
            cluster = self.clusters.pop(arn)
            if cluster:
                LOG.debug("shutting down cluster arn %s (%s)", arn, cluster.url)
                cluster.shutdown()

    def is_up(self, arn: str) -> bool:
        cluster = self.get(arn)
        return cluster.is_up() if cluster else False

    def _create_cluster(
        self,
        arn: str,
        url: str,
        version: str,
        custom_endpoint: CustomEndpoint,
        security_options: SecurityOptions,
    ) -> Server:
        """
        Abstract cluster factory.

        :param version: the full prefixed version, e.g. "OpenSearch_1.0" or "Elasticsearch_7.10"
        """
        raise NotImplementedError

    def shutdown_all(self):
        while self.clusters:
            domain, cluster = self.clusters.popitem()
            call_safe(cluster.shutdown)


class ClusterEndpoint(FakeEndpointProxyServer):
    """
    An endpoint that points to a cluster, and behaves like a Server.
    """

    def __init__(self, cluster: Server, endpoint: EndpointProxy) -> None:
        super().__init__(endpoint)
        self.cluster = cluster

    def health(self):
        return super().health() and self.cluster.health()

    def do_shutdown(self):
        super(FakeEndpointProxyServer, self).do_shutdown()
        self.cluster.shutdown()


def _get_port_from_url(url: str) -> int:
    return int(url.split(":")[2])


class MultiplexingClusterManager(ClusterManager):
    """
    Multiplexes multiple endpoints to a single backend cluster (not managed by LocalStack).
    Using this, we lie to the client about the opensearch domain version.
    It only works with a single endpoint.

    Assumes the config:
    - OPENSEARCH_MULTI_CLUSTER = False
    - OPENSEARCH_ENDPOINT_STRATEGY = domain / path
    """

    cluster: Optional[Server]
    endpoints: Dict[str, ClusterEndpoint]

    def __init__(self) -> None:
        super().__init__()
        self.cluster = None
        self.endpoints = {}
        self.mutex = threading.RLock()

    def _create_cluster(
        self,
        arn: str,
        url: str,
        version: str,
        custom_endpoint: CustomEndpoint,
        security_options: SecurityOptions,
    ) -> Server:
        with self.mutex:
            if not self.cluster:
                engine_type = versions.get_engine_type(version)
                # startup routine for the singleton cluster instance
                if engine_type == EngineType.OpenSearch:
                    self.cluster = OpensearchCluster(
                        port=get_free_tcp_port(), arn=arn, security_options=security_options
                    )
                else:
                    self.cluster = ElasticsearchCluster(
                        port=get_free_tcp_port(), arn=arn, security_options=security_options
                    )

                def _start_async(*_):
                    LOG.info("starting %s on %s", type(self.cluster), self.cluster.url)
                    self.cluster.start()  # start may block during install

                start_thread(_start_async, name="opensearch-multiplex")
            cluster_endpoint = ClusterEndpoint(
                self.cluster, EndpointProxy(url, self.cluster.url, custom_endpoint=custom_endpoint)
            )
            self.clusters[arn] = cluster_endpoint
            return cluster_endpoint

    def remove(self, arn: str):
        super().remove(arn)  # removes the fake server

        if not self.endpoints:
            # if there are no endpoints left, remove the cluster
            with self.mutex:
                if not self.cluster:
                    return

                LOG.debug("shutting down multiplexed cluster for %s: %s", arn, self.cluster.url)
                self.cluster.shutdown()
                self.cluster = None


class MultiClusterManager(ClusterManager):
    """
    Manages one cluster and endpoint per domain.
    """

    def _create_cluster(
        self,
        arn: str,
        url: str,
        version: str,
        custom_endpoint: CustomEndpoint,
        security_options: SecurityOptions,
    ) -> Server:
        engine_type = versions.get_engine_type(version)
        if config.OPENSEARCH_ENDPOINT_STRATEGY != "port":
            if engine_type == EngineType.OpenSearch:
                return EdgeProxiedOpensearchCluster(
                    url=url,
                    arn=arn,
                    version=version,
                    custom_endpoint=custom_endpoint,
                    security_options=security_options,
                )
            else:
                return EdgeProxiedElasticsearchCluster(
                    url=url,
                    arn=arn,
                    version=version,
                    custom_endpoint=custom_endpoint,
                    security_options=security_options,
                )
        else:
            port = _get_port_from_url(url)
            if engine_type == EngineType.OpenSearch:
                return OpensearchCluster(
                    port=port, host=config.GATEWAY_LISTEN[0].host, arn=arn, version=version
                )
            else:
                return ElasticsearchCluster(
                    port=port, host=config.GATEWAY_LISTEN[0].host, arn=arn, version=version
                )


class SingletonClusterManager(ClusterManager):
    """
    Manages a single cluster and always returns that cluster. Using this, we lie to the client about the
    elasticsearch domain version. The first call to create_domain with a specific version will create the cluster
    with that version. Subsequent calls will believe they created a cluster with the version they specified. It keeps
    the cluster running until the last domain was removed. It only works with a single endpoint.
    Assumes the config:
    - ES_ENDPOINT_STRATEGY == "port"
    - ES_MULTI_CLUSTER == False
    """

    cluster: Optional[Server]

    def __init__(self) -> None:
        super().__init__()
        self.server = None
        self.mutex = threading.RLock()
        self.cluster = None

    def create(
        self,
        arn: str,
        version: str,
        endpoint_options: Optional[DomainEndpointOptions] = None,
        security_options: Optional[SecurityOptions] = None,
        preferred_port: int = None,
    ) -> Server:
        with self.mutex:
            return super().create(arn, version, endpoint_options, security_options, preferred_port)

    def _create_cluster(
        self,
        arn: str,
        url: str,
        version: str,
        custom_endpoint: CustomEndpoint,
        security_options: SecurityOptions,
    ) -> Server:
        if not self.cluster:
            port = _get_port_from_url(url)
            engine_type = versions.get_engine_type(version)
            if engine_type == EngineType.OpenSearch:
                self.cluster = OpensearchCluster(
                    port=port,
                    host=config.GATEWAY_LISTEN[0].host,
                    version=version,
                    arn=arn,
                    security_options=security_options,
                )
            else:
                self.cluster = ElasticsearchCluster(
                    port=port,
                    host=LOCALHOST,
                    version=version,
                    arn=arn,
                    security_options=security_options,
                )

        return self.cluster

    def remove(self, arn: str):
        with self.mutex:
            try:
                cluster = self.clusters.pop(arn)
            except KeyError:
                return

            LOG.debug("removing cluster for %s, %s remaining", arn, len(self.clusters))
            if not self.clusters:
                # shutdown the cluster if it is
                cluster.shutdown()
                self.cluster = None


class CustomBackendManager(ClusterManager):
    def _create_cluster(
        self,
        arn: str,
        url: str,
        version: str,
        custom_endpoint: CustomEndpoint,
        security_options: SecurityOptions,
    ) -> Server:
        return FakeEndpointProxyServer(
            EndpointProxy(url, config.OPENSEARCH_CUSTOM_BACKEND, custom_endpoint)
        )
