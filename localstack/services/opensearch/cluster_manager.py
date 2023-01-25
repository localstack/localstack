import dataclasses
import logging
import threading
from typing import Dict, List, Optional
from urllib.parse import urlparse

from botocore.utils import ArnParser
from werkzeug.routing import Rule

from localstack import config
from localstack.aws.api.opensearch import DomainEndpointOptions, EngineType
from localstack.config import EDGE_BIND_HOST
from localstack.constants import LOCALHOST, LOCALHOST_HOSTNAME
from localstack.http.proxy import ProxyHandler
from localstack.services.edge import ROUTER
from localstack.services.generic_proxy import FakeEndpointProxyServer
from localstack.services.infra import DEFAULT_BACKEND_HOST
from localstack.services.opensearch import versions
from localstack.services.opensearch.cluster import (
    CustomEndpoint,
    EdgeProxiedElasticsearchServer,
    EdgeProxiedOpensearchServer,
    ElasticsearchCluster,
    OpensearchCluster,
)
from localstack.utils.common import (
    PortNotAvailableException,
    call_safe,
    external_service_ports,
    get_free_tcp_port,
    start_thread,
)
from localstack.utils.serving import Server
from localstack.utils.sync import retry

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
        return f"arn:aws:es:{self.region}:{self.account}:domain/{self.domain_name}"

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
        endpoint_url = f"{config.LOCALSTACK_HOSTNAME}:{assigned_port}"
    elif config.OPENSEARCH_ENDPOINT_STRATEGY == "path":
        endpoint_url = f"{config.LOCALSTACK_HOSTNAME}:{config.EDGE_PORT}/{engine_domain}/{domain_key.region}/{domain_key.domain_name}"
    # or through a subdomain (domain-name.region.opensearch.localhost.localstack.cloud)
    else:
        endpoint_url = f"{domain_key.domain_name}.{domain_key.region}.{engine_domain}.{LOCALHOST_HOSTNAME}:{config.EDGE_PORT}"
    endpoint_url = f"http://{endpoint_url}" if "://" not in endpoint_url else endpoint_url
    return endpoint_url


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
        self.routing_rules = {}

    def create(
        self,
        arn: str,
        version: str,
        endpoint_options: Optional[DomainEndpointOptions] = None,
        preferred_port: Optional[int] = None,
    ) -> Server:
        """
        Creates a new cluster.

        :param arn: of the cluster to create
        :param version: of the cluster to start (string including the EngineType)
        :param endpoint_options: DomainEndpointOptions (may contain information about a custom endpoint url)
        :param preferred_port: port which should be preferred (only if OPENSEARCH_ENDPOINT_STRATEGY == "port")
        :return: None
        """

        # determine custom domain endpoint
        custom_endpoint = determine_custom_endpoint(endpoint_options)

        # determine engine type
        engine_type = versions.get_engine_type(version)

        url = build_cluster_endpoint(
            DomainKey.from_arn(arn), custom_endpoint, engine_type, preferred_port
        )
        # call abstract cluster factory
        cluster = self._create_cluster(arn=arn, url=url, version=version)
        cluster.start()

        # The assignment of the final port can take some time
        def wait_for_cluster():
            port = self._cluster_port
            # if not hasattr(cluster, "cluster_port"):
            #     return cluster.port
            # port = cluster.cluster_port
            if not port:
                raise Exception("Port for cluster could not be determined")
            return port

        # save cluster into registry
        self.clusters[arn] = cluster
        url = urlparse(url)
        cluster_port = retry(wait_for_cluster, retries=10, sleep=0.1)
        self.routing_rules[arn] = self.register_cluster(
            host=url.hostname,
            path=url.path,
            cluster_port=cluster_port,
            custom_endpoint=custom_endpoint,
        )

        return cluster

    def register_cluster(self, host, path, cluster_port: int, custom_endpoint) -> List[Rule]:
        # custom backends overwrite
        forward_url = (
            config.OPENSEARCH_CUSTOM_BACKEND or f"http://{DEFAULT_BACKEND_HOST}:{cluster_port}"
        )
        endpoint = ProxyHandler(forward_url)
        rules = []
        # custom endpoints override any endpoint strategy
        if custom_endpoint:
            LOG.debug(f"Registering route from {host}{path} to {endpoint.proxy.forward_base_url}")
            assert not (
                host == config.LOCALSTACK_HOSTNAME and (not path or path == "/")
            ), "trying to register an illegal catch all route"
            rules.append(
                ROUTER.add(
                    path=path,
                    endpoint=endpoint,
                    host=f'{host}<regex("(:.*)?"):port>',
                )
            )
            rules.append(
                ROUTER.add(
                    f"{path}/<path:path>",
                    endpoint=endpoint,
                    host=f'{host}<regex("(:.*)?"):port>',
                )
            )
        else:
            match config.OPENSEARCH_ENDPOINT_STRATEGY:
                case "domain":
                    LOG.debug(f"Registering route from {host} to {endpoint.proxy.forward_base_url}")
                    assert (
                        not host == config.LOCALSTACK_HOSTNAME
                    ), "trying to register an illegal catch all route"
                    rules.append(
                        ROUTER.add(
                            "/",
                            endpoint=endpoint,
                            host=f"{host}<regex('(:.*)?'):port>",
                        )
                    )
                    rules.append(
                        ROUTER.add(
                            "/<path:path>",
                            endpoint=endpoint,
                            host=f"{host}<regex('(:.*)?'):port>",
                        )
                    )
                case "path":
                    LOG.debug(f"Registering route from {path} to {endpoint.proxy.forward_base_url}")
                    assert path and not path == "/", "trying to register an illegal catch all route"
                    rules.append(ROUTER.add(path, endpoint=endpoint))
                    rules.append(ROUTER.add(f"{path}/<path:path>", endpoint=endpoint))

                case "port":
                    # port strategy exposes clusters directly, nothing to route
                    pass

        return rules

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

    def _create_cluster(self, arn: str, url: str, version: str) -> Server:
        """
        Abstract cluster factory.

        :param version: the full prefixed version, e.g. "OpenSearch_1.0" or "Elasticsearch_7.10"
        """
        raise NotImplementedError

    @property
    def _cluster_port(self):
        raise NotImplementedError

    def shutdown_all(self):
        while self.clusters:
            domain, cluster = self.clusters.popitem()
            call_safe(cluster.shutdown)


class ClusterEndpoint(FakeEndpointProxyServer):
    """
    An endpoint that points to a cluster, and behaves like a Server.
    """

    def __init__(self, base_url: str, cluster: Server) -> None:
        super().__init__(base_url, cluster.url)
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

    @property
    def _cluster_port(self):
        return self.cluster.port

    def _create_cluster(self, arn: str, url: str, version: str) -> Server:
        with self.mutex:
            engine_type = versions.get_engine_type(version)
            if not self.cluster:
                # startup routine for the singleton cluster instance
                if engine_type == EngineType.OpenSearch:
                    self.cluster = OpensearchCluster(port=get_free_tcp_port(), arn=arn)
                else:
                    self.cluster = ElasticsearchCluster(port=get_free_tcp_port(), arn=arn)

                def _start_async(*_):
                    LOG.info("starting %s on %s", type(self.cluster), self.cluster.url)
                    self.cluster.start()  # start may block during install

                start_thread(_start_async, name="opensearch-multiplex")
            cluster_endpoint = ClusterEndpoint(
                url,
                self.cluster,
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

    @property
    def _cluster_port(self):
        if config.OPENSEARCH_ENDPOINT_STRATEGY == "port":
            return self.cluster.port
        else:
            return self.cluster.cluster_port

    def _create_cluster(self, arn: str, url: str, version: str) -> Server:
        engine_type = versions.get_engine_type(version)
        if config.OPENSEARCH_ENDPOINT_STRATEGY != "port":
            if engine_type == EngineType.OpenSearch:
                self.cluster = EdgeProxiedOpensearchServer(
                    url=url,
                    arn=arn,
                    version=version,
                )
            else:
                self.cluster = EdgeProxiedElasticsearchServer(
                    url=url,
                    arn=arn,
                    version=version,
                )
        else:
            port = _get_port_from_url(url)
            if engine_type == EngineType.OpenSearch:
                self.cluster = OpensearchCluster(
                    port=port, host=EDGE_BIND_HOST, arn=arn, version=version
                )
            else:
                self.cluster = ElasticsearchCluster(
                    port=port, host=EDGE_BIND_HOST, arn=arn, version=version
                )

        return self.cluster


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
        preferred_port: int = None,
    ) -> Server:
        with self.mutex:
            return super().create(arn, version, endpoint_options, preferred_port)

    @property
    def _cluster_port(self):
        return self.cluster.port

    def _create_cluster(self, arn: str, url: str, version: str) -> Server:
        if not self.cluster:
            port = _get_port_from_url(url)
            engine_type = versions.get_engine_type(version)
            if engine_type == EngineType.OpenSearch:
                self.cluster = OpensearchCluster(
                    port=port, host=EDGE_BIND_HOST, version=version, arn=arn
                )
            else:
                self.cluster = ElasticsearchCluster(
                    port=port, host=LOCALHOST, version=version, arn=arn
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
    def _create_cluster(self, arn: str, url: str, version: str) -> Server:
        self.cluster = FakeEndpointProxyServer(
            url,
            config.OPENSEARCH_CUSTOM_BACKEND,
        )
        return self.cluster

    def _cluster_port(self):
        return self.cluster.port
