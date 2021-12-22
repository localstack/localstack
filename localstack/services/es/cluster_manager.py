import dataclasses
import logging
import threading
from typing import Dict, Optional

from botocore.utils import ArnParser

from localstack import config, constants
from localstack.constants import ELASTICSEARCH_DEFAULT_VERSION
from localstack.services.es import versions
from localstack.services.es.cluster import (
    CustomEndpoint,
    EdgeProxiedElasticsearchCluster,
    ElasticsearchCluster,
    ProxiedElasticsearchCluster,
    resolve_directories,
)
from localstack.services.generic_proxy import EndpointProxy, FakeEndpointProxyServer
from localstack.utils.common import call_safe, get_free_tcp_port, start_thread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)

ES_BASE_DOMAIN = f"es.{constants.LOCALHOST_HOSTNAME}"


def create_cluster_manager() -> "ClusterManager":
    if config.ES_CUSTOM_BACKEND:
        return CustomBackendManager()

    if config.ES_ENDPOINT_STRATEGY == "off" and not config.ES_MULTI_CLUSTER:
        return SingletonClusterManager()

    if config.ES_ENDPOINT_STRATEGY != "off":
        if config.ES_MULTI_CLUSTER:
            return MultiClusterManager()
        else:
            return MultiplexingClusterManager()

    raise ValueError(
        "cannot manage clusters with ES_ENDPOINT_STRATEGY=off and ES_MULTI_CLUSTER=True"
    )


@dataclasses.dataclass
class DomainKey:
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
            raise ValueError("not an elasticsearch arn: %s", arn)

        return DomainKey(
            domain_name=parsed["resource"][7:],  # strip 'domain/'
            region=parsed["region"],
            account=parsed["account"],
        )


def build_cluster_endpoint(
    domain_key: DomainKey, custom_endpoint: Optional[CustomEndpoint] = None
) -> str:
    """
    Builds the cluster endpoint from and optional custom_endpoint and the localstack elasticsearch config. Example
    values:

    - my-domain.us-east-1.es.localhost.localstack.cloud:4566 (endpoint strategy = domain (default))
    - localhost:4566/us-east-1/my-domain (endpoint strategy = path)
    - localhost:4751 (endpoint strategy = off)
    - my.domain:443/foo (arbitrary endpoints (technically not allowed by AWS, but there are no rules in localstack))
    """
    if custom_endpoint and custom_endpoint.enabled:
        return custom_endpoint.endpoint

    if config.ES_ENDPOINT_STRATEGY == "off":
        return "%s:%s" % (config.LOCALSTACK_HOSTNAME, config.PORT_ELASTICSEARCH)
    if config.ES_ENDPOINT_STRATEGY == "path":
        return "%s:%s/es/%s/%s" % (
            config.LOCALSTACK_HOSTNAME,
            config.EDGE_PORT,
            domain_key.region,
            domain_key.domain_name,
        )

    return f"{domain_key.domain_name}.{domain_key.region}.{ES_BASE_DOMAIN}:{config.EDGE_PORT}"


def determine_custom_endpoint(domain_endpoint_options: Dict) -> Optional[CustomEndpoint]:
    if not domain_endpoint_options:
        return

    custom_endpoint = domain_endpoint_options.get("CustomEndpoint")
    enabled = domain_endpoint_options.get("CustomEndpointEnabled", False)
    # TODO: other attributes (are they relevant?)
    #  - EnforceHTTPS: bool
    #  - TLSSecurityPolicy: str
    #  - CustomEndpointCertificateArn: str

    if not custom_endpoint:
        raise ValueError("Please provide the CustomEndpoint field to create a custom endpoint.")

    # TODO: validate custom_endpoint

    return CustomEndpoint(enabled, custom_endpoint)


class ClusterManager:
    clusters: Dict[str, Server]

    def __init__(self) -> None:
        self.clusters = {}

    def create(self, arn: str, create_domain_request: Dict) -> Server:
        version = versions.get_install_version(
            create_domain_request.get("ElasticsearchVersion") or ELASTICSEARCH_DEFAULT_VERSION
        )

        # determine custom domain endpoint
        endpoint_options = create_domain_request.get("DomainEndpointOptions")
        custom_endpoint = determine_custom_endpoint(endpoint_options)

        # build final endpoint and cluster url
        endpoint = build_cluster_endpoint(DomainKey.from_arn(arn), custom_endpoint)
        url = f"http://{endpoint}" if "://" not in endpoint else endpoint

        # call abstract cluster factory
        cluster = self._create_cluster(arn, url, version, create_domain_request)
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

    def _create_cluster(self, arn, url, version, create_domain_request) -> Server:
        """
        Abstract cluster factory.
        """
        raise NotImplementedError

    def shutdown_all(self):
        while self.clusters:
            domain, cluster = self.clusters.popitem()
            call_safe(cluster.shutdown)


class SingletonClusterManager(ClusterManager):
    """
    Manages a single cluster and always returns that cluster. Using this, we lie to the client about the the
    elasticsearch domain version. The first call to create_domain with a specific version will create the cluster
    with that version. Subsequent calls will believe they created a cluster with the version they specified. It keeps
    the cluster running until the last domain was removed. It only works with a single endpoint.

    Assumes the config:
    - ES_ENDPOINT_STRATEGY == "off"
    - ES_MULTI_CLUSTER == False
    """

    cluster: Optional[Server]

    def __init__(self) -> None:
        super().__init__()
        self.server = None
        self.mutex = threading.RLock()
        self.cluster = None

    def create(self, arn: str, create_domain_request: Dict) -> Server:
        with self.mutex:
            return super().create(arn, create_domain_request)

    def _create_cluster(self, arn, url, version, create_domain_request) -> Server:
        if not self.cluster:
            # FIXME: if remove() is called, then immediately after, create() (without letting time pass for the proxy to
            #  shut down) there's a chance that there will be a bind exception when trying to start the proxy again
            #  (which is currently always bound to PORT_ELASTICSEARCH)
            self.cluster = ProxiedElasticsearchCluster(
                port=config.PORT_ELASTICSEARCH,
                host=constants.LOCALHOST,
                version=version,
                directories=resolve_directories(version, arn),
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


class ClusterEndpoint(FakeEndpointProxyServer):
    """
    An endpoint that points to a cluster, and behaves like a Server.
    """

    def __init__(self, cluster: Server, endpoint: EndpointProxy) -> None:
        super().__init__(endpoint)
        self.cluster = cluster

    def health(self):
        return super().health() and self.cluster.health()


class MultiplexingClusterManager(ClusterManager):
    """
    Similar to SingletonClusterManager, but Multiplexes multiple endpoints to a single backend cluster.

    Assumes the config:
    - ES_ENDPOINT_STRATEGY != "off"
    - ES_MULTI_CLUSTER = False
    """

    cluster: Optional[Server]
    endpoints: Dict[str, ClusterEndpoint]

    def __init__(self) -> None:
        super().__init__()
        self.cluster = None
        self.endpoints = {}
        self.mutex = threading.RLock()

    def _create_cluster(self, arn, url, version, create_domain_request) -> Server:
        with self.mutex:
            if not self.cluster:
                # startup routine for the singleton cluster instance
                self.cluster = ElasticsearchCluster(
                    port=get_free_tcp_port(), directories=resolve_directories(version, arn)
                )

                def _start_async(*_):
                    LOG.info("starting %s on %s", type(self.cluster), self.cluster.url)
                    self.cluster.start()  # start may block during install

                start_thread(_start_async)

        return ClusterEndpoint(self.cluster, EndpointProxy(url, self.cluster.url))

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

    def _create_cluster(self, arn, url, version, create_domain_request) -> Server:
        return EdgeProxiedElasticsearchCluster(
            url, version, directories=resolve_directories(version, arn)
        )


class CustomBackendManager(ClusterManager):
    def _create_cluster(self, arn, url, version, create_domain_request) -> Server:
        return FakeEndpointProxyServer(EndpointProxy(url, config.ES_CUSTOM_BACKEND))
