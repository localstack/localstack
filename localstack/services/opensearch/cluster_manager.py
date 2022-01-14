import dataclasses
import logging
import threading
from typing import Dict, Optional

from botocore.utils import ArnParser

from localstack import config, constants
from localstack.aws.api.opensearch import DomainEndpointOptions
from localstack.services.generic_proxy import EndpointProxy, FakeEndpointProxyServer
from localstack.services.opensearch import versions
from localstack.services.opensearch.cluster import (
    CustomEndpoint,
    EdgeProxiedOpensearchCluster,
    OpensearchCluster,
    resolve_directories,
)
from localstack.utils.common import call_safe, get_free_tcp_port, start_thread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)

OPENSEARCH_BASE_DOMAIN = f"opensearch.{constants.LOCALHOST_HOSTNAME}"


def create_cluster_manager() -> "ClusterManager":
    """Creates the cluster manager according to the configuration."""

    # If we have an external cluster, we always use the CustomBackendManager.
    if config.OPENSEARCH_CUSTOM_BACKEND:
        return CustomBackendManager()

    # If we are using a localstack-managed multi-cluster-setup, we use the MultiClusterManager.
    if config.OPENSEARCH_MULTI_CLUSTER:
        return MultiClusterManager()
    else:
        # Otherwise, if we are using a localstack-managed multiplexing-to-a-single-cluster-setup,
        # we use the MultiplexingClusterManager.
        return MultiplexingClusterManager()


@dataclasses.dataclass
class DomainKey:
    """Uniquely identifies an OpenSearch domain."""

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
            raise ValueError("not an opensearch arn: %s", arn)

        return DomainKey(
            domain_name=parsed["resource"][7:],  # strip 'domain/'
            region=parsed["region"],
            account=parsed["account"],
        )


def build_cluster_endpoint(
    domain_key: DomainKey, custom_endpoint: Optional[CustomEndpoint] = None
) -> str:
    """
    Builds the cluster endpoint from and optional custom_endpoint and the localstack opensearch config. Example
    values:

    - my-domain.us-east-1.opensearch.localhost.localstack.cloud:4566 (endpoint strategy = domain (default))
    - localhost:4566/us-east-1/my-domain (endpoint strategy = path)
    - my.domain:443/foo (arbitrary endpoints (technically not allowed by AWS, but there are no rules in localstack))
    """
    # If we have a CustomEndpoint, we directly take its endpoint.
    if custom_endpoint and custom_endpoint.enabled:
        return custom_endpoint.endpoint

    # Otherwise, the endpoint is either routed through the edge proxy via a sub-path (localhost:4566/opensearch/...)
    if config.OPENSEARCH_ENDPOINT_STRATEGY == "path":
        return "%s:%s/opensearch/%s/%s" % (
            config.LOCALSTACK_HOSTNAME,
            config.EDGE_PORT,
            domain_key.region,
            domain_key.domain_name,
        )
    # or through a subdomain (domain-name.region.opensearch.localhost.localstack.cloud)
    return (
        f"{domain_key.domain_name}.{domain_key.region}.{OPENSEARCH_BASE_DOMAIN}:{config.EDGE_PORT}"
    )


def determine_custom_endpoint(
    domain_endpoint_options: DomainEndpointOptions,
) -> Optional[CustomEndpoint]:
    if not domain_endpoint_options:
        return

    custom_endpoint = domain_endpoint_options.get("CustomEndpoint")
    enabled = domain_endpoint_options.get("CustomEndpointEnabled", False)

    if not custom_endpoint:
        raise ValueError("Please provide the CustomEndpoint field to create a custom endpoint.")

    return CustomEndpoint(enabled, custom_endpoint)


class ClusterManager:
    clusters: Dict[str, Server]

    def __init__(self) -> None:
        self.clusters = dict()

    def create(self, arn: str, version: str, endpoint_options=None) -> Server:
        version = versions.get_install_version(version)

        # determine custom domain endpoint
        custom_endpoint = determine_custom_endpoint(endpoint_options)

        # build final endpoint and cluster url
        endpoint = build_cluster_endpoint(DomainKey.from_arn(arn), custom_endpoint)
        url = f"http://{endpoint}" if "://" not in endpoint else endpoint

        # call abstract cluster factory
        cluster = self._create_cluster(arn, url, version)
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

    def _create_cluster(self, arn, url, version) -> Server:
        """
        Abstract cluster factory.
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


class MultiplexingClusterManager(ClusterManager):
    """
    Multiplexes multiple endpoints to a single backend cluster (not managed by LocalStack).
    Using this, we lie to the client about the opensearch domain version.
    It only works with a single endpoint.

    Assumes the config:
    - OPENSEARCH_MULTI_CLUSTER = False
    """

    cluster: Optional[Server]
    endpoints: Dict[str, ClusterEndpoint]

    def __init__(self) -> None:
        super().__init__()
        self.cluster = None
        self.endpoints = dict()
        self.mutex = threading.RLock()

    def _create_cluster(self, arn, url, version) -> Server:
        with self.mutex:
            if not self.cluster:
                # startup routine for the singleton cluster instance
                self.cluster = OpensearchCluster(
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

    def _create_cluster(self, arn, url, version) -> Server:
        return EdgeProxiedOpensearchCluster(
            url, version, directories=resolve_directories(version, arn)
        )


class CustomBackendManager(ClusterManager):
    def _create_cluster(self, arn, url, version) -> Server:
        return FakeEndpointProxyServer(EndpointProxy(url, config.OPENSEARCH_CUSTOM_BACKEND))
