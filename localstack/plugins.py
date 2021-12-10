import logging

from localstack import config
from localstack.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.configure_localstack_container()
def configure_edge_port(container):
    ports = [config.EDGE_PORT, config.EDGE_PORT_HTTP]
    LOG.debug("configuring container with edge ports: %s", ports)
    for port in ports:
        if port:
            container.ports.add(port)


# Register the PartitionAdjustingProxyListener only if the feature flag is enabled
@hooks.on_infra_start(should_load=lambda: config.PARTITION_ADJUSTMENT)
def register_partition_adjusting_proxy_listener():
    LOG.info(
        "Registering PartitionAdjustingProxyListener to dynamically replace partitions in requests and responses."
    )
    from localstack.services.generic_proxy import PartitionAdjustingProxyListener, ProxyListener

    ProxyListener.DEFAULT_LISTENERS.append(PartitionAdjustingProxyListener())
