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


# Register the PartitionAdjustingProxyListener only if the default region is a region in the AWS GovCloud partition
@hooks.on_infra_start(should_load=lambda: config.DEFAULT_REGION.startswith("us-gov-"))
def register_partition_adjusting_proxy_listener():
    LOG.info(
        "Registering PartitionAdjustingProxyListener to dynamically replace partitions in requests and responses."
    )
    from localstack.services.generic_proxy import PartitionAdjustingProxyListener, ProxyListener

    ProxyListener.DEFAULT_LISTENERS.append(PartitionAdjustingProxyListener())
