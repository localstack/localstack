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


# Register the ArnPartitionRewriteListener only if the feature flag is enabled
@hooks.on_infra_start(should_load=lambda: config.ARN_PARTITION_REWRITING)
def register_partition_adjusting_proxy_listener():
    LOG.info(
        "Registering ArnPartitionRewriteListener to dynamically replace partitions in requests and responses."
    )
    from localstack.aws import handlers
    from localstack.aws.handlers.partition_rewriter import ArnPartitionRewriteHandler

    handlers.preprocess_request.append(ArnPartitionRewriteHandler())


@hooks.on_infra_start()
def deprecation_warnings() -> None:
    LOG.debug("Checking for the usage of deprecated community features and configs...")
    from localstack.deprecations import log_deprecation_warnings

    log_deprecation_warnings()
