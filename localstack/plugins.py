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
    from localstack.services.generic_proxy import ArnPartitionRewriteListener, ProxyListener

    ProxyListener.DEFAULT_LISTENERS.append(ArnPartitionRewriteListener())


@hooks.on_infra_start()
def patch_get_account_id():
    """Patch Moto's account ID resolver with our own."""
    from moto import core as moto_core
    from moto.core import models as moto_core_models

    from localstack.utils.accounts import get_default_account_id

    moto_core.account_id_resolver = get_default_account_id
    moto_core.ACCOUNT_ID = moto_core_models.ACCOUNT_ID = get_default_account_id()
