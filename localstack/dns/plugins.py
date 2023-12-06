import logging

from localstack import config
from localstack.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start(priority=10)
def start_dns_server():
    try:
        from localstack.dns import server

        server.start_dns_server(port=config.DNS_PORT, asynchronous=True)
    except Exception as e:
        LOG.warning("Unable to start DNS: %s", e)


@hooks.on_infra_start()
def setup_dns_configuration_on_host():
    try:
        from localstack.dns import server

        if server.is_server_running():
            # Prepare network interfaces for DNS server for the infra.
            server.setup_network_configuration()
    except Exception as e:
        LOG.warning("error setting up dns server: %s", e)
