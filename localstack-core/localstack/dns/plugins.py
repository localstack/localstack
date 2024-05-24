import logging

from localstack import config
from localstack.runtime import hooks

LOG = logging.getLogger(__name__)

# Note: Don't want to introduce a possible import order conflict by importing SERVICE_SHUTDOWN_PRIORITY
# TODO: consider extracting these priorities into some static configuration
DNS_SHUTDOWN_PRIORITY = -30
"""Make sure the DNS server is shut down after the ON_AFTER_SERVICE_SHUTDOWN_HANDLERS, which in turn is after
SERVICE_SHUTDOWN_PRIORITY. Currently this value needs to be less than -20"""


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


@hooks.on_infra_shutdown(priority=DNS_SHUTDOWN_PRIORITY)
def stop_server():
    try:
        from localstack.dns import server

        server.revert_network_configuration()
        server.stop_servers()
    except Exception as e:
        LOG.warning("Unable to stop DNS servers: %s", e)
