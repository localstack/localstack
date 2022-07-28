import logging
import os
from functools import lru_cache
from typing import Optional

from localstack import config
from localstack.utils.container_utils.container_client import ContainerException
from localstack.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


@lru_cache()
def get_main_container_network() -> Optional[str]:
    """
    Gets the main network of the LocalStack container (if we run in one, bridge otherwise)
    If there are multiple networks connected to the LocalStack container, we choose the first as "main" network

    :return: Network name
    """
    main_container_network = None
    try:
        if config.is_in_docker:
            networks = DOCKER_CLIENT.get_networks(get_main_container_name())
            main_container_network = networks[0]
        else:
            main_container_network = "bridge"  # use the default bridge network in case of host mode
        LOG.info("Determined main container network: %s", main_container_network)
    except Exception as e:
        container_name = get_main_container_name()
        LOG.info('Unable to get network name of main container "%s": %s', container_name, e)
    return main_container_network


@lru_cache()
def get_endpoint_for_network(network: Optional[str] = None) -> str:
    """
    Get the LocalStack endpoint (= IP address) on the given network.
    If a network is given, it will return the IP address/hostname of LocalStack on that network
    If omitted, it will return the IP address/hostname of the main container network
    This is a cached call, clear cache if networks might have changed

    :param network: Network to return the endpoint for
    :return: IP address or hostname of LS on the given network
    """
    container_name = get_main_container_name()
    network = network or get_main_container_network()
    main_container_ip = None
    try:
        if config.is_in_docker:
            main_container_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                container_name_or_id=container_name,
                container_network=network,
            )
        else:
            # default gateway for the network should be the host
            # (only under Linux - otherwise fall back to DOCKER_HOST_FROM_CONTAINER below)
            if config.is_in_linux:
                main_container_ip = DOCKER_CLIENT.inspect_network(network)["IPAM"]["Config"][0][
                    "Gateway"
                ]
        LOG.info("Determined main container target IP: %s", main_container_ip)
    except Exception as e:
        LOG.info('Unable to get IP address of main Docker container "%s": %s', container_name, e)
    # return (1) predefined endpoint host, or (2) main container IP, or (3) Docker host (e.g., bridge IP)
    return main_container_ip or config.DOCKER_HOST_FROM_CONTAINER


def get_main_container_ip():
    """
    Get the container IP address of the LocalStack container.
    Use get_endpoint_for network where possible, as it allows better control about which address to return

    :return: IP address of LocalStack container
    """
    container_name = get_main_container_name()
    return DOCKER_CLIENT.get_container_ip(container_name)


def get_main_container_id():
    """
    Return the container ID of the LocalStack container

    :return: container ID
    """
    container_name = get_main_container_name()
    try:
        return DOCKER_CLIENT.get_container_id(container_name)
    except ContainerException:
        return None


@lru_cache()
def get_main_container_name():
    """
    Returns the container name of the LocalStack container

    :return: LocalStack container name
    """
    hostname = os.environ.get("HOSTNAME")
    if hostname:
        try:
            return DOCKER_CLIENT.get_container_name(hostname)
        except ContainerException:
            return config.MAIN_CONTAINER_NAME
    else:
        return config.MAIN_CONTAINER_NAME
