from localstack import config
from localstack.utils.container_networking import (
    get_endpoint_for_network,
    get_main_container_network,
)

# IP address of main Docker container (lazily initialized)
DOCKER_MAIN_CONTAINER_IP = None
LAMBDA_CONTAINER_NETWORK = None


def get_main_endpoint_from_container() -> str:
    if config.HOSTNAME_FROM_LAMBDA:
        return config.HOSTNAME_FROM_LAMBDA
    return get_endpoint_for_network(network=get_main_container_network_for_lambda())


def get_main_container_network_for_lambda() -> str:
    global LAMBDA_CONTAINER_NETWORK
    if config.LAMBDA_DOCKER_NETWORK:
        return config.LAMBDA_DOCKER_NETWORK.split(",")[0]
    return get_main_container_network()


def get_all_container_networks_for_lambda() -> list[str]:
    global LAMBDA_CONTAINER_NETWORK
    if config.LAMBDA_DOCKER_NETWORK:
        return config.LAMBDA_DOCKER_NETWORK.split(",")
    return [get_main_container_network()]
