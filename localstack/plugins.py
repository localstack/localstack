import os

from localstack import config
from localstack.constants import TRUE_STRINGS
from localstack.utils.bootstrap import ENV_SCRIPT_STARTING_DOCKER

# Note: make sure not to add any additional imports at the global scope here!


def register_localstack_plugins():
    # skip loading plugins for Docker launching, to increase startup speed
    if os.environ.get(ENV_SCRIPT_STARTING_DOCKER) not in TRUE_STRINGS:
        do_register_localstack_plugins()

    docker_flags = []

    # add Docker flags for edge ports
    for port in [config.EDGE_PORT, config.EDGE_PORT_HTTP]:
        if port:
            docker_flags += ["-p {p}:{p}".format(p=port)]

    result = {"docker": {"run_flags": " ".join(docker_flags)}}
    return result


def do_register_localstack_plugins():
    pass
