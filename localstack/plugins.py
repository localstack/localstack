from localstack import config

# Note: make sure not to add any additional imports at the global scope here!


def register_localstack_plugins():

    docker_flags = []

    # add Docker flags for edge ports
    for port in [config.EDGE_PORT, config.EDGE_PORT_HTTP]:
        if port:
            docker_flags += ["-p {p}:{p}".format(p=port)]

    result = {"docker": {"run_flags": " ".join(docker_flags)}}
    return result
