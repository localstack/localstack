from localstack import config
from localstack.services.infra import start_local_api


def start_elasticsearch_service(port=None, asynchronous=False):
    """
    Starts the ElasticSearch management API (not the actual elasticsearch process.
    """
    from localstack.services.es import es_api

    port = port or config.PORT_ES
    return start_local_api("ES", port, api="es", method=es_api.serve, asynchronous=asynchronous)
