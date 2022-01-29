from localstack import config
from localstack.services.cloudformation import cloudformation_api
from localstack.services.infra import start_local_api


def start_cloudformation(port=None, asynchronous=False):
    port = port or config.service_port("cloudformation")
    return start_local_api(
        "CloudFormation",
        port,
        api="cloudformation",
        method=cloudformation_api.serve,
        asynchronous=asynchronous,
    )
