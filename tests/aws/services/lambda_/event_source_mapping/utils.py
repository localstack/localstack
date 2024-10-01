from localstack.config import LAMBDA_EVENT_SOURCE_MAPPING
from localstack.testing.aws.util import is_aws_cloud

_LAMBDA_WITH_RESPONSE = """
import json

def handler(event, context):
    print(json.dumps(event))
    return {response}
"""


def create_lambda_with_response(response: str) -> str:
    """Creates a lambda with pre-defined response"""
    return _LAMBDA_WITH_RESPONSE.format(response=response)


def is_v2_esm():
    return LAMBDA_EVENT_SOURCE_MAPPING == "v2" and not is_aws_cloud()


def is_old_esm():
    return LAMBDA_EVENT_SOURCE_MAPPING == "v1" and not is_aws_cloud()
