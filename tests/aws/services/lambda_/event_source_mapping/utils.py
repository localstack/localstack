_LAMBDA_WITH_RESPONSE = """
import json

def handler(event, context):
    print(json.dumps(event))
    return {response}
"""


def create_lambda_with_response(response: str) -> str:
    """Creates a lambda with pre-defined response"""
    return _LAMBDA_WITH_RESPONSE.format(response=response)
