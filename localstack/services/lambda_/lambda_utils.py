"""Lambda utilities for behavior and implicit functionality.
Everything related to API operations goes into `api_utils.py`.
"""
import logging
import os

from localstack.aws.api.lambda_ import Runtime

# Custom logger for proactive deprecation hints related to the migration from the old to the new lambda provider
HINT_LOG = logging.getLogger("localstack.services.lambda_.hints")


def get_handler_file_from_name(handler_name: str, runtime: str = None):
    # Previously used DEFAULT_LAMBDA_RUNTIME here but that is only relevant for testing and this helper is still used in
    # a CloudFormation model in localstack.services.cloudformation.models.lambda_.LambdaFunction.get_lambda_code_param
    runtime = runtime or Runtime.python3_9

    # TODO: consider using localstack/testing/aws/lambda_utils.py:RUNTIMES_AGGREGATED for testing or moving the constant
    #   RUNTIMES_AGGREGATED to LocalStack core if this helper remains relevant within CloudFormation.
    if runtime.startswith(Runtime.provided):
        return "bootstrap"
    if runtime.startswith("nodejs"):
        return format_name_to_path(handler_name, ".", ".js")
    if runtime.startswith(Runtime.go1_x):
        return handler_name
    if runtime.startswith("dotnet"):
        return format_name_to_path(handler_name, ":", ".dll")
    if runtime.startswith("ruby"):
        return format_name_to_path(handler_name, ".", ".rb")

    return format_name_to_path(handler_name, ".", ".py")


def format_name_to_path(handler_name: str, delimiter: str, extension: str):
    file_path = handler_name.rpartition(delimiter)[0]
    if delimiter == ":":
        file_path = file_path.split(delimiter)[0]

    if os.path.sep not in file_path:
        file_path = file_path.replace(".", os.path.sep)

    if file_path.startswith(f".{os.path.sep}"):
        file_path = file_path[2:]

    return f"{file_path}{extension}"
