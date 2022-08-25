import json
from typing import Literal

from localstack.utils.common import to_str
from localstack.utils.generic.wait_utils import ShortCircuitWaitException


def update_done(client, function_name):
    """wait fn for checking 'LastUpdateStatus' of lambda"""

    def _update_done():
        last_update_status = client.get_function_configuration(FunctionName=function_name)[
            "LastUpdateStatus"
        ]
        if last_update_status == "Failed":
            raise ShortCircuitWaitException(f"Lambda Config update failed: {last_update_status=}")
        else:
            return last_update_status == "Successful"

    return _update_done


def concurrency_update_done(client, function_name, qualifier):
    """wait fn for ProvisionedConcurrencyConfig 'Status'"""

    def _concurrency_update_done():
        status = client.get_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=qualifier
        )["Status"]
        if status == "FAILED":
            raise ShortCircuitWaitException(f"Concurrency update failed: {status=}")
        else:
            return status == "READY"

    return _concurrency_update_done


def get_invoke_init_type(
    client, function_name, qualifier
) -> Literal["on-demand", "provisioned-concurrency"]:
    """check the environment in the lambda for AWS_LAMBDA_INITIALIZATION_TYPE indicating ondemand/provisioned"""
    invoke_result = client.invoke(FunctionName=function_name, Qualifier=qualifier)
    return json.loads(to_str(invoke_result["Payload"].read()))["env"][
        "AWS_LAMBDA_INITIALIZATION_TYPE"
    ]
