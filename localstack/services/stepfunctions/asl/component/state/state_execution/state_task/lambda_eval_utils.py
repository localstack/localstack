import json
from json import JSONDecodeError
from typing import Any, Final, Optional

from localstack.aws.api.lambda_ import InvocationResponse
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import to_bytes


class LambdaFunctionErrorException(Exception):
    function_error: Final[Optional[str]]
    payload: Final[str]

    def __init__(self, function_error: Optional[str], payload: str):
        self.function_error = function_error
        self.payload = payload


def exec_lambda_function(env: Environment, parameters: dict, region: str, account: str) -> None:
    lambda_client = boto_client_for(region=region, account=account, service="lambda")

    invocation_resp: InvocationResponse = lambda_client.invoke(**parameters)

    func_error: Optional[str] = invocation_resp.get("FunctionError")
    payload_json = json.load(invocation_resp["Payload"])
    if func_error:
        payload_str = json.dumps(payload_json, separators=(",", ":"))
        raise LambdaFunctionErrorException(func_error, payload_str)

    invocation_resp["Payload"] = payload_json

    response = select_from_typed_dict(typed_dict=InvocationResponse, obj=invocation_resp)
    env.stack.append(response)


def to_payload_type(payload: Any) -> Optional[bytes]:
    if isinstance(payload, bytes):
        return payload

    if payload is None:
        str_value = to_json_str(dict())
    elif isinstance(payload, str):
        try:
            json.loads(payload)
            str_value = payload
        except JSONDecodeError:
            str_value = to_json_str(payload)
    else:
        str_value = to_json_str(payload)
    return to_bytes(str_value)
