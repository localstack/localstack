import json
from json import JSONDecodeError
from typing import Any, Final, Optional

from botocore.config import Config

from localstack.aws.api.lambda_ import InvocationResponse
from localstack.aws.connect import connect_externally_to
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.run import to_str
from localstack.utils.strings import to_bytes


class LambdaFunctionErrorException(Exception):
    function_error: Final[Optional[str]]
    payload: Final[str]

    def __init__(self, function_error: Optional[str], payload: str):
        self.function_error = function_error
        self.payload = payload


def exec_lambda_function(env: Environment, parameters: dict) -> None:
    lambda_client = connect_externally_to(config=Config(parameter_validation=False)).lambda_
    invocation_resp: InvocationResponse = lambda_client.invoke(**parameters)

    func_error: Optional[str] = invocation_resp.get("FunctionError")
    if func_error:
        payload = json.loads(to_str(invocation_resp["Payload"].read()))
        payload_str = json.dumps(payload, separators=(",", ":"))
        raise LambdaFunctionErrorException(func_error, payload_str)

    resp_payload = invocation_resp["Payload"].read()
    resp_payload_str = to_str(resp_payload)
    resp_payload_json: json = json.loads(resp_payload_str)
    resp_payload_value = resp_payload_json if resp_payload_json is not None else dict()
    invocation_resp["Payload"] = resp_payload_value

    response = select_from_typed_dict(typed_dict=InvocationResponse, obj=invocation_resp)
    env.stack.append(response)


def to_payload_type(payload: Any) -> Optional[bytes]:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        try:
            json.loads(payload)
            str_value = payload
        except JSONDecodeError:
            str_value = to_json_str(payload)
    else:
        str_value = to_json_str(payload)
    return to_bytes(str_value)
