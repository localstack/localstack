import json
from json import JSONDecodeError
from typing import IO, Any, Final, Optional, Union

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


def _from_payload(payload_streaming_body: IO[bytes]) -> Union[json, str]:
    """
    This method extracts the lambda payload. The payload may be a string or a JSON stringified object.
    In the first case, this function converts the output into a UTF-8 string, otherwise it parses the
    JSON string into a JSON object.
    """

    payload_bytes: bytes = payload_streaming_body.read()
    decoded_data: str = payload_bytes.decode("utf-8")
    try:
        json_data: json = json.loads(decoded_data)
        return json_data
    except (UnicodeDecodeError, json.JSONDecodeError):
        return decoded_data


def exec_lambda_function(env: Environment, parameters: dict, region: str, account: str) -> None:
    lambda_client = boto_client_for(region=region, account=account, service="lambda")

    invocation_resp: InvocationResponse = lambda_client.invoke(**parameters)

    func_error: Optional[str] = invocation_resp.get("FunctionError")

    payload = invocation_resp["Payload"]
    payload_json = _from_payload(payload)
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
