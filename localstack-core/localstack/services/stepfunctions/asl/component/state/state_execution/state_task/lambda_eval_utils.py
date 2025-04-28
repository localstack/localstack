import json
from json import JSONDecodeError
from typing import IO, Any, Final, Optional, Union

from localstack.aws.api.lambda_ import InvocationResponse
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    StateCredentials,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.mock_eval_utils import (
    eval_mocked_response,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.mocking.mock_config import MockedResponse
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


def _mocked_invoke_lambda_function(env: Environment) -> InvocationResponse:
    mocked_response: MockedResponse = env.get_current_mocked_response()
    eval_mocked_response(env=env, mocked_response=mocked_response)
    invocation_resp: InvocationResponse = env.stack.pop()
    return invocation_resp


def _invoke_lambda_function(
    parameters: dict, region: str, state_credentials: StateCredentials
) -> InvocationResponse:
    lambda_client = boto_client_for(
        service="lambda", region=region, state_credentials=state_credentials
    )

    invocation_response: InvocationResponse = lambda_client.invoke(**parameters)

    payload = invocation_response["Payload"]
    payload_json = _from_payload(payload)
    invocation_response["Payload"] = payload_json

    return invocation_response


def execute_lambda_function_integration(
    env: Environment, parameters: dict, region: str, state_credentials: StateCredentials
) -> None:
    if env.is_mocked_mode():
        invocation_response: InvocationResponse = _mocked_invoke_lambda_function(env=env)
    else:
        invocation_response: InvocationResponse = _invoke_lambda_function(
            parameters=parameters, region=region, state_credentials=state_credentials
        )

    function_error: Optional[str] = invocation_response.get("FunctionError")
    if function_error:
        payload_json = invocation_response["Payload"]
        payload_str = json.dumps(payload_json, separators=(",", ":"))
        raise LambdaFunctionErrorException(function_error, payload_str)

    response = select_from_typed_dict(typed_dict=InvocationResponse, obj=invocation_response)  # noqa
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
