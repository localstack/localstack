import json
from typing import Final, Optional

from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import InvocationRequest, InvocationResponse, InvocationType
from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    LambdaFunctionFailedEventDetails,
    LambdaFunctionScheduledEventDetails,
    LambdaFunctionSucceededEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    LambdaResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.aws.aws_stack import connect_to_service
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import to_bytes, to_str


class LambdaFunctionErrorException(Exception):
    function_error: Final[Optional[str]]
    payload: Final[str]

    def __init__(self, function_error: Optional[str], payload: str):
        self.function_error = function_error
        self.payload = payload


class StateTaskLambda(StateTask):
    resource: LambdaResource

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        error = "Exception"
        if isinstance(ex, LambdaFunctionErrorException):
            error_name = CustomErrorName(error)
            cause = ex.payload
        elif isinstance(ex, ClientError):
            error_name = CustomErrorName(error)
            cause = ex.response["Error"]["Message"]
        else:
            error_name = StatesErrorName(StatesErrorNameType.StatesTaskFailed)
            cause = str(ex)

        return FailureEvent(
            error_name=error_name,
            event_type=HistoryEventType.LambdaFunctionFailed,
            event_details=EventDetails(
                lambdaFunctionFailedEventDetails=LambdaFunctionFailedEventDetails(
                    error=error,
                    cause=cause,
                )
            ),
        )

    def _exec_lambda_function(self, env: Environment) -> None:
        # TODO: check type? input (file) path as lm input? raw binary inputs? always json?
        tmp = env.stack.pop()

        parameters: InvocationRequest = dict()
        parameters["FunctionName"] = self.resource.resource_arn
        parameters["Payload"] = to_bytes(json.dumps(tmp))  # TODO: IO[bytes]
        parameters["InvocationType"] = InvocationType.RequestResponse
        if self.parameters:
            self.parameters.eval(env=env)
            gen_parameters: dict = env.stack.pop()

            parameters.update(gen_parameters)
            p_payload = parameters["Payload"]
            if not isinstance(p_payload, bytes):
                if not isinstance(p_payload, str):
                    p_payload = json.dumps(p_payload)
                parameters["Payload"] = to_bytes(p_payload)  # TODO: IO[bytes]

        # TODO: check for type and support other types.
        lambda_client = connect_to_service("lambda")
        invocation_resp: InvocationResponse = lambda_client.invoke(**parameters)

        func_error: Optional[str] = invocation_resp.get("FunctionError")
        if func_error:
            payload = json.loads(to_str(invocation_resp["Payload"].read()))
            payload_str = json.dumps(payload, separators=(",", ":"))
            raise LambdaFunctionErrorException(func_error, payload_str)

        # TODO: supported response types?
        resp_payload = invocation_resp["Payload"].read()
        resp_payload_str = to_str(resp_payload)
        resp_payload_json: json = json.loads(resp_payload_str) or dict()
        if resp_payload_json:
            resp_payload_json.pop("ResponseMetadata", None)
        invocation_resp["Payload"] = resp_payload_json

        response = select_from_typed_dict(typed_dict=InvocationResponse, obj=invocation_resp)
        env.stack.append(response)

    def _eval_execution(self, env: Environment) -> None:
        env.event_history.add_event(
            hist_type_event=HistoryEventType.LambdaFunctionScheduled,
            event_detail=EventDetails(
                lambdaFunctionScheduledEventDetails=LambdaFunctionScheduledEventDetails(
                    resource=self.resource.resource_arn,
                    input=to_json_str(env.inp),
                    inputDetails=HistoryEventExecutionDataDetails(
                        truncated=False  # Always False for api calls.
                    ),
                )
            ),
        )
        env.event_history.add_event(
            hist_type_event=HistoryEventType.LambdaFunctionStarted,
            event_detail=EventDetails(),
        )

        self._exec_lambda_function(env=env)

        # In lambda invocations, only payload is passed on as output.
        output = env.stack.pop()
        output_payload = output["Payload"]
        env.stack.append(output_payload)

        env.event_history.add_event(
            hist_type_event=HistoryEventType.LambdaFunctionSucceeded,
            event_detail=EventDetails(
                lambdaFunctionSucceededEventDetails=LambdaFunctionSucceededEventDetails(
                    output=to_json_str(output_payload),
                    outputDetails=HistoryEventExecutionDataDetails(
                        truncated=False  # Always False for api calls.
                    ),
                )
            ),
        )
