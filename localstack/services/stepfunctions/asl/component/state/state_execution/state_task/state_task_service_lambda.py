import json
from typing import Optional

from localstack.aws.api.lambda_ import InvocationRequest, InvocationResponse, InvocationType
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.aws.aws_stack import connect_to_service
from localstack.utils.strings import to_bytes, to_str


class StateTaskServiceLambda(StateTaskService):
    def _to_error_name(self, ex: Exception) -> ErrorName:
        # TODO: reduce to correct invocation error.
        return CustomErrorName("Lambda.Unknown")

    def _eval_execution(self, env: Environment) -> None:
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
            raise Exception(func_error)

        # TODO: supported response types?
        resp_payload = invocation_resp["Payload"].read()
        resp_payload_str = to_str(resp_payload)
        resp_payload_json: json = json.loads(resp_payload_str)
        resp_payload_json.pop("ResponseMetadata", None)

        env.stack.append(resp_payload_json)
