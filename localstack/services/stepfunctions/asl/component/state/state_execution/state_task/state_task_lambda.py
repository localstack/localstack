from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import InvocationRequest, InvocationType
from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    LambdaFunctionFailedEventDetails,
    LambdaFunctionScheduledEventDetails,
    LambdaFunctionSucceededEventDetails,
    LambdaFunctionTimedOutEventDetails,
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task import (
    lambda_eval_utils,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    LambdaResource,
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class StateTaskLambda(StateTask):
    resource: LambdaResource

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, TimeoutError):
            return FailureEvent(
                env=env,
                error_name=StatesErrorName(typ=StatesErrorNameType.StatesTimeout),
                event_type=HistoryEventType.LambdaFunctionTimedOut,
                event_details=EventDetails(
                    lambdaFunctionTimedOutEventDetails=LambdaFunctionTimedOutEventDetails(
                        error=StatesErrorNameType.StatesTimeout.to_name(),
                    )
                ),
            )

        error = "Exception"
        if isinstance(ex, lambda_eval_utils.LambdaFunctionErrorException):
            error_name = CustomErrorName(error)
            cause = ex.payload
        elif isinstance(ex, ClientError):
            error_name = CustomErrorName(error)
            cause = ex.response["Error"]["Message"]
        else:
            error_name = StatesErrorName(StatesErrorNameType.StatesTaskFailed)
            cause = str(ex)

        return FailureEvent(
            env=env,
            error_name=error_name,
            event_type=HistoryEventType.LambdaFunctionFailed,
            event_details=EventDetails(
                lambdaFunctionFailedEventDetails=LambdaFunctionFailedEventDetails(
                    error=error,
                    cause=cause,
                )
            ),
        )

    def _eval_parameters(self, env: Environment) -> dict:
        if self.parameters:
            self.parameters.eval(env=env)
        payload = env.stack.pop()
        parameters = InvocationRequest(
            FunctionName=self.resource.resource_arn,
            InvocationType=InvocationType.RequestResponse,
            Payload=payload,
        )
        return parameters

    def _eval_execution(self, env: Environment) -> None:
        parameters = self._eval_parameters(env=env)
        payload = parameters["Payload"]

        scheduled_event_details = LambdaFunctionScheduledEventDetails(
            resource=self.resource.resource_arn,
            input=to_json_str(payload),
            inputDetails=HistoryEventExecutionDataDetails(
                truncated=False  # Always False for api calls.
            ),
        )
        if not self.timeout.is_default_value():
            self.timeout.eval(env=env)
            timeout_seconds = env.stack.pop()
            scheduled_event_details["timeoutInSeconds"] = timeout_seconds
        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.LambdaFunctionScheduled,
            event_detail=EventDetails(lambdaFunctionScheduledEventDetails=scheduled_event_details),
        )

        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.LambdaFunctionStarted,
        )

        self.resource.eval(env=env)
        resource_runtime_part: ResourceRuntimePart = env.stack.pop()

        parameters["Payload"] = lambda_eval_utils.to_payload_type(parameters["Payload"])
        lambda_eval_utils.exec_lambda_function(
            env=env,
            parameters=parameters,
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
        )

        # In lambda invocations, only payload is passed on as output.
        output = env.stack.pop()
        output_payload = output["Payload"]
        env.stack.append(output_payload)

        env.event_history.add_event(
            context=env.event_history_context,
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
