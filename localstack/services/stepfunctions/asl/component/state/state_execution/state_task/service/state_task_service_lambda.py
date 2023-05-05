from localstack.aws.api.stepfunctions import (
    HistoryEventType,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_lambda import (
    StateTaskLambda,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class StateTaskServiceLambda(StateTaskService, StateTaskLambda):
    def _get_resource_type(self) -> str:
        return "lambda"

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        failure_event: FailureEvent = super()._from_error(env=env, ex=ex)
        event_details: EventDetails = failure_event.event_details
        if "taskFailedEventDetails" in event_details:
            task_failed_details: TaskStartedEventDetails = event_details["taskFailedEventDetails"]
            task_failed_details["resourceType"] = self._get_resource_type()
            task_failed_details["resource"] = self.resource.api_action
        return failure_event

    def _eval_execution(self, env: Environment) -> None:
        parameters = self._eval_parameters(env=env)
        parameters_str = to_json_str(parameters)
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskScheduled,
            event_detail=EventDetails(
                taskScheduledEventDetails=TaskScheduledEventDetails(
                    resourceType=self._get_resource_type(),
                    resource=self.resource.api_action,
                    region=self.resource.region,
                    parameters=parameters_str,
                )
            ),
        )
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskStarted,
            event_detail=EventDetails(
                taskStartedEventDetails=TaskStartedEventDetails(
                    resourceType=self._get_resource_type(),
                    resource=self.resource.api_action,
                )
            ),
        )
        super()._eval_execution(env=env)
