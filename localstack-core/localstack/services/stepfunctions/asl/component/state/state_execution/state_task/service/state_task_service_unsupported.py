import logging

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for

LOG = logging.getLogger(__name__)


class StateTaskServiceUnsupported(StateTaskServiceCallback):
    def _log_unsupported_warning(self):
        # Logs that the optimised service integration is not supported,
        # however the request is being forwarded to the service.
        service_name = self._get_boto_service_name()
        resource_arn = self.resource.resource_arn
        LOG.warning(
            f"Unsupported Optimised service integration for service_name '{service_name}' "
            f"in resource: '{resource_arn}'."
            "Attempting to forward request to service."
        )

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        # Logs that the evaluation of this optimised service integration is not supported
        # and relays the call to the target service with the computed parameters.
        self._log_unsupported_warning()
        service_name = self._get_boto_service_name()
        boto_action = self._get_boto_service_action()
        boto_client = boto_client_for(
            region=resource_runtime_part.region,
            account=resource_runtime_part.account,
            service=service_name,
        )
        response = getattr(boto_client, boto_action)(**normalised_parameters)
        response.pop("ResponseMetadata", None)
        env.stack.append(response)
