from __future__ import annotations

from typing import Callable, Final

from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval import (
    ResourceEval,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    StateCredentials,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.boto_client import boto_client_for
from localstack.utils.strings import camel_to_snake_case, to_str


class ResourceEvalS3(ResourceEval):
    _HANDLER_REFLECTION_PREFIX: Final[str] = "_handle_"
    _API_ACTION_HANDLER_TYPE = Callable[[Environment, ResourceRuntimePart, StateCredentials], None]

    @staticmethod
    def _get_s3_client(
        resource_runtime_part: ResourceRuntimePart, state_credentials: StateCredentials
    ):
        return boto_client_for(
            region=resource_runtime_part.region, service="s3", state_credentials=state_credentials
        )

    @staticmethod
    def _handle_get_object(
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        state_credentials: StateCredentials,
    ) -> None:
        s3_client = ResourceEvalS3._get_s3_client(
            resource_runtime_part=resource_runtime_part, state_credentials=state_credentials
        )
        parameters = env.stack.pop()
        response = s3_client.get_object(**parameters)  # noqa
        content = to_str(response["Body"].read())
        env.stack.append(content)

    @staticmethod
    def _handle_list_objects_v2(
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        state_credentials: StateCredentials,
    ) -> None:
        s3_client = ResourceEvalS3._get_s3_client(
            resource_runtime_part=resource_runtime_part, state_credentials=state_credentials
        )
        parameters = env.stack.pop()
        response = s3_client.list_objects_v2(**parameters)  # noqa
        contents = response["Contents"]
        env.stack.append(contents)

    def _get_api_action_handler(self) -> ResourceEvalS3._API_ACTION_HANDLER_TYPE:
        api_action = camel_to_snake_case(self.resource.api_action).strip()
        handler_name = ResourceEvalS3._HANDLER_REFLECTION_PREFIX + api_action
        resolver_handler = getattr(self, handler_name)
        if resolver_handler is None:
            raise ValueError(f"Unknown s3 action '{api_action}'.")
        return resolver_handler

    def eval_resource(self, env: Environment) -> None:
        self.resource.eval(env=env)
        resource_runtime_part: ResourceRuntimePart = env.stack.pop()
        resolver_handler = self._get_api_action_handler()
        state_credentials = StateCredentials(role_arn=env.aws_execution_details.role_arn)
        resolver_handler(env, resource_runtime_part, state_credentials)
