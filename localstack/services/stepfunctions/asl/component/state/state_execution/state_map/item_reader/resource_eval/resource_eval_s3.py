from typing import Final

from botocore.config import Config

from localstack.aws.connect import connect_externally_to
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval import (
    ResourceEval,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.strings import camel_to_snake_case, to_str


class ResourceEvalS3(ResourceEval):
    _HANDLER_REFLECTION_PREFIX: Final[str] = "_handle_"

    @staticmethod
    def _get_s3_client():
        # TODO:connect_externally_to is being deprecated, update to new pattern.
        return connect_externally_to(config=Config(parameter_validation=False)).s3

    @staticmethod
    def _get_handler_for_api_action(api_action: str):
        return ResourceEvalS3._HANDLER_REFLECTION_PREFIX + api_action.strip()

    @staticmethod
    def _handle_get_object(env: Environment) -> None:
        s3_client = ResourceEvalS3._get_s3_client()
        parameters = env.stack.pop()
        response = s3_client.get_object(**parameters)
        content = to_str(response["Body"].read())
        env.stack.append(content)

    def eval_resource(self, env: Environment) -> None:
        api_action = camel_to_snake_case(self.resource.api_action)
        reflection_resolver = self._get_handler_for_api_action(api_action=api_action)
        resolver_handler = getattr(self, reflection_resolver)
        if resolver_handler is not None:
            resolver_handler(env=env)
        else:
            raise ValueError(f"Unknown s3 action '{api_action}'.")
