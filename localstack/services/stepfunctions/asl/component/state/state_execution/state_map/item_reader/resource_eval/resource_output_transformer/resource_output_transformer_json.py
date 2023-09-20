import json

from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_decl import (
    ReaderConfigOutput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer import (
    ResourceOutputTransformer,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ResourceOutputTransformerJson(ResourceOutputTransformer):
    def _eval_body(self, env: Environment) -> None:
        _: ReaderConfigOutput = (
            env.stack.pop()
        )  # Not used, but expected by workflow (hence should consume the stack).
        resource_value: str = env.stack.pop()

        # TODO check these scenarios:
        #     - [] object is not a list
        json_list = json.loads(resource_value)
        env.stack.append(json_list)
