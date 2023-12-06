import copy
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_decl import (
    ReaderConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval import (
    ResourceEval,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval_factory import (
    resource_eval_for,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer import (
    ResourceOutputTransformer,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer_factory import (
    resource_output_transformer_for,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ItemReader(EvalComponent):
    resource_eval: Final[ResourceEval]
    parameters: Final[Optional[Parameters]]
    reader_config: Final[Optional[ReaderConfig]]
    resource_output_transformer: Optional[ResourceOutputTransformer]

    def __init__(
        self,
        resource: Resource,
        parameters: Optional[Parameters],
        reader_config: Optional[ReaderConfig],
    ):
        self.resource_eval = resource_eval_for(resource=resource)
        self.parameters = parameters
        self.reader_config = reader_config

        self.resource_output_transformer = None
        if self.reader_config:
            self.resource_output_transformer = resource_output_transformer_for(
                input_type=self.reader_config.input_type
            )

    @property
    def resource(self):
        return self.resource_eval.resource

    def __str__(self):
        class_dict = copy.deepcopy(self.__dict__)
        del class_dict["resource_eval"]
        class_dict["resource"] = self.resource
        return f"({self.__class__.__name__}| {class_dict})"

    def _eval_body(self, env: Environment) -> None:
        if self.parameters:
            self.parameters.eval(env=env)
        else:
            env.stack.append(dict())

        self.resource_eval.eval_resource(env=env)

        if self.reader_config:
            self.reader_config.eval(env=env)
            self.resource_output_transformer.eval(env=env)
