import copy
import logging
from typing import Final

from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.result_writer.resource_eval.resource_eval import (
    ResourceEval,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.result_writer.resource_eval.resource_eval_factory import (
    resource_eval_for,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class ResultWriter(EvalComponent):
    resource_eval: Final[ResourceEval]
    parameters: Final[Parameters]

    def __init__(
        self,
        resource: Resource,
        parameters: Parameters,
    ):
        self.resource_eval = resource_eval_for(resource=resource)
        self.parameters = parameters

    @property
    def resource(self):
        return self.resource_eval.resource

    def __str__(self):
        class_dict = copy.deepcopy(self.__dict__)
        del class_dict["resource_eval"]
        class_dict["resource"] = self.resource
        return f"({self.__class__.__name__}| {class_dict})"

    def _eval_body(self, env: Environment) -> None:
        self.parameters.eval(env=env)
        self.resource_eval.eval_resource(env=env)
