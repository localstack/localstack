import copy
import logging
from typing import Final

from localstack.services.stepfunctions.asl.component.common.parargs import Parargs
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
    parargs: Final[Parargs]

    def __init__(
        self,
        resource: Resource,
        parargs: Parargs,
    ):
        self.resource_eval = resource_eval_for(resource=resource)
        self.parargs = parargs

    @property
    def resource(self):
        return self.resource_eval.resource

    def __str__(self):
        class_dict = copy.deepcopy(self.__dict__)
        del class_dict["resource_eval"]
        class_dict["resource"] = self.resource
        return f"({self.__class__.__name__}| {class_dict})"

    def _eval_body(self, env: Environment) -> None:
        self.parargs.eval(env=env)
        self.resource_eval.eval_resource(env=env)
