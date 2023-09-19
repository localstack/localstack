import abc
from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ResourceEval(abc.ABC):
    resource: Final[ServiceResource]

    def __init__(self, resource: ServiceResource):
        self.resource = resource

    def eval_resource(self, env: Environment) -> None:
        ...
