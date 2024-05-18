import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ServiceResource,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ResourceEval(abc.ABC):
    resource: Final[ServiceResource]

    def __init__(self, resource: ServiceResource):
        self.resource = resource

    def eval_resource(self, env: Environment) -> None: ...
