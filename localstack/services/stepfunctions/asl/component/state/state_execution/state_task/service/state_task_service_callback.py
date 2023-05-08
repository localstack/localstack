from abc import abstractmethod

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StateTaskServiceCallback(StateTaskService):
    @abstractmethod
    def _eval_service_task(self, env: Environment):
        ...

    def _eval_execution(self, env: Environment) -> None:
        self._eval_service_task(env=env)
        if self.resource.condition is not None:
            callback_id = env.context_object_manager.context_object["Task"]["Token"]
            callback_endpoint = env.callback_pool_manager.get(callback_id)
            callback_endpoint.wait()  # TODO: implement timeout.
