import logging
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.parargs import Parameters
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_worker import (
    IterationWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class InlineItemProcessorWorker(IterationWorker):
    _parameters: Final[Optional[Parameters]]
    _item_selector: Final[Optional[ItemSelector]]

    def __init__(
        self,
        work_name: str,
        job_pool: JobPool,
        env: Environment,
        item_selector: Optional[ItemSelector],
        parameters: Optional[Parameters],
    ):
        super().__init__(work_name=work_name, job_pool=job_pool, env=env)
        self._item_selector = item_selector
        self._parameters = parameters

    def _eval_input(self, env_frame: Environment) -> None:
        if not self._parameters and not self._item_selector:
            return

        map_state_input = self._env.stack[-1]
        env_frame.states.reset(input_value=map_state_input)
        env_frame.stack.append(map_state_input)

        if self._item_selector:
            self._item_selector.eval(env_frame)
        elif self._parameters:
            self._parameters.eval(env_frame)

        output_value = env_frame.stack[-1]
        env_frame.states.reset(input_value=output_value)
