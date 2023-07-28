from __future__ import annotations

import json
import logging
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component_base import (
    DistributedIterationComponent,
    DistributedIterationComponentEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator_worker import (
    IteratorWorker,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class IteratorEvalInput(DistributedIterationComponentEvalInput):
    parameters: Final[Optional[ItemSelector]]

    def __init__(
        self,
        state_name: str,
        max_concurrency: int,
        input_items: list[json],
        parameters: Optional[Parameters],
    ):
        super().__init__(
            state_name=state_name, max_concurrency=max_concurrency, input_items=input_items
        )
        self.parameters = parameters


class Iterator(DistributedIterationComponent):
    _eval_input: Optional[IteratorEvalInput]

    def _create_worker(self, env: Environment) -> IteratorWorker:
        return IteratorWorker(
            work_name=self._eval_input.state_name,
            job_pool=self._job_pool,
            env=env,
            parameters=self._eval_input.parameters,
        )
