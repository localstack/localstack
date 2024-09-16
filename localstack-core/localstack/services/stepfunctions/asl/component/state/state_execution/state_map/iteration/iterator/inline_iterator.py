from __future__ import annotations

import logging
from typing import Optional

from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.inline_iteration_component import (
    InlineIterationComponent,
    InlineIterationComponentEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.inline_iterator_worker import (
    InlineIteratorWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator_decl import (
    IteratorDecl,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class InlineIteratorEvalInput(InlineIterationComponentEvalInput):
    pass


class InlineIterator(InlineIterationComponent):
    _eval_input: Optional[InlineIteratorEvalInput]

    def _create_worker(self, env: Environment) -> InlineIteratorWorker:
        return InlineIteratorWorker(
            work_name=self._eval_input.state_name,
            job_pool=self._job_pool,
            env=env,
            parameters=self._eval_input.parameters,
            item_selector=self._eval_input.item_selector,
        )

    @classmethod
    def from_declaration(cls, iterator_decl: IteratorDecl):
        return cls(
            start_at=iterator_decl.start_at,
            states=iterator_decl.states,
            comment=iterator_decl.comment,
            processor_config=iterator_decl.processor_config,
        )
