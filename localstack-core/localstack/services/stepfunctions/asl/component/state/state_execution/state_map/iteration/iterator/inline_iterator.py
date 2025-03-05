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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class InlineIteratorEvalInput(InlineIterationComponentEvalInput):
    pass


class InlineIterator(InlineIterationComponent):
    _eval_input: Optional[InlineIteratorEvalInput]

    def _create_worker(
        self, env: Environment, eval_input: InlineIteratorEvalInput, job_pool: JobPool
    ) -> InlineIteratorWorker:
        return InlineIteratorWorker(
            work_name=eval_input.state_name,
            job_pool=job_pool,
            env=env,
            parameters=eval_input.parameters,
            item_selector=eval_input.item_selector,
        )

    @classmethod
    def from_declaration(cls, iterator_decl: IteratorDecl):
        return cls(
            query_language=iterator_decl.query_language,
            start_at=iterator_decl.start_at,
            states=iterator_decl.states,
            comment=iterator_decl.comment,
            processor_config=iterator_decl.processor_config,
        )
