from __future__ import annotations

import logging
from typing import Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.inline_iteration_component import (
    InlineIterationComponent,
    InlineIterationComponentEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.inline_item_processor_worker import (
    InlineItemProcessorWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps

LOG = logging.getLogger(__name__)


class InlineItemProcessorEvalInput(InlineIterationComponentEvalInput):
    pass


class InlineItemProcessor(InlineIterationComponent):
    _eval_input: Optional[InlineItemProcessorEvalInput]

    @classmethod
    def from_props(cls, props: TypedProps) -> InlineItemProcessor:
        if not props.get(States):
            raise ValueError(f"Missing States declaration in props '{props}'.")
        if not props.get(StartAt):
            raise ValueError(f"Missing StartAt declaration in props '{props}'.")
        item_processor = cls(
            start_at=props.get(StartAt),
            states=props.get(States),
            comment=props.get(Comment),
            processor_config=props.get(ProcessorConfig) or ProcessorConfig(),
        )
        return item_processor

    def _create_worker(self, env: Environment) -> InlineItemProcessorWorker:
        return InlineItemProcessorWorker(
            work_name=self._eval_input.state_name,
            job_pool=self._job_pool,
            env=env,
            item_selector=self._eval_input.item_selector,
            parameters=self._eval_input.parameters,
        )
