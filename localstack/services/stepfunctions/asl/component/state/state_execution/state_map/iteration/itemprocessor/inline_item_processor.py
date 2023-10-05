from __future__ import annotations

import json
import logging
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
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
    item_selector: Final[Optional[ItemSelector]]

    def __init__(
        self,
        state_name: str,
        max_concurrency: int,
        input_items: list[json],
        item_selector: Optional[ItemSelector],
    ):
        super().__init__(
            state_name=state_name, max_concurrency=max_concurrency, input_items=input_items
        )
        self.item_selector = item_selector


class InlineItemProcessor(InlineIterationComponent):
    _processor_config: Final[ProcessorConfig]
    _eval_input: Optional[InlineItemProcessorEvalInput]

    def __init__(
        self,
        start_at: StartAt,
        states: States,
        comment: Optional[Comment],
        processor_config: ProcessorConfig,
    ):
        super().__init__(start_at=start_at, states=states, comment=comment)
        self._processor_config = processor_config

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
            processor_config=props.get(ProcessorConfig),
        )
        return item_processor

    def _create_worker(self, env: Environment) -> InlineItemProcessorWorker:
        return InlineItemProcessorWorker(
            work_name=self._eval_input.state_name,
            job_pool=self._job_pool,
            env=env,
            item_selector=self._eval_input.item_selector,
        )
