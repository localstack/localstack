from __future__ import annotations

import logging

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.program.states import States
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps

LOG = logging.getLogger(__name__)


class InlineItemProcessorEvalInput(InlineIterationComponentEvalInput):
    pass


class InlineItemProcessor(InlineIterationComponent):
    @classmethod
    def from_props(cls, props: TypedProps) -> InlineItemProcessor:
        if not props.get(States):
            raise ValueError(f"Missing States declaration in props '{props}'.")
        if not props.get(StartAt):
            raise ValueError(f"Missing StartAt declaration in props '{props}'.")
        item_processor = cls(
            query_language=props.get(QueryLanguage) or QueryLanguage(),
            start_at=props.get(StartAt),
            states=props.get(States),
            comment=props.get(Comment),
            processor_config=props.get(ProcessorConfig) or ProcessorConfig(),
        )
        return item_processor

    def _create_worker(
        self, env: Environment, eval_input: InlineItemProcessorEvalInput, job_pool: JobPool
    ) -> InlineItemProcessorWorker:
        return InlineItemProcessorWorker(
            work_name=eval_input.state_name,
            job_pool=job_pool,
            env=env,
            item_selector=eval_input.item_selector,
            parameters=eval_input.parameters,
        )
