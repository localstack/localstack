from __future__ import annotations

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.program.states import States
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.distributed_iteration_component import (
    DistributedIterationComponent,
    DistributedIterationComponentEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.distributed_item_processor_worker import (
    DistributedItemProcessorWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps


class DistributedItemProcessorEvalInput(DistributedIterationComponentEvalInput):
    pass


class DistributedItemProcessor(DistributedIterationComponent):
    @classmethod
    def from_props(cls, props: TypedProps) -> DistributedItemProcessor:
        item_processor = cls(
            query_language=props.get(QueryLanguage) or QueryLanguage(),
            start_at=props.get(
                typ=StartAt,
                raise_on_missing=ValueError(f"Missing StartAt declaration in props '{props}'."),
            ),
            states=props.get(
                typ=States,
                raise_on_missing=ValueError(f"Missing States declaration in props '{props}'."),
            ),
            comment=props.get(Comment),
            processor_config=props.get(ProcessorConfig) or ProcessorConfig(),
        )
        return item_processor

    def _create_worker(
        self, env: Environment, eval_input: DistributedItemProcessorEvalInput, job_pool: JobPool
    ) -> DistributedItemProcessorWorker:
        return DistributedItemProcessorWorker(
            work_name=eval_input.state_name,
            job_pool=job_pool,
            env=env,
            item_reader=eval_input.item_reader,
            parameters=eval_input.parameters,
            item_selector=eval_input.item_selector,
            map_run_record=eval_input.map_run_record,
        )
