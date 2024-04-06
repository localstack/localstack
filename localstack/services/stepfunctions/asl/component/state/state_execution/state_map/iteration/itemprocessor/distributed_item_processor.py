from __future__ import annotations

from typing import Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
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
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps


class DistributedItemProcessorEvalInput(DistributedIterationComponentEvalInput):
    pass


class DistributedItemProcessor(DistributedIterationComponent):
    _eval_input: Optional[DistributedItemProcessorEvalInput]

    @classmethod
    def from_props(cls, props: TypedProps) -> DistributedItemProcessor:
        item_processor = cls(
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

    def _create_worker(self, env: Environment) -> DistributedItemProcessorWorker:
        return DistributedItemProcessorWorker(
            work_name=self._eval_input.state_name,
            job_pool=self._job_pool,
            env=env,
            item_reader=self._eval_input.item_reader,
            parameters=self._eval_input.parameters,
            item_selector=self._eval_input.item_selector,
            map_run_record=self._map_run_record,
        )
