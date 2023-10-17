from __future__ import annotations

from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.item_reader_decl import (
    ItemReader,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
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
    item_selector: Final[Optional[ItemSelector]]

    def __init__(
        self,
        state_name: str,
        max_concurrency: int,
        item_reader: ItemReader,
        item_selector: Optional[ItemSelector],
    ):
        super().__init__(
            state_name=state_name, max_concurrency=max_concurrency, item_reader=item_reader
        )
        self.item_selector = item_selector


class DistributedItemProcessor(DistributedIterationComponent):
    _processor_config: Final[ProcessorConfig]
    _eval_input: Optional[DistributedItemProcessorEvalInput]

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
            processor_config=props.get(ProcessorConfig),
        )
        return item_processor

    def _create_worker(self, env: Environment) -> DistributedItemProcessorWorker:
        return DistributedItemProcessorWorker(
            work_name=self._eval_input.state_name,
            job_pool=self._job_pool,
            env=env,
            item_reader=self._eval_input.item_reader,
            item_selector=self._eval_input.item_selector,
            map_run_record=self._map_run_record,
        )
