from __future__ import annotations

import json
import logging
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.item_processor_props import (
    ItemProcessorProps,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.count_down_latch import CountDownLatch
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.program_worker import ProgramWorker

LOG = logging.getLogger(__name__)


class ItemProcessor(EvalComponent):
    def __init__(
        self,
        processor_config: ProcessorConfig,
        start_at: StartAt,
        states: States,
        comment: Optional[Comment],
    ):
        super().__init__()
        self.processor_config: Final[ProcessorConfig] = processor_config
        self.start_at: Final[StartAt] = start_at
        self.states: Final[States] = states
        self.comment: Final[Optional[Comment]] = comment

    @classmethod
    def from_props(cls, props: ItemProcessorProps) -> ItemProcessor:
        if not props.get(States):
            raise ValueError(f"Missing States declaration in props '{props}'.")
        if not props.get(StartAt):
            raise ValueError(f"Missing StartAt declaration in props '{props}'.")
        item_processor = cls(
            processor_config=props.get(ProcessorConfig),
            start_at=props.get(StartAt),
            states=props.get(States),
            comment=props.get(Comment),
        )
        return item_processor

    def _eval_body(self, env: Environment) -> None:
        input_items: list[json] = env.stack.pop()
        LOG.debug(f"[ItemProcessor] [eval]: {len(input_items)} input items.")

        # Create a sub-sfn program and launch worker.
        input_item_prog: Final[Program] = Program(
            start_at=self.start_at, states=self.states, comment=self.comment
        )

        # CountDownLatch to detect halting of all worker threads.
        latch: Final[CountDownLatch] = CountDownLatch(len(input_items))

        # Create state_map workers.
        # TODO:
        #  add support for support for ProcessorConfig (already parsed in this node).
        #  Note:
        #  Concurrent iterations may be limited. When this occurs, some iterations won't begin
        #  until previous iterations are complete. The likelihood of this occurring increases
        #  when your input array has more than 40 items.
        worker_pool: list[ProgramWorker] = list()
        for input_item in input_items:
            # Open a new Environment frame (linked to the main's state).
            env_frame: Environment = env.open_frame()
            env_frame.inp = input_item

            # Launch the worker.
            worker = ProgramWorker()
            worker.eval(program=input_item_prog, env_frame=env_frame, latch=latch)

            worker_pool.append(worker)

        # Await for worker threads.
        latch.wait()

        # Collect results and push to the stack.
        result_list = list()
        for worker in worker_pool:
            env_frame = worker.env_frame

            result = env_frame.inp
            result_list.append(result)

            env.close_frame(env_frame)

        env.stack.append(result_list)
