from __future__ import annotations

import json
import logging
import threading
from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.item_processor_job import (
    Job,
    JobPool,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.item_processor_props import (
    ItemProcessorProps,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.item_processor_worker import (
    ItemProcessorWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
)
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.threads import TMP_THREADS

LOG = logging.getLogger(__name__)


class ItemProcessor(EvalComponent):

    processor_config: Final[ProcessorConfig]
    start_at: Final[StartAt]
    states: Final[States]
    comment: Final[Optional[Comment]]

    def __init__(
        self,
        processor_config: ProcessorConfig,
        start_at: StartAt,
        states: States,
        comment: Optional[Comment],
    ):
        self.processor_config = processor_config
        self.start_at = start_at
        self.states = states
        self.comment = comment

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
        max_concurrency: int = env.stack.pop()
        work_name: str = env.stack.pop()

        # Create a sub-sfn program and launch worker.
        input_item_prog: Final[Program] = Program(
            start_at=self.start_at, states=self.states, comment=self.comment
        )

        # TODO:
        #  add support for support for ProcessorConfig (already parsed in this node).
        #  add support for ItemSelector before passing input_items forward

        job_pool = JobPool(job_program=input_item_prog, job_inputs=input_items)

        number_of_workers = (
            len(input_items) if max_concurrency == MaxConcurrency.DEFAULT else max_concurrency
        )
        for _ in range(number_of_workers):
            worker = ItemProcessorWorker(work_name=work_name, job_pool=job_pool, env=env)
            worker_thread = threading.Thread(target=worker.eval)
            TMP_THREADS.append(worker_thread)
            worker_thread.start()

        job_pool.await_jobs()

        worker_exception: Optional[Exception] = job_pool.get_worker_exception()
        if worker_exception is not None:
            raise worker_exception

        closed_jobs: list[Job] = job_pool.get_closed_jobs()
        outputs: list[Any] = [closed_job.job_output for closed_job in closed_jobs]

        env.stack.append(outputs)
