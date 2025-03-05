from __future__ import annotations

import abc
import json
import threading
from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.parargs import Parameters
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.program.states import States
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component import (
    IterationComponent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_worker import (
    IterationWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    JobClosed,
    JobPool,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    DEFAULT_MAX_CONCURRENCY_VALUE,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.threads import TMP_THREADS


class InlineIterationComponentEvalInput:
    state_name: Final[str]
    max_concurrency: Final[int]
    input_items: Final[list[json]]
    parameters: Final[Optional[Parameters]]
    item_selector: Final[Optional[ItemSelector]]

    def __init__(
        self,
        state_name: str,
        max_concurrency: int,
        input_items: list[json],
        parameters: Optional[Parameters],
        item_selector: Optional[ItemSelector],
    ):
        self.state_name = state_name
        self.max_concurrency = max_concurrency
        self.input_items = input_items
        self.parameters = parameters
        self.item_selector = item_selector


class InlineIterationComponent(IterationComponent, abc.ABC):
    _processor_config: Final[ProcessorConfig]

    def __init__(
        self,
        query_language: QueryLanguage,
        start_at: StartAt,
        states: States,
        processor_config: ProcessorConfig,
        comment: Optional[Comment],
    ):
        super().__init__(
            query_language=query_language, start_at=start_at, states=states, comment=comment
        )
        self._processor_config = processor_config

    @abc.abstractmethod
    def _create_worker(
        self, env: Environment, eval_input: InlineIterationComponentEvalInput, job_pool: JobPool
    ) -> IterationWorker: ...

    def _launch_worker(
        self, env: Environment, eval_input: InlineIterationComponentEvalInput, job_pool: JobPool
    ) -> IterationWorker:
        worker = self._create_worker(env=env, eval_input=eval_input, job_pool=job_pool)
        worker_thread = threading.Thread(target=worker.eval, daemon=True)
        TMP_THREADS.append(worker_thread)
        worker_thread.start()
        return worker

    def _eval_body(self, env: Environment) -> None:
        eval_input = env.stack.pop()

        max_concurrency: int = eval_input.max_concurrency
        input_items: list[json] = eval_input.input_items

        input_item_program: Final[Program] = self._get_iteration_program()
        job_pool = JobPool(job_program=input_item_program, job_inputs=eval_input.input_items)

        number_of_workers = (
            len(input_items)
            if max_concurrency == DEFAULT_MAX_CONCURRENCY_VALUE
            else max_concurrency
        )
        for _ in range(number_of_workers):
            self._launch_worker(env=env, eval_input=eval_input, job_pool=job_pool)

        job_pool.await_jobs()

        worker_exception: Optional[Exception] = job_pool.get_worker_exception()
        if worker_exception is not None:
            raise worker_exception

        closed_jobs: list[JobClosed] = job_pool.get_closed_jobs()
        outputs: list[Any] = [closed_job.job_output for closed_job in closed_jobs]

        env.stack.append(outputs)
