from __future__ import annotations

import abc
import json
import threading
from typing import Any, Final, Iterable, Optional

from localstack.aws.api.stepfunctions import (
    HistoryEventType,
    MapRunFailedEventDetails,
    MapRunStartedEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.inline_iteration_component import (
    InlineIterationComponent,
    InlineIterationComponentEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component import (
    IterationComponent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_worker import (
    IterationWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    Job,
    JobPool,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
)
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.event.event_history import EventHistory
from localstack.utils.threads import TMP_THREADS


class DistributedIterationComponentEvalInput(InlineIterationComponentEvalInput):
    pass


class DistributedIterationComponent(InlineIterationComponent, abc.ABC):
    @abc.abstractmethod
    def _create_worker(self, env: Environment) -> IterationWorker:
        ...

    def _map_run(self, env: Environment) -> None:
        self._eval_input = env.stack.pop()

        max_concurrency: int = self._eval_input.max_concurrency
        input_items: list[json] = self._eval_input.input_items

        input_item_prog: Final[Program] = Program(
            start_at=self._start_at,
            states=self._states,
            timeout_seconds=None,
            comment=self._comment,
        )
        self._job_pool = JobPool(
            job_program=input_item_prog, job_inputs=self._eval_input.input_items
        )

        number_of_workers = (
            len(input_items) if max_concurrency == MaxConcurrency.DEFAULT else max_concurrency
        )
        for _ in range(number_of_workers):
            worker = self._create_worker(env=env)
            worker_thread = threading.Thread(target=worker.eval)
            TMP_THREADS.append(worker_thread)
            worker_thread.start()

        self._job_pool.await_jobs()

        worker_exception: Optional[Exception] = self._job_pool.get_worker_exception()
        if worker_exception is not None:
            raise worker_exception

        closed_jobs: list[Job] = self._job_pool.get_closed_jobs()
        outputs: list[Any] = [closed_job.job_output for closed_job in closed_jobs]

        env.stack.append(outputs)

    def _eval_body(self, env: Environment) -> None:
        env.event_history.add_event(
            hist_type_event=HistoryEventType.MapRunStarted,
            event_detail=EventDetails(
                mapRunStartedEventDetails=MapRunStartedEventDetails(mapRunArn="TODO")
            ),
        )

        execution_event_history = env.event_history
        try:
            # TODO: investigate if this is truly propagated also to eventual sub programs in map run states.
            env.event_history = EventHistory()
            self._map_run(env=env)
        except Exception as ex:
            env.event_history = execution_event_history
            env.event_history.add_event(
                hist_type_event=HistoryEventType.MapRunFailed,
                event_detail=EventDetails(
                    mapRunFailedEventDetails=MapRunFailedEventDetails(
                        error="TODO ERROR", cause="TODO CAUSE"
                    )
                ),
            )
            raise ex
        finally:
            env.event_history = execution_event_history

        # TODO: review workflow of program stops and maprunstops
        # program_state = env.program_state()
        # if isinstance(program_state, ProgramSucceeded)
        env.event_history.add_event(
            hist_type_event=HistoryEventType.MapRunSucceeded,
        )
