from __future__ import annotations

import abc
import json
import threading
from typing import Any, Final, Optional

from localstack.aws.api.stepfunctions import (
    HistoryEventType,
    MapRunFailedEventDetails,
    MapRunStartedEventDetails,
    MapRunStatus,
)
from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.item_reader_decl import (
    ItemReader,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.inline_iteration_component import (
    InlineIterationComponent,
    InlineIterationComponentEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.map_run_record import (
    MapRunRecord,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
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


class DistributedIterationComponentEvalInput(InlineIterationComponentEvalInput):
    item_reader: Final[Optional[ItemReader]]

    def __init__(
        self,
        state_name: str,
        max_concurrency: int,
        input_items: list[json],
        parameters: Optional[Parameters],
        item_selector: Optional[ItemSelector],
        item_reader: Optional[ItemReader],
    ):
        super().__init__(
            state_name=state_name,
            max_concurrency=max_concurrency,
            input_items=input_items,
            parameters=parameters,
            item_selector=item_selector,
        )
        self.item_reader = item_reader


class DistributedIterationComponent(InlineIterationComponent, abc.ABC):
    _eval_input: Optional[DistributedIterationComponentEvalInput]
    _mutex: Final[threading.Lock]
    _map_run_record: Optional[MapRunRecord]
    _workers: list[IterationWorker]

    def __init__(
        self, start_at: StartAt, states: States, comment: Comment, processor_config: ProcessorConfig
    ):
        super().__init__(
            start_at=start_at, states=states, comment=comment, processor_config=processor_config
        )
        self._mutex = threading.Lock()
        self._map_run_record = None
        self._workers = list()

    @abc.abstractmethod
    def _create_worker(self, env: Environment) -> IterationWorker:
        ...

    def _launch_worker(self, env: Environment) -> IterationWorker:
        worker = super()._launch_worker(env=env)
        self._workers.append(worker)
        return worker

    def _set_active_workers(self, workers_number: int, env: Environment) -> None:
        with self._mutex:
            current_workers_number = len(self._workers)
            workers_diff = workers_number - current_workers_number
            if workers_diff > 0:
                for _ in range(workers_diff):
                    self._launch_worker(env=env)
            elif workers_diff < 0:
                deletion_workers = list(self._workers)[workers_diff:]
                for worker in deletion_workers:
                    worker.sig_stop()
                    self._workers.remove(worker)

    def _map_run(self, env: Environment) -> None:
        input_items: list[json] = env.stack[-1]

        input_item_prog: Final[Program] = Program(
            start_at=self._start_at,
            states=self._states,
            timeout_seconds=None,
            comment=self._comment,
        )
        self._job_pool = JobPool(job_program=input_item_prog, job_inputs=input_items)

        # TODO: add watch on map_run_record update event and adjust the number of running workers accordingly.
        max_concurrency = self._map_run_record.max_concurrency
        workers_number = (
            len(input_items) if max_concurrency == MaxConcurrency.DEFAULT else max_concurrency
        )
        self._set_active_workers(workers_number=workers_number, env=env)

        self._job_pool.await_jobs()

        worker_exception: Optional[Exception] = self._job_pool.get_worker_exception()
        if worker_exception is not None:
            raise worker_exception

        closed_jobs: list[Job] = self._job_pool.get_closed_jobs()
        outputs: list[Any] = [closed_job.job_output for closed_job in closed_jobs]

        env.stack.append(outputs)

    def _eval_body(self, env: Environment) -> None:
        self._eval_input = env.stack.pop()

        self._map_run_record = MapRunRecord(
            state_machine_arn=env.context_object_manager.context_object["StateMachine"]["Id"],
            execution_arn=env.context_object_manager.context_object["Execution"]["Id"],
            max_concurrency=self._eval_input.max_concurrency,
        )
        env.map_run_record_pool_manager.add(self._map_run_record)

        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.MapRunStarted,
            event_detail=EventDetails(
                mapRunStartedEventDetails=MapRunStartedEventDetails(
                    mapRunArn=self._map_run_record.map_run_arn
                )
            ),
        )

        execution_event_history = env.event_history
        try:
            if self._eval_input.item_reader:
                self._eval_input.item_reader.eval(env=env)
            else:
                env.stack.append(self._eval_input.input_items)

            # TODO: investigate if this is truly propagated also to eventual sub programs in map run states.
            env.event_history = EventHistory()
            self._map_run(env=env)

        except FailureEventException as failure_event_ex:
            map_run_fail_event_detail = MapRunFailedEventDetails()

            maybe_error_cause_pair = failure_event_ex.extract_error_cause_pair()
            if maybe_error_cause_pair:
                error, cause = maybe_error_cause_pair
                if error:
                    map_run_fail_event_detail["error"] = error
                if cause:
                    map_run_fail_event_detail["cause"] = cause

            env.event_history = execution_event_history
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.MapRunFailed,
                event_detail=EventDetails(mapRunFailedEventDetails=map_run_fail_event_detail),
            )
            self._map_run_record.set_stop(status=MapRunStatus.FAILED)
            raise failure_event_ex

        except Exception as ex:
            env.event_history = execution_event_history
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.MapRunFailed,
                event_detail=EventDetails(mapRunFailedEventDetails=MapRunFailedEventDetails()),
            )
            self._map_run_record.set_stop(status=MapRunStatus.FAILED)
            raise ex
        finally:
            env.event_history = execution_event_history

        # TODO: review workflow of program stops and maprunstops
        # program_state = env.program_state()
        # if isinstance(program_state, ProgramSucceeded)
        env.event_history.add_event(
            context=env.event_history_context, hist_type_event=HistoryEventType.MapRunSucceeded
        )
        self._map_run_record.set_stop(status=MapRunStatus.SUCCEEDED)
