from __future__ import annotations

import abc
import json
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
from localstack.services.stepfunctions.asl.component.common.parargs import Parameters
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.program.states import States
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    JobClosed,
    JobPool,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    DEFAULT_MAX_CONCURRENCY_VALUE,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.event.event_manager import (
    EventManager,
)


class DistributedIterationComponentEvalInput(InlineIterationComponentEvalInput):
    item_reader: Final[Optional[ItemReader]]
    label: Final[Optional[str]]
    map_run_record: Final[MapRunRecord]

    def __init__(
        self,
        state_name: str,
        max_concurrency: int,
        input_items: list[json],
        parameters: Optional[Parameters],
        item_selector: Optional[ItemSelector],
        item_reader: Optional[ItemReader],
        tolerated_failure_count: int,
        tolerated_failure_percentage: float,
        label: Optional[str],
        map_run_record: MapRunRecord,
    ):
        super().__init__(
            state_name=state_name,
            max_concurrency=max_concurrency,
            input_items=input_items,
            parameters=parameters,
            item_selector=item_selector,
        )
        self.item_reader = item_reader
        self.tolerated_failure_count = tolerated_failure_count
        self.tolerated_failure_percentage = tolerated_failure_percentage
        self.label = label
        self.map_run_record = map_run_record


class DistributedIterationComponent(InlineIterationComponent, abc.ABC):
    def __init__(
        self,
        query_language: QueryLanguage,
        start_at: StartAt,
        states: States,
        comment: Comment,
        processor_config: ProcessorConfig,
    ):
        super().__init__(
            query_language=query_language,
            start_at=start_at,
            states=states,
            comment=comment,
            processor_config=processor_config,
        )

    def _map_run(
        self, env: Environment, eval_input: DistributedIterationComponentEvalInput
    ) -> None:
        input_items: list[json] = env.stack.pop()

        input_item_program: Final[Program] = self._get_iteration_program()
        job_pool = JobPool(job_program=input_item_program, job_inputs=input_items)

        # TODO: add watch on map_run_record update event and adjust the number of running workers accordingly.
        max_concurrency = eval_input.map_run_record.max_concurrency
        workers_number = (
            len(input_items)
            if max_concurrency == DEFAULT_MAX_CONCURRENCY_VALUE
            else max_concurrency
        )
        for _ in range(workers_number):
            self._launch_worker(env=env, eval_input=eval_input, job_pool=job_pool)

        job_pool.await_jobs()

        worker_exception: Optional[Exception] = job_pool.get_worker_exception()
        if worker_exception is not None:
            raise worker_exception

        closed_jobs: list[JobClosed] = job_pool.get_closed_jobs()
        outputs: list[Any] = [closed_job.job_output for closed_job in closed_jobs]

        env.stack.append(outputs)

    def _eval_body(self, env: Environment) -> None:
        eval_input: DistributedIterationComponentEvalInput = env.stack.pop()
        map_run_record = eval_input.map_run_record

        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.MapRunStarted,
            event_details=EventDetails(
                mapRunStartedEventDetails=MapRunStartedEventDetails(
                    mapRunArn=map_run_record.map_run_arn
                )
            ),
        )

        parent_event_manager = env.event_manager
        try:
            if eval_input.item_reader:
                eval_input.item_reader.eval(env=env)
            else:
                env.stack.append(eval_input.input_items)

            env.event_manager = EventManager()
            self._map_run(env=env, eval_input=eval_input)

        except FailureEventException as failure_event_ex:
            map_run_fail_event_detail = MapRunFailedEventDetails()

            maybe_error_cause_pair = failure_event_ex.extract_error_cause_pair()
            if maybe_error_cause_pair:
                error, cause = maybe_error_cause_pair
                if error:
                    map_run_fail_event_detail["error"] = error
                if cause:
                    map_run_fail_event_detail["cause"] = cause

            env.event_manager = parent_event_manager
            env.event_manager.add_event(
                context=env.event_history_context,
                event_type=HistoryEventType.MapRunFailed,
                event_details=EventDetails(mapRunFailedEventDetails=map_run_fail_event_detail),
            )
            map_run_record.set_stop(status=MapRunStatus.FAILED)
            raise failure_event_ex

        except Exception as ex:
            env.event_manager = parent_event_manager
            env.event_manager.add_event(
                context=env.event_history_context,
                event_type=HistoryEventType.MapRunFailed,
                event_details=EventDetails(mapRunFailedEventDetails=MapRunFailedEventDetails()),
            )
            map_run_record.set_stop(status=MapRunStatus.FAILED)
            raise ex
        finally:
            env.event_manager = parent_event_manager

        # TODO: review workflow of program stops and map run stops
        env.event_manager.add_event(
            context=env.event_history_context, event_type=HistoryEventType.MapRunSucceeded
        )
        map_run_record.set_stop(status=MapRunStatus.SUCCEEDED)
