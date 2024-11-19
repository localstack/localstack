import datetime
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, HistoryEventType
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.branch_worker import (
    BranchWorker,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.program_state import ProgramError, ProgramState
from localstack.utils.collections import select_from_typed_dict


class BranchWorkerPool(BranchWorker.BranchWorkerComm):
    _mutex: Final[threading.Lock]
    _termination_event: Final[threading.Event]
    _active_workers_num: int

    _terminated_with_error: Optional[ExecutionFailedEventDetails]

    def __init__(self, workers_num: int):
        self._mutex = threading.Lock()
        self._termination_event = threading.Event()
        self._active_workers_num = workers_num

        self._terminated_with_error = None

    def on_terminated(self, env: Environment):
        if self._termination_event.is_set():
            return
        with self._mutex:
            end_program_state: ProgramState = env.program_state()
            if isinstance(end_program_state, ProgramError):
                self._terminated_with_error = select_from_typed_dict(
                    typed_dict=ExecutionFailedEventDetails, obj=end_program_state.error or dict()
                )
                self._termination_event.set()
            else:
                self._active_workers_num -= 1
                if self._active_workers_num == 0:
                    self._termination_event.set()

    def wait(self):
        self._termination_event.wait()

    def get_exit_event_details(self) -> Optional[ExecutionFailedEventDetails]:
        return self._terminated_with_error


class BranchesDecl(EvalComponent):
    def __init__(self, programs: list[Program]):
        self.programs: Final[list[Program]] = programs

    def _eval_body(self, env: Environment) -> None:
        # Input value for every state_parallel process.
        input_val = env.stack.pop()

        branch_worker_pool = BranchWorkerPool(workers_num=len(self.programs))

        branch_workers: list[BranchWorker] = list()
        for program in self.programs:
            # Environment frame for this sub process.
            env_frame: Environment = env.open_inner_frame()
            env_frame.states.reset(input_value=input_val)

            # Launch the worker.
            worker = BranchWorker(
                branch_worker_comm=branch_worker_pool, program=program, env=env_frame
            )
            branch_workers.append(worker)

            worker.start()

        branch_worker_pool.wait()

        # Propagate exception if parallel task failed.
        exit_event_details: Optional[ExecutionFailedEventDetails] = (
            branch_worker_pool.get_exit_event_details()
        )
        if exit_event_details is not None:
            for branch_worker in branch_workers:
                branch_worker.stop(stop_date=datetime.datetime.now(), cause=None, error=None)
                env.close_frame(branch_worker.env)

            exit_error_name = exit_event_details.get("error")
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=CustomErrorName(error_name=exit_error_name),
                    event_type=HistoryEventType.ExecutionFailed,
                    event_details=EventDetails(executionFailedEventDetails=exit_event_details),
                )
            )

        # Collect the results and return.
        result_list = list()

        for worker in branch_workers:
            env_frame = worker.env
            result_list.append(env_frame.states.get_input())
            env.close_frame(env_frame)

        env.stack.append(result_list)
