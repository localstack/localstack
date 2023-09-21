import abc
import logging
from typing import Final, Optional

from localstack.aws.api.stepfunctions import HistoryEventType, MapIterationEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    Job,
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import Item, Map
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramError,
    ProgramState,
    ProgramStopped,
)

LOG = logging.getLogger(__name__)


class IterationWorker(abc.ABC):
    _work_name: Final[str]
    _job_pool: Final[JobPool]
    _env: Final[Environment]
    _stop_signal_received: bool

    def __init__(
        self,
        work_name: str,
        job_pool: JobPool,
        env: Environment,
    ):
        self._work_name = work_name
        self._job_pool = job_pool
        self._env = env
        self._stop_signal_received = False

    def sig_stop(self):
        self._stop_signal_received = True

    def stopped(self):
        return self._stop_signal_received

    @abc.abstractmethod
    def _eval_input(self, env_frame: Environment) -> None:
        ...

    def _eval_job(self, job: Job) -> None:
        map_iteration_event_details = MapIterationEventDetails(
            name=self._work_name, index=job.job_index
        )

        self._env.event_history.add_event(
            hist_type_event=HistoryEventType.MapIterationStarted,
            event_detail=EventDetails(mapIterationStartedEventDetails=map_iteration_event_details),
        )

        env_frame: Environment = self._env.open_frame()
        job_output = RuntimeError(
            f"Unexpected Runtime Error in ItemProcessor worker for input '{job.job_index}'."
        )
        try:
            env_frame.context_object_manager.context_object["Map"] = Map(
                Item=Item(Index=job.job_index, Value=job.job_input)
            )

            env_frame.inp = job.job_input
            self._eval_input(env_frame=env_frame)

            job.job_program.eval(env_frame)

            # Program evaluation suppressed runtime exceptions into an execution exception in the program state.
            # Hence, here the routine extract this error triggering FailureEventExceptions, to allow the error at this
            # depth to be logged appropriately and propagate to parent states.

            # In case of internal error that lead to failure, then raise execution Exception
            # and hence leading to a MapIterationFailed event.
            end_program_state: ProgramState = env_frame.program_state()
            if isinstance(end_program_state, ProgramError):
                error_name = end_program_state.error.get("error")
                if error_name is not None:
                    error_name = CustomErrorName(error_name=error_name)
                raise FailureEventException(
                    failure_event=FailureEvent(
                        error_name=error_name,
                        event_type=HistoryEventType.MapIterationFailed,
                        event_details=EventDetails(
                            executionFailedEventDetails=end_program_state.error
                        ),
                    )
                )
            # If instead the program (parent state machine) was halted, then raise an execution Exception.
            elif isinstance(end_program_state, ProgramStopped):
                raise FailureEventException(
                    failure_event=FailureEvent(
                        error_name=CustomErrorName(error_name=HistoryEventType.MapIterationAborted),
                        event_type=HistoryEventType.MapIterationAborted,
                        event_details=EventDetails(
                            executionFailedEventDetails=end_program_state.error
                        ),
                    )
                )

            # Otherwise, execution succeeded and the output of this operation is available.
            self._env.event_history.add_event(
                hist_type_event=HistoryEventType.MapIterationSucceeded,
                event_detail=EventDetails(
                    mapIterationSucceededEventDetails=map_iteration_event_details
                ),
            )
            # Extract the output otherwise.
            job_output = env_frame.inp

        except FailureEventException as failure_event_ex:
            # Extract the output to be this exception: this will trigger a failure workflow in the jobs pool.
            job_output = failure_event_ex

            # At this depth, the next event is either a MapIterationFailed (for any reasons) or a MapIterationAborted
            # if explicitly indicated.
            if failure_event_ex.failure_event.event_type == HistoryEventType.MapIterationAborted:
                self._env.event_history.add_event(
                    hist_type_event=HistoryEventType.MapIterationAborted,
                    event_detail=EventDetails(
                        mapIterationAbortedEventDetails=map_iteration_event_details
                    ),
                )
            else:
                self._env.event_history.add_event(
                    hist_type_event=HistoryEventType.MapIterationFailed,
                    event_detail=EventDetails(
                        mapIterationFailedEventDetails=map_iteration_event_details
                    ),
                )

        except Exception as ex:
            # Error case.
            LOG.warning(
                f"Unhandled termination error in item processor worker for job '{job.job_index}'."
            )

            # Pass the exception upstream leading to evaluation halt.
            job_output = ex

            self._env.event_history.add_event(
                hist_type_event=HistoryEventType.MapIterationFailed,
                event_detail=EventDetails(
                    mapIterationFailedEventDetails=map_iteration_event_details
                ),
            )

        finally:
            job.job_output = job_output
            self._job_pool.close_job(job)
            self._env.close_frame(env_frame)

    def eval(self) -> None:
        job: Optional[Job] = self._job_pool.next_job()
        while job is not None:
            self._eval_job(job=job)
            if self.stopped():
                break
            job = self._job_pool.next_job()
