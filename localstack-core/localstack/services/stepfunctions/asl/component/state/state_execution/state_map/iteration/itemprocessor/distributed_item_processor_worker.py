import logging
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import EvalTimeoutError
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.item_reader_decl import (
    ItemReader,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.inline_item_processor_worker import (
    InlineItemProcessorWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.map_run_record import (
    MapRunRecord,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    Job,
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import Item, Map
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramError,
    ProgramState,
    ProgramStopped,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

LOG = logging.getLogger(__name__)


class DistributedItemProcessorWorker(InlineItemProcessorWorker):
    _item_reader: Final[ItemReader]
    _map_run_record: MapRunRecord

    def __init__(
        self,
        work_name: str,
        job_pool: JobPool,
        env: Environment,
        item_reader: ItemReader,
        parameters: Optional[Parameters],
        item_selector: Optional[ItemSelector],
        map_run_record: MapRunRecord,
    ):
        super().__init__(
            work_name=work_name,
            job_pool=job_pool,
            env=env,
            parameters=parameters,
            item_selector=item_selector,
        )
        self._item_reader = item_reader
        self._map_run_record = map_run_record

    def _eval_job(self, env: Environment, job: Job) -> None:
        self._map_run_record.item_counter.total.count()
        self._map_run_record.item_counter.running.count()

        self._map_run_record.execution_counter.total.count()
        self._map_run_record.execution_counter.running.count()

        job_output = None
        try:
            env.context_object_manager.context_object["Map"] = Map(
                Item=Item(Index=job.job_index, Value=job.job_input)
            )

            env.inp = job.job_input
            env.stack.append(env.inp)
            self._eval_input(env_frame=env)

            job.job_program.eval(env)

            # TODO: verify behaviour with all of these scenarios.
            end_program_state: ProgramState = env.program_state()
            if isinstance(end_program_state, ProgramError):
                self._map_run_record.execution_counter.failed.count()
                self._map_run_record.item_counter.failed.count()
                job_output = None
            elif isinstance(end_program_state, ProgramStopped):
                self._map_run_record.execution_counter.aborted.count()
                self._map_run_record.item_counter.aborted.count()
            else:
                self._map_run_record.item_counter.succeeded.count()
                self._map_run_record.item_counter.results_written.count()

                self._map_run_record.execution_counter.succeeded.count()
                self._map_run_record.execution_counter.results_written.count()
                self._map_run_record.execution_counter.running.offset(-1)

                job_output = env.inp

        except EvalTimeoutError as timeout_error:
            LOG.debug(
                "MapRun worker Timeout Error '%s' for input '%s'.",
                timeout_error,
                to_json_str(job.job_input),
            )
            self._map_run_record.item_counter.timed_out.count()

        except FailureEventException as failure_event_ex:
            LOG.debug(
                "MapRun worker Event Exception '%s' for input '%s'.",
                to_json_str(failure_event_ex.failure_event),
                to_json_str(job.job_input),
            )
            self._map_run_record.item_counter.failed.count()

        except Exception as exception:
            LOG.debug(
                "MapRun worker Error '%s' for input '%s'.",
                exception,
                to_json_str(job.job_input),
            )
            self._map_run_record.item_counter.failed.count()

        finally:
            self._map_run_record.item_counter.running.offset(-1)
            job.job_output = job_output

    def _eval_pool(self, job: Optional[Job], worker_frame: Environment) -> None:
        if job is None:
            self._env.delete_frame(worker_frame)
            return

        # Evaluate the job.
        job_frame = worker_frame.open_frame()
        self._eval_job(env=job_frame, job=job)
        worker_frame.delete_frame(job_frame)

        # Evaluation terminates here due to exception in job, or worker was stopped.
        if isinstance(job.job_output, Exception) or self.stopped():
            self._env.delete_frame(worker_frame)
            self._job_pool.close_job(job)
            return

        next_job: Job = self._job_pool.next_job()
        # Iteration will terminate after this job.
        if next_job is None:
            # The frame has to be closed before the job, to ensure the owner environment is correctly updated
            #  before the evaluation continues; map states await for job termination not workers termination.
            self._env.delete_frame(worker_frame)
            self._job_pool.close_job(job)
            return

        self._job_pool.close_job(job)
        self._eval_pool(job=next_job, worker_frame=worker_frame)

    def eval(self) -> None:
        self._eval_pool(job=self._job_pool.next_job(), worker_frame=self._env)
