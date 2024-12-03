from typing import Optional

from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.parargs import Parameters
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import EvalTimeoutError
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.map_run_record import (
    MapRunRecord,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.inline_iterator_worker import (
    InlineIteratorWorker,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.job import (
    Job,
    JobPool,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramError,
    ProgramState,
    ProgramStopped,
)
from localstack.services.stepfunctions.asl.eval.states import ItemData, MapData


class DistributedIteratorWorker(InlineIteratorWorker):
    _map_run_record: MapRunRecord

    def __init__(
        self,
        work_name: str,
        job_pool: JobPool,
        env: Environment,
        parameters: Optional[Parameters],
        map_run_record: MapRunRecord,
        item_selector: Optional[ItemSelector],
    ):
        super().__init__(
            work_name=work_name,
            job_pool=job_pool,
            env=env,
            parameters=parameters,
            item_selector=item_selector,
        )
        self._map_run_record = map_run_record

    def _eval_job(self, env: Environment, job: Job) -> None:
        self._map_run_record.item_counter.total.count()
        self._map_run_record.item_counter.running.count()

        self._map_run_record.execution_counter.total.count()
        self._map_run_record.execution_counter.running.count()

        job_output = None
        try:
            env.states.context_object.context_object_data["Map"] = MapData(
                Item=ItemData(Index=job.job_index, Value=job.job_input)
            )

            env.states.reset(input_value=job.job_input)
            env.stack.append(env.states.get_input())
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

                job_output = env.states.get_input()

        except EvalTimeoutError:
            self._map_run_record.item_counter.timed_out.count()

        except FailureEventException:
            self._map_run_record.item_counter.failed.count()

        except Exception:
            self._map_run_record.item_counter.failed.count()

        finally:
            self._map_run_record.item_counter.running.offset(-1)
            job.job_output = job_output

    def _eval_pool(self, job: Optional[Job], worker_frame: Environment) -> None:
        # Note: the frame has to be closed before the job, to ensure the owner environment is correctly updated
        #  before the evaluation continues; map states await for job termination not workers termination.
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
            self._env.delete_frame(worker_frame)
            self._job_pool.close_job(job)
            return

        self._job_pool.close_job(job)
        self._eval_pool(job=next_job, worker_frame=worker_frame)

    def eval(self) -> None:
        self._eval_pool(job=self._job_pool.next_job(), worker_frame=self._env)
