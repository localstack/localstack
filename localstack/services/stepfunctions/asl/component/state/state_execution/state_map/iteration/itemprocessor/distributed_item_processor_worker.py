from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
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
from localstack.services.stepfunctions.asl.eval.event.event_history import EventHistory
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramError,
    ProgramState,
    ProgramStopped,
)


class DistributedItemProcessorWorker(InlineItemProcessorWorker):
    _item_reader: Final[ItemReader]
    _map_run_record: MapRunRecord

    def __init__(
        self,
        work_name: str,
        job_pool: JobPool,
        env: Environment,
        item_reader: ItemReader,
        item_selector: Optional[ItemSelector],
        map_run_record: MapRunRecord,
    ):
        super().__init__(
            work_name=work_name, job_pool=job_pool, env=env, item_selector=item_selector
        )
        self._item_reader = item_reader
        self._map_run_record = map_run_record

    def _eval_job(self, job: Job) -> None:
        self._map_run_record.item_counter.total.count()
        self._map_run_record.item_counter.running.count()

        job_output = None
        env_frame: Environment = self._env.open_frame()
        try:
            env_frame.context_object_manager.context_object["Map"] = Map(
                Item=Item(Index=job.job_index, Value=job.job_input)
            )
            env_frame.event_history = (
                EventHistory()
            )  # Prevent dumping events on the program's event history.

            env_frame.inp = job.job_input
            self._eval_input(env_frame=env_frame)

            job.job_program.eval(env_frame)

            # TODO: verify behaviour with all of these scenarios.
            end_program_state: ProgramState = env_frame.program_state()
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
                job_output = env_frame.inp

        except EvalTimeoutError:
            self._map_run_record.item_counter.timed_out.count()

        except FailureEventException:
            self._map_run_record.item_counter.failed.count()

        except Exception:
            self._map_run_record.item_counter.failed.count()

        finally:
            self._map_run_record.item_counter.running.offset(-1)
            job.job_output = job_output
            self._job_pool.close_job(job)
            self._env.close_frame(env_frame)

    def eval(self) -> None:
        job: Optional[Job] = self._job_pool.next_job()
        while job is not None:
            self._map_run_record.execution_counter.total.count()
            self._map_run_record.execution_counter.running.count()
            self._eval_job(job=job)
            if self.stopped():
                break
            job = self._job_pool.next_job()
            self._map_run_record.execution_counter.succeeded.count()
            self._map_run_record.execution_counter.results_written.count()
            self._map_run_record.execution_counter.running.offset(-1)
