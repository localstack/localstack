import copy
import logging
import threading
from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

LOG = logging.getLogger(__name__)


class Job:
    job_index: Final[int]
    job_program: Final[Program]
    job_input: Final[Optional[Any]]
    job_output: Optional[Any]

    def __init__(self, job_index: int, job_program: Program, job_input: Optional[Any]):
        self.job_index = job_index
        self.job_program = job_program
        self.job_input = job_input
        self.job_output = None


class JobClosed:
    job_index: Final[int]
    job_output: Optional[Any]

    def __init__(self, job_index: int, job_output: Optional[Any]):
        self.job_index = job_index
        self.job_output = job_output

    def __hash__(self):
        return hash(self.job_index)


class JobPool:
    _mutex: Final[threading.Lock]
    _termination_event: Final[threading.Event]
    _worker_exception: Optional[Exception]

    _jobs_number: Final[int]
    _open_jobs: Final[list[Job]]
    _closed_jobs: Final[set[JobClosed]]

    def __init__(self, job_program: Program, job_inputs: list[Any]):
        self._mutex = threading.Lock()
        self._termination_event = threading.Event()
        self._worker_exception = None

        self._jobs_number = len(job_inputs)
        self._open_jobs = [
            Job(job_index=job_index, job_program=job_program, job_input=job_input)
            for job_index, job_input in enumerate(job_inputs)
        ]
        self._open_jobs.reverse()
        self._closed_jobs = set()

    def next_job(self) -> Optional[Any]:
        with self._mutex:
            if self._worker_exception is not None:
                return None
            try:
                return self._open_jobs.pop()
            except IndexError:
                return None

    def _is_terminated(self) -> bool:
        return len(self._closed_jobs) == self._jobs_number or self._worker_exception is not None

    def _notify_on_termination(self) -> None:
        if self._is_terminated():
            self._termination_event.set()

    def get_worker_exception(self) -> Optional[Exception]:
        return self._worker_exception

    def close_job(self, job: Job) -> None:
        with self._mutex:
            if self._is_terminated():
                return

            if job in self._closed_jobs:
                LOG.warning(
                    "Duplicate execution of Job with index '%s' and input '%s'",
                    job.job_index,
                    to_json_str(job.job_input),
                )

            if isinstance(job.job_output, Exception):
                self._worker_exception = job.job_output
            else:
                self._closed_jobs.add(JobClosed(job_index=job.job_index, job_output=job.job_output))

            self._notify_on_termination()

    def get_closed_jobs(self) -> list[JobClosed]:
        with self._mutex:
            closed_jobs = copy.deepcopy(self._closed_jobs)
        return sorted(closed_jobs, key=lambda closed_job: closed_job.job_index)

    def await_jobs(self) -> None:
        if not self._is_terminated():
            self._termination_event.wait()
