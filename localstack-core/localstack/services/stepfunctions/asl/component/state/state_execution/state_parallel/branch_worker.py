import abc
import logging
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import Timestamp
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.threads import TMP_THREADS

LOG = logging.getLogger(__name__)


class BranchWorker:
    class BranchWorkerComm(abc.ABC):
        @abc.abstractmethod
        def on_terminated(self, env: Environment): ...

    _branch_worker_comm: Final[BranchWorkerComm]
    _program: Final[Program]
    _worker_thread: Optional[threading.Thread]
    env: Final[Environment]

    def __init__(self, branch_worker_comm: BranchWorkerComm, program: Program, env: Environment):
        self._branch_worker_comm = branch_worker_comm
        self._program = program
        self.env = env
        self._worker_thread = None

    def _thread_routine(self) -> None:
        LOG.info(f"[BranchWorker] [launched] [id: {self._worker_thread.native_id}]")
        self._program.eval(self.env)
        LOG.info(f"[BranchWorker] [terminated] [id: {self._worker_thread.native_id}]")
        self._branch_worker_comm.on_terminated(env=self.env)

    def start(self):
        if self._worker_thread is not None:
            raise RuntimeError(f"Attempted to rerun BranchWorker for program ${self._program}.")

        self._worker_thread = threading.Thread(
            target=self._thread_routine, name=f"BranchWorker_${self._program}"
        )
        TMP_THREADS.append(self._worker_thread)
        self._worker_thread.start()

    def stop(self, stop_date: Timestamp, cause: Optional[str], error: Optional[str]) -> None:
        env = self.env
        if env:
            try:
                env.set_stop(stop_date, cause, error)
            except Exception:
                # Ignore closing exceptions, this method attempts to release resources earlier.
                pass
