import logging
import threading
from typing import Optional

from localstack.aws.api.stepfunctions import Timestamp
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.eval.count_down_latch import CountDownLatch
from localstack.services.stepfunctions.asl.eval.environment import Environment

LOG = logging.getLogger(__name__)


class ProgramWorker:
    def __init__(self):
        self._worker_thread: Optional[threading.Thread] = None
        self.env_frame: Optional[Environment] = None

    def _worker_routine(self, program: Program, latch: CountDownLatch) -> None:
        # TODO: exception handling.
        LOG.info(f"[ProgramWorker] [launched] [id: {self._worker_thread.native_id}]")
        print(f"[ProgramWorker] [launched] [id: {self._worker_thread.native_id}]")

        program.eval(self.env_frame)

        LOG.info(f"[ProgramWorker] [terminated] [id: {self._worker_thread.native_id}]")
        print(f"[ProgramWorker] [terminated] [id: {self._worker_thread.native_id}]")

        self._worker_thread = None
        latch.count_down()

    def eval(self, program: Program, env_frame: Environment, latch: CountDownLatch):
        if self._worker_thread is not None:
            raise RuntimeError("Call to ProgramWorker.eval whilst another job is running.")
        self.env_frame = env_frame
        self._worker_thread = threading.Thread(target=self._worker_routine, args=(program, latch))
        self._worker_thread.start()

    def stop(self, stop_date: Timestamp, cause: Optional[str], error: Optional[str]) -> None:
        env = self.env_frame
        if env:
            env.set_stop(stop_date, cause, error)
