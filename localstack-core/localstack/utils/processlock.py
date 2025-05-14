import atexit
import logging
import os
import time
from pathlib import Path
from typing import Callable

from filelock import FileLock

from localstack.logging.setup import setup_logging_from_config
from localstack.utils.functions import run_safe

LOG = logging.getLogger(__name__)
logging.getLogger("filelock").setLevel(logging.WARNING)


class CrossProcessCriticalSection:
    def __init__(self, name: str, work: Callable[[], None]):
        self.name = name
        self.work = work
        self.lockfile = Path(f"/tmp/my_task.{name}.lock")
        self.donefile = Path(f"/tmp/my_task.{name}.done")
        self.lock_timeout = 60  # seconds

        self.pid = os.getpid()

    def run_once(self):
        self._log("waiting for lock")
        with FileLock(str(self.lockfile), timeout=self.lock_timeout):
            self._log("lock achieved")
            if self.donefile.is_file():
                self._log("work already complete")
                # we are not the first process so end this critical section
                return

            # we are the first to reach this critical section, so make sure the done file does not exist
            # and run the work
            self._log("registering atexit")
            atexit.register(self.cleanup)

            with self.donefile.open("w") as outfile:
                outfile.write("1")

            self._log("starting work")
            self.work()
            self._log("work finished")

            run_safe(lambda: os.remove(self.lockfile))

    def cleanup(self):
        self._log("cleaning up")
        for path in [self.lockfile, self.donefile]:
            run_safe(lambda: os.remove(path))

    def _log(self, message: str):
        LOG.debug("[%s:%d] %s", self.name, self.pid, message)


def __main__():
    setup_logging_from_config()

    def work():
        print("Should only run once")
        time.sleep(10)

    cpcs = CrossProcessCriticalSection(work)
    cpcs.run_once()

    time.sleep(5)


if __name__ == "__main__":
    __main__()
