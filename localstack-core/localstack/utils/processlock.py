import atexit
import os
from pathlib import Path
from typing import Callable

from filelock import FileLock

LOCKFILE = Path("/tmp/my_task.lock")
DONEFILE = Path("/tmp/my_task.done")
PIDFILE = Path("/tmp/my_task.pids")
LOCK_TIMEOUT = 60  # seconds


class CrossProcessCriticalSection:
    def __init__(self, work: Callable[[], None] | None = None):
        self.work = work
        self.pid = os.getpid()

    def _log(self, message: str):
        print(f"[{self.pid}]: {message}")

    def run_once(self):
        if not self.work:
            raise RuntimeError("Work not defined")

        self._log("waiting for file lock")
        with FileLock(str(LOCKFILE), timeout=LOCK_TIMEOUT):
            self._log("got file lock")
            if DONEFILE.is_file():
                self._log("donefile exists, exiting critical section")
                # we are not the first process so end this critical section
                return

            # we are the first to reach this critical section, so make sure the done file does not exist
            # and run the work
            self._log("donefile does not exist, registering cleanup")
            atexit.register(self.cleanup)

            self._log("adding donefile")
            with DONEFILE.open("w") as outfile:
                outfile.write("1")

            self._log("performing work")
            self.work()
            self._log("work finished")

        self._log("ended critical section")

    def cleanup(self):
        self._log("cleaning up")
        os.remove(DONEFILE)
