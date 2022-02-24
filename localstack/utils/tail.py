import os
import threading
from typing import Callable, Optional

from .platform import is_windows
from .run import ShellCommandThread, is_command_available
from .threads import FuncThread


class FileListener:
    """
    Platform independent `tail -f` command that calls a callback every time a new line is received on the file. If
    use_tail_command is set (which is the default if we're not on windows and the tail command is available),
    then a `tail -f` subprocess will be started. Otherwise the tailer library is used that uses polling with retry.
    """

    def __init__(self, file_path: str, callback: Callable[[str], None]):
        self.file_path = file_path
        self.callback = callback

        self.thread: Optional[FuncThread] = None
        self.started = threading.Event()

        self.use_tail_command = not is_windows() and is_command_available("tail")

    def start(self):
        self.thread = self._do_start_thread()
        self.started.wait()

        if self.thread.result_future.done():
            # this will re-raise exceptions from the run command that occurred before started was set
            self.thread.result_future.result()

    def join(self, timeout=None):
        if self.thread:
            self.thread.join(timeout=timeout)

    def close(self):
        if self.thread and self.thread.running:
            self.thread.stop()

        self.started.clear()
        self.thread = None

    def _do_start_thread(self) -> FuncThread:
        if self.use_tail_command:
            thread = self._create_tail_command_thread()
            thread.start()
            thread.started.wait(5)
            self.started.set()
        else:
            thread = self._create_tailer_thread()
            thread.start()

        return thread

    def _create_tail_command_thread(self) -> ShellCommandThread:
        def _log_listener(line, *args, **kwargs):
            try:
                self.callback(line.rstrip("\r\n"))
            except Exception:
                pass

        if not os.path.isfile(self.file_path):
            raise FileNotFoundError

        return ShellCommandThread(
            cmd=["tail", "-f", self.file_path], quiet=False, log_listener=_log_listener
        )

    def _create_tailer_thread(self) -> FuncThread:
        from tailer import Tailer

        tailer = Tailer(open(self.file_path), end=True)

        def _run_follow(*_):
            try:
                self.started.set()
                for line in tailer.follow(delay=0.25):
                    try:
                        self.callback(line)
                    except Exception:
                        pass
            finally:
                tailer.close()

        return FuncThread(func=_run_follow, on_stop=lambda *_: tailer.close())
