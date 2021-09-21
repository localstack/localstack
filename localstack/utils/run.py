import inspect
import logging
import os
import select
import subprocess
import sys
import threading
import traceback
from concurrent.futures import Future
from typing import AnyStr, Dict, List, Optional, Union

from localstack import config

LOG = logging.getLogger(__name__)


def run(
    cmd: Union[str, List[str]],
    print_error=True,
    asynchronous=False,
    stdin=False,
    stderr=subprocess.STDOUT,
    outfile=None,
    env_vars: Optional[Dict[AnyStr, AnyStr]] = None,
    inherit_cwd=False,
    inherit_env=True,
    tty=False,
    shell=True,
) -> Union[str, subprocess.Popen]:
    LOG.debug("Executing command: %s", cmd)
    env_dict = os.environ.copy() if inherit_env else {}
    if env_vars:
        env_dict.update(env_vars)
    env_dict = dict([(k, to_str(str(v))) for k, v in env_dict.items()])

    if isinstance(cmd, list):
        # See docs of subprocess.Popen(...):
        #  "On POSIX with shell=True, the shell defaults to /bin/sh. If args is a string,
        #   the string specifies the command to execute through the shell. [...] If args is
        #   a sequence, the first item specifies the command string, and any additional
        #   items will be treated as additional arguments to the shell itself."
        # Hence, we should *disable* shell mode here to be on the safe side, to prevent
        #  arguments in the cmd list from leaking into arguments to the shell itself. This will
        #  effectively allow us to call run(..) with both - str and list - as cmd argument, although
        #  over time we should move from "cmd: Union[str, List[str]]" to "cmd: List[str]" only.
        shell = False

    if tty:
        asynchronous = True
        stdin = True

    try:
        cwd = os.getcwd() if inherit_cwd else None
        if not asynchronous:
            if stdin:
                return subprocess.check_output(
                    cmd, shell=shell, stderr=stderr, env=env_dict, stdin=subprocess.PIPE, cwd=cwd
                )
            output = subprocess.check_output(cmd, shell=shell, stderr=stderr, env=env_dict, cwd=cwd)
            return output.decode(config.DEFAULT_ENCODING)

        stdin_arg = subprocess.PIPE if stdin else None
        stdout_arg = open(outfile, "ab") if isinstance(outfile, str) else outfile
        stderr_arg = stderr
        if tty:
            # Note: leave the "pty" import here (not supported in Windows)
            import pty

            master_fd, slave_fd = pty.openpty()
            stdin_arg = slave_fd
            stdout_arg = stderr_arg = None

        # start the actual sub process
        kwargs = {}
        if is_linux() or is_mac_os():
            kwargs["start_new_session"] = True
        process = subprocess.Popen(
            cmd,
            shell=shell,
            stdin=stdin_arg,
            bufsize=-1,
            stderr=stderr_arg,
            stdout=stdout_arg,
            env=env_dict,
            cwd=cwd,
            **kwargs,
        )

        if tty:
            # based on: https://stackoverflow.com/questions/41542960
            def pipe_streams(*args):
                while process.poll() is None:
                    r, w, e = select.select([sys.stdin, master_fd], [], [])
                    if sys.stdin in r:
                        d = os.read(sys.stdin.fileno(), 10240)
                        os.write(master_fd, d)
                    elif master_fd in r:
                        o = os.read(master_fd, 10240)
                        if o:
                            os.write(sys.stdout.fileno(), o)

            FuncThread(pipe_streams).start()

        return process
    except subprocess.CalledProcessError as e:
        if print_error:
            print("ERROR: '%s': exit code %s; output: %s" % (cmd, e.returncode, e.output))
            sys.stdout.flush()
        raise e


def is_mac_os() -> bool:
    return "Darwin" in get_uname()


def is_linux() -> bool:
    return "Linux" in get_uname()


def get_uname() -> str:
    try:
        return to_str(subprocess.check_output("uname -a", shell=True))
    except Exception:
        return ""


def to_str(obj: Union[str, bytes], errors="strict"):
    return obj.decode(config.DEFAULT_ENCODING, errors) if isinstance(obj, bytes) else obj


class FuncThread(threading.Thread):
    """Helper class to run a Python function in a background thread."""

    def __init__(self, func, params=None, quiet=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self.params = params
        self.func = func
        self.quiet = quiet
        self.result_future = Future()
        self._stop_event = threading.Event()

    def run(self):
        result = None
        try:
            kwargs = {}
            argspec = inspect.getfullargspec(self.func)
            if argspec.varkw or "_thread" in (argspec.args or []) + (argspec.kwonlyargs or []):
                kwargs["_thread"] = self
            result = self.func(self.params, **kwargs)
        except Exception as e:
            self.result_future.set_exception(e)
            result = e
            if not self.quiet:
                LOG.info(
                    "Thread run method %s(%s) failed: %s %s"
                    % (self.func, self.params, e, traceback.format_exc())
                )
        finally:
            try:
                self.result_future.set_result(result)
            except Exception:
                # this can happen as InvalidStateError on shutdown, if the task is already canceled
                pass

    @property
    def running(self):
        return not self._stop_event.is_set()

    def stop(self, quiet=False):
        self._stop_event.set()
