import io
import logging
import os
import re
import select
import subprocess
import sys
import threading
import time
from functools import lru_cache
from queue import Queue
from typing import Any, AnyStr, Callable, Dict, List, Optional, Union

from localstack import config

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.platform import is_linux, is_mac_os, is_windows  # noqa

from .threads import FuncThread, start_worker_thread

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
    cwd: str = None,
) -> Union[str, subprocess.Popen]:
    LOG.debug("Executing command: %s", cmd)
    env_dict = os.environ.copy() if inherit_env else {}
    if env_vars:
        env_dict.update(env_vars)
    env_dict = {k: to_str(str(v)) for k, v in env_dict.items()}

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
        if inherit_cwd and not cwd:
            cwd = os.getcwd()
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


def run_for_max_seconds(max_secs, _function, *args, **kwargs):
    """Run the given function for a maximum of `max_secs` seconds - continue running
    in a background thread if the function does not finish in time."""

    def _worker(*_args):
        try:
            fn_result = _function(*args, **kwargs)
        except Exception as e:
            fn_result = e

        fn_result = True if fn_result is None else fn_result
        q.put(fn_result)
        return fn_result

    start = time.time()
    q = Queue()
    start_worker_thread(_worker)
    for i in range(max_secs * 2):
        result = None
        try:
            result = q.get_nowait()
        except Exception:
            pass
        if result is not None:
            if isinstance(result, Exception):
                raise result
            return result
        if time.time() - start >= max_secs:
            return
        time.sleep(0.5)


def is_command_available(cmd: str) -> bool:
    try:
        run("which %s" % cmd, print_error=False)
        return True
    except Exception:
        return False


def kill_process_tree(parent_pid):
    # Note: Do NOT import "psutil" at the root scope
    import psutil

    parent_pid = getattr(parent_pid, "pid", None) or parent_pid
    parent = psutil.Process(parent_pid)
    for child in parent.children(recursive=True):
        try:
            child.kill()
        except Exception:
            pass
    parent.kill()


def is_root() -> bool:
    return get_os_user() == "root"


@lru_cache()
def get_os_user() -> str:
    # using getpass.getuser() seems to be reporting a different/invalid user in Docker/MacOS
    return run("whoami").strip()


def to_str(obj: Union[str, bytes], errors="strict"):
    return obj.decode(config.DEFAULT_ENCODING, errors) if isinstance(obj, bytes) else obj


class ShellCommandThread(FuncThread):
    """Helper class to run a shell command in a background thread."""

    def __init__(
        self,
        cmd: Union[str, List[str]],
        params: Any = None,
        outfile: Union[str, int] = None,
        env_vars: Dict[str, str] = None,
        stdin: bool = False,
        auto_restart: bool = False,
        quiet: bool = True,
        inherit_cwd: bool = False,
        inherit_env: bool = True,
        log_listener: Callable = None,
        stop_listener: Callable = None,
        strip_color: bool = False,
    ):
        params = params if params is not None else {}
        env_vars = env_vars if env_vars is not None else {}
        self.stopped = False
        self.cmd = cmd
        self.process = None
        self.outfile = outfile
        self.stdin = stdin
        self.env_vars = env_vars
        self.inherit_cwd = inherit_cwd
        self.inherit_env = inherit_env
        self.auto_restart = auto_restart
        self.log_listener = log_listener
        self.stop_listener = stop_listener
        self.strip_color = strip_color
        self.started = threading.Event()
        FuncThread.__init__(self, self.run_cmd, params, quiet=quiet)

    def run_cmd(self, params):
        while True:
            self.do_run_cmd()
            from localstack.utils import common

            if (
                common.INFRA_STOPPED  # FIXME: this is the wrong level of abstraction
                or not self.auto_restart
                or not self.process
                or self.process.returncode == 0
            ):
                return self.process.returncode if self.process else None
            LOG.info(
                "Restarting process (received exit code %s): %s", self.process.returncode, self.cmd
            )

    def do_run_cmd(self):
        def convert_line(line):
            line = to_str(line or "")
            if self.strip_color:
                # strip color codes
                line = re.sub(r"\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))", "", line)
            return "%s\r\n" % line.strip()

        def filter_line(line):
            """Return True if this line should be filtered, i.e., not printed"""
            return "(Press CTRL+C to quit)" in line

        outfile = self.outfile or os.devnull
        if self.log_listener and outfile == os.devnull:
            outfile = subprocess.PIPE
        try:
            self.process = run(
                self.cmd,
                asynchronous=True,
                stdin=self.stdin,
                outfile=outfile,
                env_vars=self.env_vars,
                inherit_cwd=self.inherit_cwd,
                inherit_env=self.inherit_env,
            )
            self.started.set()
            if outfile:
                if outfile == subprocess.PIPE:
                    # get stdout/stderr from child process and write to parent output
                    streams = (
                        (self.process.stdout, sys.stdout),
                        (self.process.stderr, sys.stderr),
                    )
                    for instream, outstream in streams:
                        if not instream:
                            continue
                        for line in iter(instream.readline, None):
                            # `line` should contain a newline at the end as we're iterating,
                            # hence we can safely break the loop if `line` is None or empty string
                            if line in [None, "", b""]:
                                break
                            if not (line and line.strip()) and self.is_killed():
                                break
                            line = convert_line(line)
                            if filter_line(line):
                                continue
                            if self.log_listener:
                                self.log_listener(line, stream=instream)
                            if self.outfile not in [None, os.devnull]:
                                outstream.write(line)
                                outstream.flush()
                if self.process:
                    self.process.wait()
            else:
                self.process.communicate()
        except Exception as e:
            self.result_future.set_exception(e)
            if self.process and not self.quiet:
                LOG.warning('Shell command error "%s": %s', e, self.cmd)
        if self.process and not self.quiet and self.process.returncode != 0:
            LOG.warning('Shell command exit code "%s": %s', self.process.returncode, self.cmd)

    def is_killed(self):
        from localstack.utils import common

        if not self.process:
            return True
        if common.INFRA_STOPPED:  # FIXME
            return True
        # Note: Do NOT import "psutil" at the root scope, as this leads
        # to problems when importing this file from our test Lambdas in Docker
        # (Error: libc.musl-x86_64.so.1: cannot open shared object file)
        import psutil

        return not psutil.pid_exists(self.process.pid)

    def stop(self, quiet=False):
        if self.stopped:
            return
        if not self.process:
            LOG.warning("No process found for command '%s'", self.cmd)
            return

        parent_pid = self.process.pid
        try:
            kill_process_tree(parent_pid)
            self.process = None
        except Exception as e:
            if not quiet:
                LOG.warning("Unable to kill process with pid %s: %s", parent_pid, e)
        try:
            self.stop_listener and self.stop_listener(self)
        except Exception as e:
            if not quiet:
                LOG.warning("Unable to run stop handler for shell command thread %s: %s", self, e)
        self.stopped = True


class CaptureOutput(object):
    """A context manager that captures stdout/stderr of the current thread. Use it as follows:

    with CaptureOutput() as c:
        ...
    print(c.stdout(), c.stderr())
    """

    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    orig___stdout = sys.__stdout__
    orig___stderr = sys.__stderr__
    CONTEXTS_BY_THREAD = {}

    class LogStreamIO(io.StringIO):
        def write(self, s):
            if isinstance(s, str) and hasattr(s, "decode"):
                s = s.decode("unicode-escape")
            return super(CaptureOutput.LogStreamIO, self).write(s)

    def __init__(self):
        self._stdout = self.LogStreamIO()
        self._stderr = self.LogStreamIO()

    def __enter__(self):
        # Note: import werkzeug here (not at top of file) to allow dependency pruning
        from werkzeug.local import LocalProxy

        ident = self._ident()
        if ident not in self.CONTEXTS_BY_THREAD:
            self.CONTEXTS_BY_THREAD[ident] = self
            self._set(
                LocalProxy(self._proxy(sys.stdout, "stdout")),
                LocalProxy(self._proxy(sys.stderr, "stderr")),
                LocalProxy(self._proxy(sys.__stdout__, "stdout")),
                LocalProxy(self._proxy(sys.__stderr__, "stderr")),
            )
        return self

    def __exit__(self, type, value, traceback):
        ident = self._ident()
        removed = self.CONTEXTS_BY_THREAD.pop(ident, None)
        if not self.CONTEXTS_BY_THREAD:
            # reset pointers
            self._set(
                self.orig_stdout,
                self.orig_stderr,
                self.orig___stdout,
                self.orig___stderr,
            )
        # get value from streams
        removed._stdout.flush()
        removed._stderr.flush()
        out = removed._stdout.getvalue()
        err = removed._stderr.getvalue()
        # close handles
        removed._stdout.close()
        removed._stderr.close()
        removed._stdout = out
        removed._stderr = err

    def _set(self, out, err, __out, __err):
        sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__ = (
            out,
            err,
            __out,
            __err,
        )

    def _proxy(self, original_stream, type):
        def proxy():
            ident = self._ident()
            ctx = self.CONTEXTS_BY_THREAD.get(ident)
            if ctx:
                return ctx._stdout if type == "stdout" else ctx._stderr
            return original_stream

        return proxy

    def _ident(self):
        # TODO: On some systems we seem to be running into a stack overflow with LAMBDA_EXECUTOR=local here!
        return threading.current_thread().ident

    def stdout(self):
        return self._stream_value(self._stdout)

    def stderr(self):
        return self._stream_value(self._stderr)

    def _stream_value(self, stream):
        return stream.getvalue() if hasattr(stream, "getvalue") else stream
