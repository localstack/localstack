import base64
import binascii
import functools
import glob
import hashlib
import inspect
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from multiprocessing.dummy import Pool
from queue import Queue
from typing import Any, Callable, Dict, List, Optional, Sized, Tuple, Union

import cachetools

import localstack.utils.run
from localstack import config
from localstack.constants import ENV_DEV

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.archives import is_zip_file, untar, unzip  # noqa

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.collections import (  # noqa
    DelSafeDict,
    HashableList,
    PaginatedList,
    ensure_list,
    is_list_or_tuple,
    is_sub_dict,
    items_equivalent,
    last_index_of,
    merge_dicts,
    merge_recursive,
    remove_attributes,
    remove_none_values_from_dict,
    rename_attributes,
    select_attributes,
    to_unique_items_list,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.files import (  # noqa
    TMP_FILES,
    chmod_r,
    chown_r,
    cleanup_tmp_files,
    cp_r,
    disk_usage,
    ensure_readable,
    file_exists_not_empty,
    get_or_create_file,
    is_empty_dir,
    load_file,
    mkdir,
    new_tmp_dir,
    new_tmp_file,
    replace_in_file,
    rm_rf,
    save_file,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.http import (  # noqa
    NetrcBypassAuth,
    _RequestsSafe,
    download,
    get_proxies,
    make_http_request,
    parse_request_data,
    safe_requests,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.json import (  # noqa
    CustomEncoder,
    JsonObject,
    assign_to_path,
    canonical_json,
    clone,
    clone_safe,
    extract_from_jsonpointer_path,
    extract_jsonpath,
    fix_json_keys,
    json_safe,
    parse_json_or_yaml,
    try_json,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.net import (  # noqa
    get_free_tcp_port,
    is_ip_address,
    is_ipv4_address,
    is_port_open,
    port_can_be_bound,
    resolve_hostname,
    wait_for_port_closed,
    wait_for_port_open,
    wait_for_port_status,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.numbers import format_bytes, format_number, is_number  # noqa

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.objects import (  # noqa
    ArbitraryAccessObj,
    Mock,
    ObjectIdHashComparator,
    SubtypesInstanceManager,
    fully_qualified_class_name,
    get_all_subclasses,
    keys_to_lower,
    not_none_or,
    recurse_object,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.platform import (  # noqa
    get_arch,
    get_os,
    in_docker,
    is_debian,
    is_linux,
    is_mac_os,
    is_windows,
)
from localstack.utils.run import FuncThread

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.strings import (  # noqa
    camel_to_snake_case,
    canonicalize_bool_to_str,
    convert_to_printable_chars,
    first_char_to_lower,
    first_char_to_upper,
    is_base64,
    is_string,
    is_string_or_bytes,
    snake_to_camel_case,
    str_insert,
    str_remove,
    str_startswith_ignore_case,
    str_to_bool,
    to_bytes,
    to_str,
    truncate,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.sync import (  # noqa
    poll_condition,
    retry,
    sleep_forever,
    synchronized,
    wait_until,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.time import (  # noqa
    TIMESTAMP_FORMAT,
    TIMESTAMP_FORMAT_MICROS,
    TIMESTAMP_FORMAT_TZ,
    epoch_timestamp,
    isoformat_milliseconds,
    mktime,
    now,
    now_utc,
    parse_timestamp,
    timestamp,
    timestamp_millis,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.xml import obj_to_xml, strip_xmlns  # noqa

# set up logger
LOG = logging.getLogger(__name__)

# arrays for temporary files and resources
TMP_THREADS = []
TMP_PROCESSES = []

# cache clean variables
CACHE_CLEAN_TIMEOUT = 60 * 5
CACHE_MAX_AGE = 60 * 60
CACHE_FILE_PATTERN = os.path.join(tempfile.gettempdir(), "_random_dir_", "cache.*.json")
last_cache_clean_time = {"time": 0}
MUTEX_CLEAN = threading.Lock()

# misc. constants
CODEC_HANDLER_UNDERSCORE = "underscore"

# flag to indicate whether we've received and processed the stop signal
INFRA_STOPPED = False

# generic cache object
CACHE = {}

# lock for creating certificate files
SSL_CERT_LOCK = threading.RLock()

# markers that indicate the start/end of sections in PEM cert files
PEM_CERT_START = "-----BEGIN CERTIFICATE-----"
PEM_CERT_END = "-----END CERTIFICATE-----"
PEM_KEY_START_REGEX = r"-----BEGIN(.*)PRIVATE KEY-----"
PEM_KEY_END_REGEX = r"-----END(.*)PRIVATE KEY-----"

# user of the currently running process
CACHED_USER = None


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
        params = not_none_or(params, {})
        env_vars = not_none_or(env_vars, {})
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
            if (
                INFRA_STOPPED
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
        if not self.process:
            return True
        if INFRA_STOPPED:
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


class FileMappedDocument(dict):
    """A dictionary that is mapped to a json document on disk.

    When the document is created, an attempt is made to load existing contents from disk. To load changes from
    concurrent writes, run load(). To save and overwrite the current document on disk, run save().
    """

    path: Union[str, os.PathLike]

    def __init__(self, path: Union[str, os.PathLike], mode=0o664):
        super().__init__()
        self.path = path
        self.mode = mode
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return

        if os.path.isdir(self.path):
            raise IsADirectoryError

        with open(self.path, "r") as fd:
            self.update(json.load(fd))

    def save(self):
        if os.path.isdir(self.path):
            raise IsADirectoryError

        if not os.path.exists(self.path):
            mkdir(os.path.dirname(self.path))

        def opener(path, flags):
            _fd = os.open(path, flags, self.mode)
            os.chmod(path, mode=self.mode, follow_symlinks=True)
            return _fd

        with open(self.path, "w", opener=opener) as fd:
            json.dump(self, fd)


class PortNotAvailableException(Exception):
    """Exception which indicates that the ExternalServicePortsManager could not reserve a port."""

    pass


class ExternalServicePortsManager:
    """Manages the ports used for starting external services like ElasticSearch, OpenSearch,..."""

    def __init__(self):
        # cache for locally available ports (ports are reserved for a short period of a few seconds)
        self._PORTS_CACHE = cachetools.TTLCache(maxsize=100, ttl=6)
        self._PORTS_LOCK = threading.RLock()

    def reserve_port(self, port: int = None) -> int:
        """
        Reserves the given port (if it is still free). If the given port is None, it reserves a free port from the
        configured port range for external services. If a port is given, it has to be within the configured
        range of external services (i.e. in [config#EXTERNAL_SERVICE_PORTS_START, config#EXTERNAL_SERVICE_PORTS_END)).
        :param port: explicit port to check or None if a random port from the configured range should be selected
        :return: reserved, free port number (int)
        :raises: PortNotAvailableException if the given port is outside the configured range, it is already bound or
                    reserved, or if the given port is none and there is no free port in the configured service range.
        """
        ports_range = range(config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END)
        if port is not None and port not in ports_range:
            raise PortNotAvailableException(
                f"The requested port ({port}) is not in the configured external "
                f"service port range ({ports_range})."
            )
        with self._PORTS_LOCK:
            if port is not None:
                return self._check_port(port)
            else:
                for port_in_range in ports_range:
                    try:
                        return self._check_port(port_in_range)
                    except PortNotAvailableException:
                        # We ignore the fact that this single port is reserved, we just check the next one
                        pass
        raise PortNotAvailableException(
            "No free network ports available to start service instance (currently reserved: %s)",
            list(self._PORTS_CACHE.keys()),
        )

    def _check_port(self, port: int) -> int:
        """Checks if the given port is currently not reserved and can be bound."""
        if not self._PORTS_CACHE.get(port) and port_can_be_bound(port):
            # reserve the port for a short period of time
            self._PORTS_CACHE[port] = "__reserved__"
            return port
        else:
            raise PortNotAvailableException(f"The given port ({port}) is already reserved.")


external_service_ports = ExternalServicePortsManager()


# ----------------
# UTILITY METHODS
# ----------------


def start_thread(method, *args, **kwargs) -> FuncThread:
    """Start the given method in a background thread, and add the thread to the TMP_THREADS shutdown hook"""
    _shutdown_hook = kwargs.pop("_shutdown_hook", True)
    thread = FuncThread(method, *args, **kwargs)
    thread.start()
    if _shutdown_hook:
        TMP_THREADS.append(thread)
    return thread


def start_worker_thread(method, *args, **kwargs):
    return start_thread(method, *args, _shutdown_hook=False, **kwargs)


def empty_context_manager():
    import contextlib

    return contextlib.nullcontext()


def prevent_stack_overflow(match_parameters=False):
    """Function decorator to protect a function from stack overflows -
    raises an exception if a (potential) infinite recursion is detected."""

    def _decorator(wrapped):
        @functools.wraps(wrapped)
        def func(*args, **kwargs):
            def _matches(frame):
                if frame.function != wrapped.__name__:
                    return False
                frame = frame.frame

                if not match_parameters:
                    return False

                # construct dict of arguments this stack frame has been called with
                prev_call_args = {
                    frame.f_code.co_varnames[i]: frame.f_locals[frame.f_code.co_varnames[i]]
                    for i in range(frame.f_code.co_argcount)
                }

                # construct dict of arguments the original function has been called with
                sig = inspect.signature(wrapped)
                this_call_args = dict(zip(sig.parameters.keys(), args))
                this_call_args.update(kwargs)

                return prev_call_args == this_call_args

            matching_frames = [frame[2] for frame in inspect.stack(context=1) if _matches(frame)]
            if matching_frames:
                raise RecursionError("(Potential) infinite recursion detected")
            return wrapped(*args, **kwargs)

        return func

    return _decorator


def md5(string: Union[str, bytes]) -> str:
    m = hashlib.md5()
    m.update(to_bytes(string))
    return m.hexdigest()


def path_from_url(url: str) -> str:
    return "/%s" % str(url).partition("://")[2].partition("/")[2] if "://" in url else url


def get_service_protocol():
    return "https" if config.USE_SSL else "http"


def edge_ports_info():
    if config.EDGE_PORT_HTTP:
        result = "ports %s/%s" % (config.EDGE_PORT, config.EDGE_PORT_HTTP)
    else:
        result = "port %s" % config.EDGE_PORT
    result = "%s %s" % (get_service_protocol(), result)
    return result


def base64_to_hex(b64_string: str) -> bytes:
    return binascii.hexlify(base64.b64decode(b64_string))


def is_command_available(cmd: str) -> bool:
    try:
        run("which %s" % cmd, print_error=False)
        return True
    except Exception:
        return False


def short_uid() -> str:
    return str(uuid.uuid4())[0:8]


def long_uid() -> str:
    return str(uuid.uuid4())


def cleanup(files=True, env=ENV_DEV, quiet=True):
    if files:
        cleanup_tmp_files()


def cleanup_threads_and_processes(quiet=True):
    for thread in TMP_THREADS:
        if thread:
            try:
                # LOG.debug('[shutdown] Cleaning up thread: %s', thread)
                if hasattr(thread, "shutdown"):
                    thread.shutdown()
                    continue
                if hasattr(thread, "kill"):
                    thread.kill()
                    continue
                thread.stop(quiet=quiet)
            except Exception as e:
                print(e)
    for proc in TMP_PROCESSES:
        try:
            # LOG.debug('[shutdown] Cleaning up process: %s', proc)
            kill_process_tree(proc.pid)
            # proc.terminate()
        except Exception as e:
            print(e)
    # clean up async tasks
    try:
        import asyncio

        for task in asyncio.all_tasks():
            try:
                # LOG.debug('[shutdown] Canceling asyncio task: %s', task)
                task.cancel()
            except Exception as e:
                print(e)
    except Exception:
        pass
    LOG.debug("[shutdown] Done cleaning up threads / processes / tasks")
    # clear lists
    TMP_THREADS.clear()
    TMP_PROCESSES.clear()


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


def is_root():
    return get_os_user() == "root"


def get_os_user():
    global CACHED_USER
    if not CACHED_USER:
        # TODO: using getpass.getuser() seems to be reporting a different/invalid user in Docker/MacOS
        # import getpass
        # CACHED_USER = getpass.getuser()
        CACHED_USER = run("whoami").strip()
    return CACHED_USER


def cleanup_resources():
    cleanup_tmp_files()
    cleanup_threads_and_processes()


@synchronized(lock=SSL_CERT_LOCK)
def generate_ssl_cert(
    target_file=None,
    overwrite=False,
    random=False,
    return_content=False,
    serial_number=None,
):
    # Note: Do NOT import "OpenSSL" at the root scope
    # (Our test Lambdas are importing this file but don't have the module installed)
    from OpenSSL import crypto

    def all_exist(*files):
        return all(os.path.exists(f) for f in files)

    def store_cert_key_files(base_filename):
        key_file_name = "%s.key" % base_filename
        cert_file_name = "%s.crt" % base_filename
        # TODO: Cleaner code to load the cert dynamically
        # extract key and cert from target_file and store into separate files
        content = load_file(target_file)
        key_start = re.search(PEM_KEY_START_REGEX, content)
        key_start = key_start.group(0)
        key_end = re.search(PEM_KEY_END_REGEX, content)
        key_end = key_end.group(0)
        key_content = content[content.index(key_start) : content.index(key_end) + len(key_end)]
        cert_content = content[
            content.index(PEM_CERT_START) : content.rindex(PEM_CERT_END) + len(PEM_CERT_END)
        ]
        save_file(key_file_name, key_content)
        save_file(cert_file_name, cert_content)
        return cert_file_name, key_file_name

    if target_file and not overwrite and os.path.exists(target_file):
        try:
            cert_file_name, key_file_name = store_cert_key_files(target_file)
        except Exception as e:
            # fall back to temporary files if we cannot store/overwrite the files above
            LOG.info(
                "Error storing key/cert SSL files (falling back to random tmp file names): %s", e
            )
            target_file_tmp = new_tmp_file()
            cert_file_name, key_file_name = store_cert_key_files(target_file_tmp)
        if all_exist(cert_file_name, key_file_name):
            return target_file, cert_file_name, key_file_name
    if random and target_file:
        if "." in target_file:
            target_file = target_file.replace(".", ".%s." % short_uid(), 1)
        else:
            target_file = "%s.%s" % (target_file, short_uid())

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    subj = cert.get_subject()
    subj.C = "AU"
    subj.ST = "Some-State"
    subj.L = "Some-Locality"
    subj.O = "LocalStack Org"  # noqa
    subj.OU = "Testing"
    subj.CN = "localhost"
    # Note: new requirements for recent OSX versions: https://support.apple.com/en-us/HT210176
    # More details: https://www.iol.unh.edu/blog/2019/10/10/macos-catalina-and-chrome-trust
    serial_number = serial_number or 1001
    cert.set_version(2)
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(2 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    alt_names = (
        b"DNS:localhost,DNS:test.localhost.atlassian.io,DNS:localhost.localstack.cloud,IP:127.0.0.1"
    )
    cert.add_extensions(
        [
            crypto.X509Extension(b"subjectAltName", False, alt_names),
            crypto.X509Extension(b"basicConstraints", True, b"CA:false"),
            crypto.X509Extension(
                b"keyUsage", True, b"nonRepudiation,digitalSignature,keyEncipherment"
            ),
            crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
        ]
    )
    cert.sign(k, "SHA256")

    cert_file = io.StringIO()
    key_file = io.StringIO()
    cert_file.write(to_str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
    key_file.write(to_str(crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))
    cert_file_content = cert_file.getvalue().strip()
    key_file_content = key_file.getvalue().strip()
    file_content = "%s\n%s" % (key_file_content, cert_file_content)
    if target_file:
        key_file_name = "%s.key" % target_file
        cert_file_name = "%s.crt" % target_file
        # check existence to avoid permission denied issues:
        # https://github.com/localstack/localstack/issues/1607
        if not all_exist(target_file, key_file_name, cert_file_name):
            for i in range(2):
                try:
                    save_file(target_file, file_content)
                    save_file(key_file_name, key_file_content)
                    save_file(cert_file_name, cert_file_content)
                    break
                except Exception as e:
                    if i > 0:
                        raise
                    LOG.info(
                        "Unable to store certificate file under %s, using tmp file instead: %s",
                        target_file,
                        e,
                    )
                    # Fix for https://github.com/localstack/localstack/issues/1743
                    target_file = "%s.pem" % new_tmp_file()
                    key_file_name = "%s.key" % target_file
                    cert_file_name = "%s.crt" % target_file
            TMP_FILES.append(target_file)
            TMP_FILES.append(key_file_name)
            TMP_FILES.append(cert_file_name)
        if not return_content:
            return target_file, cert_file_name, key_file_name
    return file_content


def call_safe(
    func: Callable, args: Tuple = None, kwargs: Dict = None, exception_message: str = None
) -> Optional[Any]:
    """
    Call the given function with the given arguments, and if it fails, log the given exception_message.
    If logging.DEBUG is set for the logger, then we also log the traceback.

    :param func: function to call
    :param args: arguments to pass
    :param kwargs: keyword arguments to pass
    :param exception_message: message to log on exception
    :return: whatever the func returns
    """
    if exception_message is None:
        exception_message = "error calling function %s" % func.__name__
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}

    try:
        return func(*args, **kwargs)
    except Exception as e:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.exception(exception_message)
        else:
            LOG.warning("%s: %s", exception_message, e)


def run_safe(_python_lambda, *args, _default=None, **kwargs):
    print_error = kwargs.get("print_error", False)
    try:
        return _python_lambda(*args, **kwargs)
    except Exception as e:
        if print_error:
            LOG.warning("Unable to execute function: %s", e)
        return _default


def run_cmd_safe(**kwargs):
    return run_safe(run, print_error=False, **kwargs)


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

    start = now()
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
        if now() - start >= max_secs:
            return
        time.sleep(0.5)


def do_run(cmd: str, run_cmd: Callable, cache_duration_secs: float):
    if cache_duration_secs <= 0:
        return run_cmd()

    hashcode = md5(cmd)
    cache_file = CACHE_FILE_PATTERN.replace("*", hashcode)
    mkdir(os.path.dirname(CACHE_FILE_PATTERN))
    if os.path.isfile(cache_file):
        # check file age
        mod_time = os.path.getmtime(cache_file)
        time_now = time.time()
        if mod_time > (time_now - cache_duration_secs):
            with open(cache_file) as fd:
                return fd.read()
    result = run_cmd()
    with open(cache_file, "w+") as fd:
        fd.write(result)
    clean_cache()
    return result


def run(
    cmd: Union[str, List[str]], cache_duration_secs=0, **kwargs
) -> Union[str, subprocess.Popen]:
    # TODO: should be unified and replaced with safe_run(..) over time! (allowing only lists for cmd parameter)
    def run_cmd():
        return localstack.utils.run.run(cmd, **kwargs)

    return do_run(cmd, run_cmd, cache_duration_secs)


def safe_run(cmd: List[str], cache_duration_secs=0, **kwargs) -> Union[str, subprocess.Popen]:
    def run_cmd():
        return localstack.utils.run.run(cmd, shell=False, **kwargs)

    return do_run(" ".join(cmd), run_cmd, cache_duration_secs)


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


def clean_cache(file_pattern=CACHE_FILE_PATTERN, last_clean_time=None, max_age=CACHE_MAX_AGE):
    if last_clean_time is None:
        last_clean_time = last_cache_clean_time

    with MUTEX_CLEAN:
        time_now = now()
        if last_clean_time["time"] > time_now - CACHE_CLEAN_TIMEOUT:
            return
        for cache_file in set(glob.glob(file_pattern)):
            mod_time = os.path.getmtime(cache_file)
            if time_now > mod_time + max_age:
                rm_rf(cache_file)
        last_clean_time["time"] = time_now
    return time_now


def parallelize(func: Callable, arr: List, size: int = None):
    if not size:
        size = len(arr)
    if size <= 0:
        return None

    with Pool(size) as pool:
        return pool.map(func, arr)


# TODO move to aws_responses.py?
def replace_response_content(response, pattern, replacement):
    content = to_str(response.content or "")
    response._content = re.sub(pattern, replacement, content)


def is_none_or_empty(obj: Union[Optional[str], Optional[list]]) -> bool:
    return (
        obj is None
        or (isinstance(obj, str) and obj.strip() == "")
        or (isinstance(obj, Sized) and len(obj) == 0)
    )


# Code that requires util functions from above
CACHE_FILE_PATTERN = CACHE_FILE_PATTERN.replace("_random_dir_", short_uid())
