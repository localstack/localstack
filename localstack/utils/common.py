import base64
import binascii
import decimal
import functools
import glob
import hashlib
import inspect
import io
import itertools
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import date, datetime, timezone, tzinfo
from json import JSONDecodeError
from multiprocessing.dummy import Pool
from queue import Queue
from typing import Any, Callable, Dict, List, Optional, Sized, Tuple, Type, Union
from urllib.parse import parse_qs, urlparse

import cachetools
import requests
from requests import Response
from requests.models import CaseInsensitiveDict

import localstack.utils.run
from localstack import config
from localstack.config import DEFAULT_ENCODING
from localstack.constants import ENV_DEV
from localstack.utils.generic.number_utils import format_number, is_number

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.generic.wait_utils import poll_condition, retry  # noqa

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.net_utils import (  # noqa
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
from localstack.utils.run import FuncThread

# set up logger
LOG = logging.getLogger(__name__)

# arrays for temporary files and resources
TMP_FILES = []
TMP_THREADS = []
TMP_PROCESSES = []

# cache clean variables
CACHE_CLEAN_TIMEOUT = 60 * 5
CACHE_MAX_AGE = 60 * 60
CACHE_FILE_PATTERN = os.path.join(tempfile.gettempdir(), "_random_dir_", "cache.*.json")
last_cache_clean_time = {"time": 0}
MUTEX_CLEAN = threading.Lock()

# misc. constants
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"
TIMESTAMP_FORMAT_TZ = "%Y-%m-%dT%H:%M:%SZ"
TIMESTAMP_FORMAT_MICROS = "%Y-%m-%dT%H:%M:%S.%fZ"
CODEC_HANDLER_UNDERSCORE = "underscore"

# chunk size for file downloads
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

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

# regular expression for unprintable characters
# Based on https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
#     #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF
_unprintables = (
    range(0x00, 0x09),
    range(0x0A, 0x0A),
    range(0x0B, 0x0D),
    range(0x0E, 0x20),
    range(0xD800, 0xE000),
    range(0xFFFE, 0x10000),
)
REGEX_UNPRINTABLE_CHARS = re.compile(
    f"[{re.escape(''.join(map(chr, itertools.chain(*_unprintables))))}]"
)

# user of the currently running process
CACHED_USER = None

# type definitions for JSON-serializable objects
JsonComplexType = Union[Dict, List]
JsonType = Union[JsonComplexType, str, int, float, bool, None]
SerializableObj = JsonType


class Mock(object):
    """Dummy class that can be used for mocking custom attributes."""

    pass


class CustomEncoder(json.JSONEncoder):
    """Helper class to convert JSON documents with datetime, decimals, or bytes."""

    def default(self, o):
        import yaml  # leave import here, to avoid breaking our Lambda tests!

        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        if isinstance(o, (datetime, date)):
            return timestamp_millis(o)
        if isinstance(o, yaml.ScalarNode):
            if o.tag == "tag:yaml.org,2002:int":
                return int(o.value)
            if o.tag == "tag:yaml.org,2002:float":
                return float(o.value)
            if o.tag == "tag:yaml.org,2002:bool":
                return bool(o.value)
            return str(o.value)
        try:
            if isinstance(o, bytes):
                return to_str(o)
            return super(CustomEncoder, self).default(o)
        except Exception:
            return None


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


class JsonObject(object):
    """Generic JSON serializable object for simplified subclassing"""

    def to_json(self, indent=None):
        return json.dumps(
            self,
            default=lambda o: (
                (float(o) if o % 1 > 0 else int(o))
                if isinstance(o, decimal.Decimal)
                else o.__dict__
            ),
            sort_keys=True,
            indent=indent,
        )

    def apply_json(self, j):
        if isinstance(j, str):
            j = json.loads(j)
        self.__dict__.update(j)

    def to_dict(self):
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, j):
        j = JsonObject.as_dict(j)
        result = cls()
        result.apply_json(j)
        return result

    @classmethod
    def from_json_list(cls, json_list):
        return [cls.from_json(j) for j in json_list]

    @classmethod
    def as_dict(cls, obj):
        if isinstance(obj, dict):
            return obj
        return obj.to_dict()

    def __str__(self):
        return self.to_json()

    def __repr__(self):
        return self.__str__()


class DelSafeDict(dict):
    """Useful when applying jsonpatch. Use it as follows:

    obj.__dict__ = DelSafeDict(obj.__dict__)
    apply_patch(obj.__dict__, patch)
    """

    def __delitem__(self, key, *args, **kwargs):
        self[key] = None


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


class ObjectIdHashComparator:
    """Simple wrapper class that allows us to create a hashset using the object id(..) as the entries' hash value"""

    def __init__(self, obj):
        self.obj = obj
        self._hash = id(obj)

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        # assumption here is that we're comparing only against ObjectIdHash instances!
        return self.obj == other.obj


class ArbitraryAccessObj:
    """Dummy object that can be arbitrarily accessed - any attributes, as a callable, item assignment, ..."""

    def __init__(self, name=None):
        self.name = name

    def __getattr__(self, name, *args, **kwargs):
        return ArbitraryAccessObj(name)

    def __call__(self, *args, **kwargs):
        if self.name in ["items", "keys", "values"] and not args and not kwargs:
            return []
        return ArbitraryAccessObj()

    def __getitem__(self, *args, **kwargs):
        return ArbitraryAccessObj()

    def __setitem__(self, *args, **kwargs):
        return ArbitraryAccessObj()


class HashableList(list):
    """Hashable list class that can be used with dicts or hashsets."""

    def __hash__(self):
        result = 0
        for i in self:
            result += hash(i)
        return result


class PaginatedList(list):
    """List which can be paginated and filtered. For usage in AWS APIs with paginated responses"""

    DEFAULT_PAGE_SIZE = 50

    def get_page(
        self,
        token_generator: Callable,
        next_token: str = None,
        page_size: int = None,
        filter_function: Callable = None,
    ) -> (list, str):
        if filter_function is not None:
            result_list = list(filter(filter_function, self))
        else:
            result_list = self

        if page_size is None:
            page_size = self.DEFAULT_PAGE_SIZE

        if len(result_list) <= page_size:
            return result_list, None

        start_idx = 0

        try:
            start_item = next(item for item in result_list if token_generator(item) == next_token)
            start_idx = result_list.index(start_item)
        except StopIteration:
            pass

        if start_idx + page_size <= len(result_list):
            next_token = token_generator(result_list[start_idx + page_size])
        else:
            next_token = None

        return result_list[start_idx : start_idx + page_size], next_token


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


def synchronized(lock=None):
    """
    Synchronization decorator as described in
    http://blog.dscpl.com.au/2014/01/the-missing-synchronized-decorator.html.
    """

    def _decorator(wrapped):
        @functools.wraps(wrapped)
        def _wrapper(*args, **kwargs):
            with lock:
                return wrapped(*args, **kwargs)

        return _wrapper

    return _decorator


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


def is_string(s, include_unicode=True, exclude_binary=False):
    if isinstance(s, bytes) and exclude_binary:
        return False
    if isinstance(s, str):
        return True
    if include_unicode and isinstance(s, str):
        return True
    return False


def is_string_or_bytes(s):
    return is_string(s) or isinstance(s, str) or isinstance(s, bytes)


def is_base64(s):
    regex = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    return is_string(s) and re.match(regex, s)


def md5(string: Union[str, bytes]) -> str:
    m = hashlib.md5()
    m.update(to_bytes(string))
    return m.hexdigest()


def select_attributes(obj: Dict, attributes: List[str]) -> Dict:
    """Select a subset of attributes from the given dict (returns a copy)"""
    attributes = attributes if is_list_or_tuple(attributes) else [attributes]
    return {k: v for k, v in obj.items() if k in attributes}


def remove_attributes(obj: Dict, attributes: List[str], recursive: bool = False) -> Dict:
    """Remove a set of attributes from the given dict (in-place)"""
    if recursive:

        def _remove(o, **kwargs):
            if isinstance(o, dict):
                remove_attributes(o, attributes)
            return o

        return recurse_object(obj, _remove)
    attributes = attributes if is_list_or_tuple(attributes) else [attributes]
    for attr in attributes:
        obj.pop(attr, None)
    return obj


def rename_attributes(
    obj: Dict, old_to_new_attributes: Dict[str, str], in_place: bool = False
) -> Dict:
    """Rename a set of attributes in the given dict object. Second parameter is a dict that maps old to
    new attribute names. Default is to return a copy, but can also pass in_place=True."""
    if not in_place:
        obj = dict(obj)
    for old_name, new_name in old_to_new_attributes.items():
        if old_name in obj:
            obj[new_name] = obj.pop(old_name)
    return obj


def is_list_or_tuple(obj) -> bool:
    return isinstance(obj, (list, tuple))


def ensure_list(obj: Any, wrap_none=False) -> List:
    """Wrap the given object in a list, or return the object itself if it already is a list."""
    if obj is None and not wrap_none:
        return obj
    return obj if isinstance(obj, list) else [obj]


def in_docker() -> bool:
    return config.in_docker()


def path_from_url(url: str) -> str:
    return "/%s" % str(url).partition("://")[2].partition("/")[2] if "://" in url else url


def sleep_forever():
    while True:
        time.sleep(1)


def get_service_protocol():
    return "https" if config.USE_SSL else "http"


def edge_ports_info():
    if config.EDGE_PORT_HTTP:
        result = "ports %s/%s" % (config.EDGE_PORT, config.EDGE_PORT_HTTP)
    else:
        result = "port %s" % config.EDGE_PORT
    result = "%s %s" % (get_service_protocol(), result)
    return result


def to_unique_items_list(inputs, comparator=None):
    """Return a list of unique items from the given input iterable.
    The comparator(item1, item2) returns True/False or an int for comparison."""

    def contained(item):
        for r in result:
            if comparator:
                cmp_res = comparator(item, r)
                if cmp_res is True or str(cmp_res) == "0":
                    return True
            elif item == r:
                return True

    result = []
    for it in inputs:
        if not contained(it):
            result.append(it)
    return result


def timestamp(time=None, format: str = TIMESTAMP_FORMAT) -> str:
    if not time:
        time = datetime.utcnow()
    if isinstance(time, (int, float)):
        time = datetime.fromtimestamp(time)
    return time.strftime(format)


def timestamp_millis(time=None) -> str:
    microsecond_time = timestamp(time=time, format=TIMESTAMP_FORMAT_MICROS)
    # truncating microseconds to milliseconds, while leaving the "Z" indicator
    return microsecond_time[:-4] + microsecond_time[-1]


def epoch_timestamp() -> float:
    return time.time()


def parse_timestamp(ts_str: str) -> datetime:
    for ts_format in [TIMESTAMP_FORMAT, TIMESTAMP_FORMAT_TZ, TIMESTAMP_FORMAT_MICROS]:
        try:
            return datetime.strptime(ts_str, ts_format)
        except ValueError:
            pass
    raise Exception("Unable to parse timestamp string with any known formats: %s" % ts_str)


def merge_recursive(source, destination, none_values=None, overwrite=False):
    if none_values is None:
        none_values = [None]
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge_recursive(value, node, none_values=none_values, overwrite=overwrite)
        else:
            if not isinstance(destination, (dict, CaseInsensitiveDict)):
                LOG.warning(
                    "Destination for merging %s=%s is not dict: %s (%s)",
                    key,
                    value,
                    destination,
                    type(destination),
                )
            if overwrite or destination.get(key) in none_values:
                destination[key] = value
    return destination


def merge_dicts(*dicts, **kwargs):
    """Merge all dicts in `*dicts` into a single dict, and return the result. If any of the entries
    in `*dicts` is None, and `default` is specified as keyword argument, then return `default`."""
    result = {}
    for d in dicts:
        if d is None and "default" in kwargs:
            return kwargs["default"]
        if d:
            result.update(d)
    return result


def remove_none_values_from_dict(dict: Dict) -> Dict:
    return {k: v for (k, v) in dict.items() if v is not None}


def recurse_object(obj: JsonType, func: Callable, path: str = "") -> Any:
    """Recursively apply `func` to `obj` (may be a list, dict, or other object)."""
    obj = func(obj, path=path)
    if isinstance(obj, list):
        for i in range(len(obj)):
            tmp_path = "%s[%s]" % (path or ".", i)
            obj[i] = recurse_object(obj[i], func, tmp_path)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            tmp_path = "%s%s" % ((path + ".") if path else "", k)
            obj[k] = recurse_object(v, func, tmp_path)
    return obj


def keys_to_lower(obj: JsonComplexType, skip_children_of: List[str] = None) -> JsonComplexType:
    """Recursively changes all dict keys to first character lowercase. Skip children
    of any elements whose names are contained in skip_children_of (e.g., ['Tags'])"""
    skip_children_of = ensure_list(skip_children_of or [])

    def fix_keys(o, path="", **kwargs):
        if any(re.match(r"(^|.*\.)%s($|[.\[].*)" % k, path) for k in skip_children_of):
            return o
        if isinstance(o, dict):
            for k, v in dict(o).items():
                o.pop(k)
                o[first_char_to_lower(k)] = v
        return o

    result = recurse_object(obj, fix_keys)
    return result


_camel_to_snake_case_sub = re.compile("((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))")


def camel_to_snake_case(string: str) -> str:
    return _camel_to_snake_case_sub.sub(r"_\1", string).replace("__", "_").lower()


def snake_to_camel_case(string: str, capitalize_first: bool = True) -> str:
    components = string.split("_")
    start_idx = 0 if capitalize_first else 1
    components = [x.title() for x in components[start_idx:]]
    return "".join(components)


def base64_to_hex(b64_string: str) -> bytes:
    return binascii.hexlify(base64.b64decode(b64_string))


def obj_to_xml(obj: SerializableObj) -> str:
    """Return an XML representation of the given object (dict, list, or primitive).
    Does NOT add a common root element if the given obj is a list.
    Does NOT work for nested dict structures."""
    if isinstance(obj, list):
        return "".join([obj_to_xml(o) for o in obj])
    if isinstance(obj, dict):
        return "".join(["<{k}>{v}</{k}>".format(k=k, v=obj_to_xml(v)) for (k, v) in obj.items()])
    return str(obj)


def strip_xmlns(obj: Any) -> Any:
    """Strip xmlns attributes from a dict returned by xmltodict.parse."""
    if isinstance(obj, list):
        return [strip_xmlns(item) for item in obj]
    if isinstance(obj, dict):
        # Remove xmlns attribute.
        obj.pop("@xmlns", None)
        if len(obj) == 1 and "#text" in obj:
            # If the only remaining key is the #text key, elide the dict
            # entirely, to match the structure that xmltodict.parse would have
            # returned if the xmlns namespace hadn't been present.
            return obj["#text"]
        return {k: strip_xmlns(v) for k, v in obj.items()}
    return obj


def now(millis: bool = False, tz: Optional[tzinfo] = None) -> int:
    return mktime(datetime.now(tz=tz), millis=millis)


def now_utc(millis: bool = False) -> int:
    return now(millis, timezone.utc)


def mktime(ts: datetime, millis: bool = False) -> int:
    if millis:
        return int(ts.timestamp() * 1000)
    return int(ts.timestamp())


def mkdir(folder: str):
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)


def is_empty_dir(directory: str, ignore_hidden: bool = False) -> bool:
    """Return whether the given directory contains any entries (files/folders), including hidden
    entries whose name starts with a dot (.), unless ignore_hidden=True is passed."""
    if not os.path.isdir(directory):
        raise Exception(f"Path is not a directory: {directory}")
    entries = os.listdir(directory)
    if ignore_hidden:
        entries = [e for e in entries if not e.startswith(".")]
    return not bool(entries)


def ensure_readable(file_path: str, default_perms: int = None):
    if default_perms is None:
        default_perms = 0o644
    try:
        with open(file_path, "rb"):
            pass
    except Exception:
        LOG.info("Updating permissions as file is currently not readable: %s", file_path)
        os.chmod(file_path, default_perms)


def chown_r(path: str, user: str):
    """Recursive chown on the given file/directory path."""
    # keep these imports here for Windows compatibility
    import grp
    import pwd

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(user).gr_gid
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for dirname in dirs:
            os.chown(os.path.join(root, dirname), uid, gid)
        for filename in files:
            os.chown(os.path.join(root, filename), uid, gid)


def chmod_r(path: str, mode: int):
    """Recursive chmod"""
    if not os.path.exists(path):
        return
    os.chmod(path, mode)
    for root, dirnames, filenames in os.walk(path):
        for dirname in dirnames:
            os.chmod(os.path.join(root, dirname), mode)
        for filename in filenames:
            os.chmod(os.path.join(root, filename), mode)


def rm_rf(path: str):
    """
    Recursively removes a file or directory
    """
    if not path or not os.path.exists(path):
        return
    # Running the native command can be an order of magnitude faster in Alpine on Travis-CI
    if is_debian():
        try:
            return run('rm -rf "%s"' % path)
        except Exception:
            pass
    # Make sure all files are writeable and dirs executable to remove
    try:
        chmod_r(path, 0o777)
    except PermissionError:
        pass  # todo log
    # check if the file is either a normal file, or, e.g., a fifo
    exists_but_non_dir = os.path.exists(path) and not os.path.isdir(path)
    if os.path.isfile(path) or exists_but_non_dir:
        os.remove(path)
    else:
        shutil.rmtree(path)


def cp_r(src: str, dst: str, rm_dest_on_conflict=False, ignore_copystat_errors=False, **kwargs):
    """Recursively copies file/directory"""
    # attention: this patch is not threadsafe
    copystat_orig = shutil.copystat
    if ignore_copystat_errors:

        def _copystat(*args, **kwargs):
            try:
                return copystat_orig(*args, **kwargs)
            except Exception:
                pass

        shutil.copystat = _copystat
    try:
        if os.path.isfile(src):
            if os.path.isdir(dst):
                dst = os.path.join(dst, os.path.basename(src))
            return shutil.copyfile(src, dst)
        if "dirs_exist_ok" in inspect.getfullargspec(shutil.copytree).args:
            kwargs["dirs_exist_ok"] = True
        try:
            return shutil.copytree(src, dst, **kwargs)
        except FileExistsError:
            if rm_dest_on_conflict:
                rm_rf(dst)
                return shutil.copytree(src, dst, **kwargs)
            raise
    except Exception as e:

        def _info(_path):
            return "%s (file=%s, symlink=%s)" % (
                _path,
                os.path.isfile(_path),
                os.path.islink(_path),
            )

        LOG.debug("Error copying files from %s to %s: %s", _info(src), _info(dst), e)
        raise
    finally:
        shutil.copystat = copystat_orig


def disk_usage(path: str) -> int:
    """Return the disk usage of the given file or directory."""

    if not os.path.exists(path):
        return 0

    if os.path.isfile(path):
        return os.path.getsize(path)

    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


def file_exists_not_empty(path: str) -> bool:
    """Return whether the given file or directory exists and is non-empty (i.e., >0 bytes content)"""
    return path and disk_usage(path) > 0


def format_bytes(count: float, default: str = "n/a"):
    """Format a bytes number as a human-readable unit, e.g., 1.3GB or 21.53MB"""
    if not is_number(count):
        return default
    cnt = float(count)
    if cnt < 0:
        return default
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if cnt < 1000 or unit == units[-1]:
            # FIXME: will return '1e+03TB' for 1000TB
            return f"{format_number(cnt, decimals=3)}{unit}"
        cnt = cnt / 1000.0
    return count


def get_proxies() -> Dict[str, str]:
    proxy_map = {}
    if config.OUTBOUND_HTTP_PROXY:
        proxy_map["http"] = config.OUTBOUND_HTTP_PROXY
    if config.OUTBOUND_HTTPS_PROXY:
        proxy_map["https"] = config.OUTBOUND_HTTPS_PROXY
    return proxy_map


def download(url: str, path: str, verify_ssl: bool = True, timeout: float = None):
    """Downloads file at url to the given path. Raises TimeoutError if the optional timeout (in secs) is reached."""

    # make sure we're creating a new session here to enable parallel file downloads
    s = requests.Session()
    proxies = get_proxies()
    if proxies:
        s.proxies.update(proxies)

    # Use REQUESTS_CA_BUNDLE path. If it doesn't exist, use the method provided settings.
    # Note that a value that is not False, will result to True and will get the bundle file.
    _verify = os.getenv("REQUESTS_CA_BUNDLE", verify_ssl)

    r = None
    try:
        r = s.get(url, stream=True, verify=_verify, timeout=timeout)
        # check status code before attempting to read body
        if not r.ok:
            raise Exception("Failed to download %s, response code %s" % (url, r.status_code))

        total = 0
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        LOG.debug(
            "Starting download from %s to %s (%s bytes)", url, path, r.headers.get("Content-Length")
        )
        with open(path, "wb") as f:
            iter_length = 0
            iter_limit = 1000000  # print a log line for every 1MB chunk
            for chunk in r.iter_content(DOWNLOAD_CHUNK_SIZE):
                total += len(chunk)
                iter_length += len(chunk)
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                else:
                    LOG.debug("Empty chunk %s (total %s) from %s", chunk, total, url)
                if iter_length >= iter_limit:
                    LOG.debug("Written %s bytes (total %s) to %s", iter_length, total, path)
                    iter_length = 0
            f.flush()
            os.fsync(f)
        if os.path.getsize(path) == 0:
            LOG.warning("Zero bytes downloaded from %s, retrying", url)
            download(url, path, verify_ssl)
            return
        LOG.debug(
            "Done downloading %s, response code %s, total bytes %d", url, r.status_code, total
        )
    except requests.exceptions.ReadTimeout as e:
        raise TimeoutError(f"Timeout ({timeout}) reached on download: {url} - {e}")
    finally:
        if r is not None:
            r.close()
        s.close()


def parse_request_data(method: str, path: str, data=None, headers=None) -> Dict:
    """Extract request data either from query string as well as request body (e.g., for POST)."""
    result = {}
    headers = headers or {}
    content_type = headers.get("Content-Type", "")

    # add query params to result
    parsed_path = urlparse(path)
    result.update(parse_qs(parsed_path.query))

    # add params from url-encoded payload
    if method in ["POST", "PUT", "PATCH"] and (not content_type or "form-" in content_type):
        # content-type could be either "application/x-www-form-urlencoded" or "multipart/form-data"
        try:
            params = parse_qs(to_str(data or ""))
            result.update(params)
        except Exception:
            pass  # probably binary / JSON / non-URL encoded payload - ignore

    # select first elements from result lists (this is assuming we are not using parameter lists!)
    result = {k: v[0] for k, v in result.items()}
    return result


def first_char_to_lower(s: str) -> str:
    return s and "%s%s" % (s[0].lower(), s[1:])


def first_char_to_upper(s: str) -> str:
    return s and "%s%s" % (s[0].upper(), s[1:])


def is_mac_os() -> bool:
    return localstack.utils.run.is_mac_os()


def is_linux() -> bool:
    return localstack.utils.run.is_linux()


def is_windows() -> bool:
    return localstack.utils.run.is_windows()


def is_debian() -> bool:
    cache_key = "_is_debian_"
    try:
        with MUTEX_CLEAN:
            if cache_key not in CACHE:
                CACHE[cache_key] = False
                if not os.path.exists("/etc/issue"):
                    return False
                out = to_str(subprocess.check_output(["cat", "/etc/issue"]))
                CACHE[cache_key] = "Debian" in out
    except subprocess.CalledProcessError:
        return False
    return CACHE[cache_key]


def get_arch() -> str:
    """
    Returns the current machine architecture
    :return: "amd64" when x86_64, "arm64" if aarch64, platform.machine() otherwise
    """
    arch = platform.machine()
    if arch == "x86_64":
        return "amd64"
    if arch == "aarch64":
        return "arm64"
    return arch


def get_os() -> str:
    if is_mac_os():
        return "osx"
    if is_linux():
        return "linux"
    if is_windows():
        return "windows"
    raise Exception("Unable to determine local operating system")


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


def parse_json_or_yaml(markup: str) -> JsonComplexType:
    import yaml  # leave import here, to avoid breaking our Lambda tests!

    try:
        return json.loads(markup)
    except Exception:
        try:
            return clone_safe(yaml.safe_load(markup))
        except Exception:
            try:
                return clone_safe(yaml.load(markup, Loader=yaml.SafeLoader))
            except Exception:
                raise


def try_json(data: str):
    """
    Tries to deserialize json input to object if possible, otherwise returns original
    :param data: string
    :return: deserialize version of input
    """
    try:
        return json.loads(to_str(data or "{}"))
    except JSONDecodeError:
        LOG.warning("failed serialize to json, fallback to original")
        return data


def json_safe(item: JsonType) -> JsonType:
    """Return a copy of the given object (e.g., dict) that is safe for JSON dumping"""
    try:
        return json.loads(json.dumps(item, cls=CustomEncoder))
    except Exception:
        item = fix_json_keys(item)
        return json.loads(json.dumps(item, cls=CustomEncoder))


def fix_json_keys(item: JsonType):
    """make sure the keys of a JSON are strings (not binary type or other)"""
    item_copy = item
    if isinstance(item, list):
        item_copy = []
        for i in item:
            item_copy.append(fix_json_keys(i))
    if isinstance(item, dict):
        item_copy = {}
        for k, v in item.items():
            item_copy[to_str(k)] = fix_json_keys(v)
    return item_copy


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True)


def extract_jsonpath(value, path):
    from jsonpath_rw import parse

    jsonpath_expr = parse(path)
    result = [match.value for match in jsonpath_expr.find(value)]
    result = result[0] if len(result) == 1 else result
    return result


def assign_to_path(target, path: str, value, delimiter: str = "."):
    parts = path.strip(delimiter).split(delimiter)
    path_to_parent = delimiter.join(parts[:-1])
    parent = extract_from_jsonpointer_path(target, path_to_parent, auto_create=True)
    if not isinstance(parent, dict):
        LOG.debug(
            'Unable to find parent (type %s) for path "%s" in object: %s',
            type(parent),
            path,
            target,
        )
        return
    path_end = int(parts[-1]) if is_number(parts[-1]) else parts[-1]
    parent[path_end] = value
    return target


def extract_from_jsonpointer_path(target, path: str, delimiter: str = "/", auto_create=False):
    parts = path.strip(delimiter).split(delimiter)
    for part in parts:
        path_part = int(part) if is_number(part) else part
        if isinstance(target, list) and not is_number(path_part):
            if path_part == "-":
                # special case where path is like /path/to/list/- where "/-" means "append to list"
                continue
            LOG.warning('Attempting to extract non-int index "%s" from list: %s', path_part, target)
            return None
        target_new = target[path_part] if isinstance(target, list) else target.get(path_part)
        if target_new is None:
            if not auto_create:
                return
            target[path_part] = target_new = {}
        target = target_new
    return target


def save_file(file, content, append=False, permissions=None):
    mode = "a" if append else "w+"
    if not isinstance(content, str):
        mode = mode + "b"

    def _opener(path, flags):
        return os.open(path, flags, permissions)

    # make sure that the parent dir exsits
    mkdir(os.path.dirname(file))
    # store file contents
    with open(file, mode, opener=_opener if permissions else None) as f:
        f.write(content)
        f.flush()


def load_file(file_path, default=None, mode=None):
    if not os.path.isfile(file_path):
        return default
    if not mode:
        mode = "r"
    with open(file_path, mode) as f:
        result = f.read()
    return result


def get_or_create_file(file_path, content=None, permissions=None):
    if os.path.exists(file_path):
        return load_file(file_path)
    content = "{}" if content is None else content
    try:
        save_file(file_path, content, permissions=permissions)
        return content
    except Exception:
        pass


def replace_in_file(search, replace, file_path):
    """Replace all occurrences of `search` with `replace` in the given file (overwrites in place!)"""
    content = load_file(file_path) or ""
    content_new = content.replace(search, replace)
    if content != content_new:
        save_file(file_path, content_new)


def to_str(obj: Union[str, bytes], encoding: str = DEFAULT_ENCODING, errors="strict") -> str:
    """If ``obj`` is an instance of ``binary_type``, return
    ``obj.decode(encoding, errors)``, otherwise return ``obj``"""
    return obj.decode(encoding, errors) if isinstance(obj, bytes) else obj


def to_bytes(obj: Union[str, bytes], encoding: str = DEFAULT_ENCODING, errors="strict") -> bytes:
    """If ``obj`` is an instance of ``text_type``, return
    ``obj.encode(encoding, errors)``, otherwise return ``obj``"""
    return obj.encode(encoding, errors) if isinstance(obj, str) else obj


def str_to_bool(value):
    """Return the boolean value of the given string, or the verbatim value if it is not a string"""
    true_strings = ["true", "True"]
    if isinstance(value, str):
        return value in true_strings
    return value


def str_insert(string, index, content):
    """Insert a substring into an existing string at a certain index."""
    return "%s%s%s" % (string[:index], content, string[index:])


def str_remove(string, index, end_index=None):
    """Remove a substring from an existing string at a certain from-to index range."""
    end_index = end_index or (index + 1)
    return "%s%s" % (string[:index], string[end_index:])


def str_startswith_ignore_case(value: str, prefix: str) -> bool:
    return value[: len(prefix)].lower() == prefix.lower()


def last_index_of(array, value):
    """Return the last index of `value` in the given list, or -1 if it does not exist."""
    result = -1
    for i in reversed(range(len(array))):
        entry = array[i]
        if entry == value or (callable(value) and value(entry)):
            return i
    return result


def is_sub_dict(child_dict: Dict, parent_dict: Dict) -> bool:
    """Returns whether the first dict is a sub-dict (subset) of the second dict."""
    return all(parent_dict.get(key) == val for key, val in child_dict.items())


def not_none_or(value: Any, alternative: Any) -> Any:
    """Return 'value' if it is not None, or 'alternative' otherwise."""
    return value if value is not None else alternative


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


def items_equivalent(list1, list2, comparator):
    """Returns whether two lists are equivalent (i.e., same items contained in both lists,
    irrespective of the items' order) with respect to a comparator function."""

    def contained(item):
        for _item in list2:
            if comparator(item, _item):
                return True

    if len(list1) != len(list2):
        return False
    for item in list1:
        if not contained(item):
            return False
    return True


def cleanup_tmp_files():
    for tmp in TMP_FILES:
        try:
            rm_rf(tmp)
        except Exception:
            pass  # file likely doesn't exist, or permission denied
    del TMP_FILES[:]


def new_tmp_file() -> str:
    """Return a path to a new temporary file."""
    tmp_file, tmp_path = tempfile.mkstemp()
    os.close(tmp_file)
    TMP_FILES.append(tmp_path)
    return tmp_path


def new_tmp_dir():
    folder = new_tmp_file()
    rm_rf(folder)
    mkdir(folder)
    return folder


def is_zip_file(content):
    stream = io.BytesIO(content)
    return zipfile.is_zipfile(stream)


def unzip(path, target_dir, overwrite=True):
    is_in_debian = is_debian()
    if is_in_debian:
        # Running the native command can be an order of magnitude faster in Alpine on Travis-CI
        flags = "-o" if overwrite else ""
        flags += " -q"
        try:
            return run("cd %s; unzip %s %s" % (target_dir, flags, path), print_error=False)
        except Exception as e:
            error_str = truncate(str(e), max_length=200)
            LOG.info(
                'Unable to use native "unzip" command (using fallback mechanism): %s', error_str
            )

    try:
        zip_ref = zipfile.ZipFile(path, "r")
    except Exception as e:
        LOG.warning("Unable to open zip file: %s: %s", path, e)
        raise e

    def _unzip_file_entry(zip_ref, file_entry, target_dir):
        """Extracts a Zipfile entry and preserves permissions"""
        out_path = os.path.join(target_dir, file_entry.filename)
        if is_in_debian and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            # this can happen under certain circumstances if the native "unzip" command
            # fails with a non-zero exit code, yet manages to extract parts of the zip file
            return
        zip_ref.extract(file_entry.filename, path=target_dir)
        perm = file_entry.external_attr >> 16
        # Make sure to preserve file permissions in the zip file
        # https://www.burgundywall.com/post/preserving-file-perms-with-python-zipfile-module
        os.chmod(out_path, perm or 0o777)

    try:
        for file_entry in zip_ref.infolist():
            _unzip_file_entry(zip_ref, file_entry, target_dir)
    finally:
        zip_ref.close()


def untar(path, target_dir):
    mode = "r:gz" if path.endswith("gz") else "r"
    with tarfile.open(path, mode) as tar:
        tar.extractall(path=target_dir)


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


def clone(item):
    return json.loads(json.dumps(item))


def clone_safe(item):
    return clone(json_safe(item))


class NetrcBypassAuth(requests.auth.AuthBase):
    def __call__(self, r):
        return r


class _RequestsSafe:
    """Wrapper around requests library, which can prevent it from verifying
    SSL certificates or reading credentials from ~/.netrc file"""

    verify_ssl = True

    def __getattr__(self, name):
        method = requests.__dict__.get(name.lower())
        if not method:
            return method

        def _wrapper(*args, **kwargs):
            if "auth" not in kwargs:
                kwargs["auth"] = NetrcBypassAuth()
            url = kwargs.get("url") or (args[1] if name == "request" else args[0])
            if not self.verify_ssl and url.startswith("https://") and "verify" not in kwargs:
                kwargs["verify"] = False
            return method(*args, **kwargs)

        return _wrapper


# create safe_requests instance
safe_requests = _RequestsSafe()


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


def make_http_request(
    url: str, data: Union[bytes, str] = None, headers: Dict[str, str] = None, method: str = "GET"
) -> Response:
    return requests.request(
        url=url, method=method, headers=headers, data=data, auth=NetrcBypassAuth(), verify=False
    )


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


def truncate(data: str, max_length: int = 100) -> str:
    data = str(data or "")
    return ("%s..." % data[:max_length]) if len(data) > max_length else data


# this requires that all subclasses have been imported before(!)
def get_all_subclasses(clazz: Type) -> List[Type]:
    """Recursively get all subclasses of the given class."""
    result = set()
    subs = clazz.__subclasses__()
    for sub in subs:
        result.add(sub)
        result.update(get_all_subclasses(sub))
    return result


def fully_qualified_class_name(klass: Type) -> str:
    return f"{klass.__module__}.{klass.__name__}"


def parallelize(func: Callable, arr: List, size: int = None):
    if not size:
        size = len(arr)
    if size <= 0:
        return None

    with Pool(size) as pool:
        return pool.map(func, arr)


def isoformat_milliseconds(t) -> str:
    try:
        return t.isoformat(timespec="milliseconds")
    except TypeError:
        return t.isoformat()[:-3]


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


def canonicalize_bool_to_str(val: bool) -> str:
    return "true" if str(val).lower() == "true" else "false"


def convert_to_printable_chars(value: Union[List, Dict, str]) -> str:
    """Removes all unprintable characters from the given string."""
    if isinstance(value, (dict, list)):

        def _convert(obj, **kwargs):
            if isinstance(obj, str):
                return convert_to_printable_chars(obj)
            return obj

        return recurse_object(value, _convert)

    result = REGEX_UNPRINTABLE_CHARS.sub("", value)
    return result


# Code that requires util functions from above
CACHE_FILE_PATTERN = CACHE_FILE_PATTERN.replace("_random_dir_", short_uid())
