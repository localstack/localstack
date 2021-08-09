import base64
import binascii
import decimal
import functools
import glob
import hashlib
import inspect
import io
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
from contextlib import closing
from datetime import date, datetime, timezone
from multiprocessing.dummy import Pool
from queue import Queue
from typing import Callable, List, Optional, Sized, Union
from urllib.parse import parse_qs, urlparse

import dns.resolver
import requests
import six

import localstack.utils.run
from localstack import config
from localstack.config import DEFAULT_ENCODING
from localstack.constants import ENV_DEV
from localstack.utils.run import FuncThread

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
TIMESTAMP_FORMAT_MICROS = "%Y-%m-%dT%H:%M:%S.%fZ"
CODEC_HANDLER_UNDERSCORE = "underscore"

# chunk size for file downloads
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

# set up logger
LOG = logging.getLogger(__name__)

# flag to indicate whether we've received and processed the stop signal
INFRA_STOPPED = False

# generic cache object
CACHE = {}

# lock for creating certificate files
SSL_CERT_LOCK = threading.RLock()


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
            if isinstance(o, six.binary_type):
                return to_str(o)
            return super(CustomEncoder, self).default(o)
        except Exception:
            return None


class ShellCommandThread(FuncThread):
    """Helper class to run a shell command in a background thread."""

    def __init__(
        self,
        cmd,
        params={},
        outfile=None,
        env_vars={},
        stdin=False,
        auto_restart=False,
        quiet=True,
        inherit_cwd=False,
        inherit_env=True,
        log_listener=None,
    ):
        self.cmd = cmd
        self.process = None
        self.outfile = outfile
        self.stdin = stdin
        self.env_vars = env_vars
        self.inherit_cwd = inherit_cwd
        self.inherit_env = inherit_env
        self.log_listener = log_listener
        self.auto_restart = auto_restart
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
                "Restarting process (received exit code %s): %s"
                % (self.process.returncode, self.cmd)
            )

    def do_run_cmd(self):
        def convert_line(line):
            line = to_str(line or "")
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
                self.process.wait()
            else:
                self.process.communicate()
        except Exception as e:
            self.result_future.set_exception(e)
            if self.process and not self.quiet:
                LOG.warning('Shell command error "%s": %s' % (e, self.cmd))
        if self.process and not self.quiet and self.process.returncode != 0:
            LOG.warning('Shell command exit code "%s": %s' % (self.process.returncode, self.cmd))

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
        if getattr(self, "stopped", False):
            return
        if not self.process:
            LOG.warning("No process found for command '%s'" % self.cmd)
            return

        parent_pid = self.process.pid
        try:
            kill_process_tree(parent_pid)
            self.process = None
        except Exception:
            if not quiet:
                LOG.warning("Unable to kill process with pid %s" % parent_pid)
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


# ----------------
# UTILITY METHODS
# ----------------


def start_thread(method, *args, **kwargs):
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
    if isinstance(s, six.binary_type) and exclude_binary:
        return False
    if isinstance(s, str):
        return True
    if include_unicode and isinstance(s, six.text_type):
        return True
    return False


def is_string_or_bytes(s):
    return is_string(s) or isinstance(s, six.string_types) or isinstance(s, bytes)


def is_base64(s):
    regex = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    return is_string(s) and re.match(regex, s)


def md5(string):
    m = hashlib.md5()
    m.update(to_bytes(string))
    return m.hexdigest()


def select_attributes(obj, attributes):
    attributes = attributes if is_list_or_tuple(attributes) else [attributes]
    return dict([(k, v) for k, v in obj.items() if k in attributes])


def is_list_or_tuple(obj):
    return isinstance(obj, (list, tuple))


def in_docker():
    return config.in_docker()


def path_from_url(url):
    return "/%s" % str(url).partition("://")[2].partition("/")[2] if "://" in url else url


def is_port_open(port_or_url, http_path=None, expect_success=True, protocols=["tcp"]):
    port = port_or_url
    if is_number(port):
        port = int(port)
    host = "localhost"
    protocol = "http"
    protocols = protocols if isinstance(protocols, list) else [protocols]
    if isinstance(port, six.string_types):
        url = urlparse(port_or_url)
        port = url.port
        host = url.hostname
        protocol = url.scheme
    nw_protocols = []
    nw_protocols += [socket.SOCK_STREAM] if "tcp" in protocols else []
    nw_protocols += [socket.SOCK_DGRAM] if "udp" in protocols else []
    for nw_protocol in nw_protocols:
        with closing(socket.socket(socket.AF_INET, nw_protocol)) as sock:
            sock.settimeout(1)
            if nw_protocol == socket.SOCK_DGRAM:
                try:
                    if port == 53:
                        dnshost = "127.0.0.1" if host == "localhost" else host
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dnshost]
                        resolver.timeout = 1
                        resolver.lifetime = 1
                        answers = resolver.query("google.com", "A")
                        assert len(answers) > 0
                    else:
                        sock.sendto(bytes(), (host, port))
                        sock.recvfrom(1024)
                except Exception:
                    return False
            elif nw_protocol == socket.SOCK_STREAM:
                result = sock.connect_ex((host, port))
                if result != 0:
                    return False
    if "tcp" not in protocols or not http_path:
        return True
    url = "%s://%s:%s%s" % (protocol, host, port, http_path)
    try:
        response = safe_requests.get(url, verify=False)
        return not expect_success or response.status_code < 400
    except Exception:
        return False


def wait_for_port_open(port, http_path=None, expect_success=True, retries=10, sleep_time=0.5):
    """Ping the given network port until it becomes available (for a given number of retries).
    If 'http_path' is set, make a GET request to this path and assert a non-error response."""

    def check():
        if not is_port_open(port, http_path=http_path, expect_success=expect_success):
            raise Exception("Port %s (path: %s) was not open" % (port, http_path))

    return retry(check, sleep=sleep_time, retries=retries)


def port_can_be_bound(port):
    """Return whether a local port can be bound to. Note that this is a stricter check
    than is_port_open(...) above, as is_port_open() may return False if the port is
    not accessible (i.e., does not respond), yet cannot be bound to."""
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", port))
        return True
    except Exception:
        return False


def get_free_tcp_port(blacklist=None):
    blacklist = blacklist or []
    for i in range(10):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
        tcp.close()
        if port not in blacklist:
            return port
    raise Exception("Unable to determine free TCP port with blacklist %s" % blacklist)


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


def timestamp(time=None, format=TIMESTAMP_FORMAT):
    if not time:
        time = datetime.utcnow()
    if isinstance(time, six.integer_types + (float,)):
        time = datetime.fromtimestamp(time)
    return time.strftime(format)


def timestamp_millis(time=None):
    microsecond_time = timestamp(time=time, format=TIMESTAMP_FORMAT_MICROS)
    # truncating microseconds to milliseconds, while leaving the "Z" indicator
    return microsecond_time[:-4] + microsecond_time[-1]


def epoch_timestamp():
    return time.time()


def retry(function, retries=3, sleep=1.0, sleep_before=0, **kwargs):
    raise_error = None
    if sleep_before > 0:
        time.sleep(sleep_before)
    for i in range(0, retries + 1):
        try:
            return function(**kwargs)
        except Exception as error:
            raise_error = error
            time.sleep(sleep)
    raise raise_error


def poll_condition(condition, timeout: float = None, interval: float = 0.5) -> bool:
    """
    Poll evaluates the given condition until a truthy value is returned. It does this every `interval` seconds
    (0.5 by default), until the timeout (in seconds, if any) is reached.

    Poll returns True once `condition()` returns a truthy value, or False if the timeout is reached.
    """
    remaining = 0
    if timeout is not None:
        remaining = timeout

    while not condition():
        if timeout is not None:
            remaining -= interval

            if remaining <= 0:
                return False

        time.sleep(interval)

    return True


def merge_recursive(source, destination, none_values=[None], overwrite=False):
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge_recursive(value, node, none_values=none_values, overwrite=overwrite)
        else:
            if not isinstance(destination, dict):
                LOG.warning(
                    "Destination for merging %s=%s is not dict: %s", key, value, destination
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


def recurse_object(obj, func, path=""):
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


def keys_to_lower(obj, skip_children_of=None):
    """Recursively changes all dict keys to first character lowercase. Skip children
    of any elements whose names are contained in skip_children_of (e.g., ['Tags'])"""
    skip_children_of = skip_children_of or []
    skip_children_of = (
        skip_children_of if isinstance(skip_children_of, list) else [skip_children_of]
    )

    def fix_keys(o, path="", **kwargs):
        if any([re.match(r"(^|.*\.)%s($|[.\[].*)" % k, path) for k in skip_children_of]):
            return o
        if isinstance(o, dict):
            for k, v in dict(o).items():
                o.pop(k)
                o[first_char_to_lower(k)] = v
        return o

    result = recurse_object(obj, fix_keys)
    return result


def camel_to_snake_case(string):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", string).replace("__", "_").lower()


def snake_to_camel_case(string, capitalize_first=True):
    components = string.split("_")
    start_idx = 0 if capitalize_first else 1
    components = [x.title() for x in components[start_idx:]]
    return "".join(components)


def base64_to_hex(b64_string):
    return binascii.hexlify(base64.b64decode(b64_string))


def obj_to_xml(obj):
    """Return an XML representation of the given object (dict, list, or primitive).
    Does NOT add a common root element if the given obj is a list.
    Does NOT work for nested dict structures."""
    if isinstance(obj, list):
        return "".join([obj_to_xml(o) for o in obj])
    if isinstance(obj, dict):
        return "".join(["<{k}>{v}</{k}>".format(k=k, v=obj_to_xml(v)) for (k, v) in obj.items()])
    return str(obj)


def now(millis=False, tz=None):
    return mktime(datetime.now(tz=tz), millis=millis)


def now_utc(millis=False):
    return now(millis, timezone.utc)


def mktime(ts, millis=False):
    if millis:
        return ts.timestamp() * 1000
    return ts.timestamp()


def mkdir(folder):
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)


def ensure_readable(file_path, default_perms=None):
    if default_perms is None:
        default_perms = 0o644
    try:
        with open(file_path, "rb"):
            pass
    except Exception:
        LOG.info("Updating permissions as file is currently not readable: %s" % file_path)
        os.chmod(file_path, default_perms)


def chown_r(path, user):
    """Recursive chown"""
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


def chmod_r(path, mode):
    """Recursive chmod"""
    if not os.path.exists(path):
        return
    os.chmod(path, mode)
    for root, dirnames, filenames in os.walk(path):
        for dirname in dirnames:
            os.chmod(os.path.join(root, dirname), mode)
        for filename in filenames:
            os.chmod(os.path.join(root, filename), mode)


def rm_rf(path):
    """
    Recursively removes a file or directory
    """
    if not path or not os.path.exists(path):
        return
    # Running the native command can be an order of magnitude faster in Alpine on Travis-CI
    if is_alpine():
        try:
            return run('rm -rf "%s"' % path)
        except Exception:
            pass
    # Make sure all files are writeable and dirs executable to remove
    chmod_r(path, 0o777)
    # check if the file is either a normal file, or, e.g., a fifo
    exists_but_non_dir = os.path.exists(path) and not os.path.isdir(path)
    if os.path.isfile(path) or exists_but_non_dir:
        os.remove(path)
    else:
        shutil.rmtree(path)


def cp_r(src, dst, rm_dest_on_conflict=False):
    """Recursively copies file/directory"""
    if os.path.isfile(src):
        return shutil.copy(src, dst)
    kwargs = {}
    if "dirs_exist_ok" in inspect.getfullargspec(shutil.copytree).args:
        kwargs["dirs_exist_ok"] = True
    try:
        return shutil.copytree(src, dst, **kwargs)
    except FileExistsError:
        if rm_dest_on_conflict:
            rm_rf(dst)
            return shutil.copytree(src, dst, **kwargs)
        raise


def disk_usage(path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


def format_bytes(count, default="n/a"):
    if not is_number(count) or count < 0:
        return default
    cnt = float(count)
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if cnt < 1000 or unit == units[-1]:
            # FIXME: will return '1e+03TB' for 1000TB
            return "%s%s" % (format_number(cnt, decimals=3), unit)
        cnt = cnt / 1000.0
    return count


def download(url, path, verify_ssl=True):
    """Downloads file at url to the given path"""
    # make sure we're creating a new session here to
    # enable parallel file downloads during installation!
    s = requests.Session()
    # Use REQUESTS_CA_BUNDLE path. If it doesn't exist, use the method provided settings.
    # Note that a value that is not False, will result to True and will get the bundle file.
    r = s.get(url, stream=True, verify=os.getenv("REQUESTS_CA_BUNDLE", verify_ssl))
    # check status code before attempting to read body
    if r.status_code >= 400:
        raise Exception("Failed to download %s, response code %s" % (url, r.status_code))

    total = 0
    try:
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        LOG.debug(
            "Starting download from %s to %s (%s bytes)"
            % (url, path, r.headers.get("Content-Length"))
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
                    LOG.debug("Empty chunk %s (total %s) from %s" % (chunk, total, url))
                if iter_length >= iter_limit:
                    LOG.debug("Written %s bytes (total %s) to %s" % (iter_length, total, path))
                    iter_length = 0
            f.flush()
            os.fsync(f)
        if os.path.getsize(path) == 0:
            LOG.warning("Zero bytes downloaded from %s, retrying" % url)
            download(url, path, verify_ssl)
            return
        LOG.debug(
            "Done downloading %s, response code %s, total bytes %d" % (url, r.status_code, total)
        )
    finally:
        r.close()
        s.close()


def parse_request_data(method, path, data=None, headers={}):
    """Extract request data either from query string (for GET) or request body (for POST)."""
    result = {}
    headers = headers or {}
    content_type = headers.get("Content-Type", "")
    if method in ["POST", "PUT", "PATCH"] and (not content_type or "form-" in content_type):
        # content-type could be either "application/x-www-form-urlencoded" or "multipart/form-data"
        try:
            result = parse_qs(to_str(data or ""))
        except Exception:
            pass  # probably binary / JSON / non-URL encoded payload - ignore
    if not result:
        parsed_path = urlparse(path)
        result = parse_qs(parsed_path.query)
    result = dict([(k, v[0]) for k, v in result.items()])
    return result


def first_char_to_lower(s):
    return s and "%s%s" % (s[0].lower(), s[1:])


def first_char_to_upper(s):
    return s and "%s%s" % (s[0].upper(), s[1:])


def format_number(number, decimals=2):
    return ("{0:.%sg}" % decimals).format(number)


def is_number(s):
    try:
        float(s)  # for int, long and float
        return True
    except (TypeError, ValueError):
        return False


def is_mac_os():
    return localstack.utils.run.is_mac_os()


def is_linux():
    return localstack.utils.run.is_linux()


def is_windows():
    return platform.system().lower() == "windows"


def is_alpine():
    try:
        with MUTEX_CLEAN:
            if "_is_alpine_" not in CACHE:
                CACHE["_is_alpine_"] = False
                if not os.path.exists("/etc/issue"):
                    return False
                out = to_str(subprocess.check_output("cat /etc/issue", shell=True))
                CACHE["_is_alpine_"] = "Alpine" in out
    except subprocess.CalledProcessError:
        return False
    return CACHE["_is_alpine_"]


def get_arch():
    if is_mac_os():
        return "osx"
    if is_alpine():
        return "alpine"
    if is_linux():
        return "linux"
    if is_windows():
        return "windows"
    raise Exception("Unable to determine system architecture")


def is_command_available(cmd):
    try:
        run("which %s" % cmd, print_error=False)
        return True
    except Exception:
        return False


def short_uid():
    return str(uuid.uuid4())[0:8]


def long_uid():
    return str(uuid.uuid4())


def parse_json_or_yaml(markup):
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


def json_safe(item):
    """return a copy of the given object (e.g., dict) that is safe for JSON dumping"""
    try:
        return json.loads(json.dumps(item, cls=CustomEncoder))
    except Exception:
        item = fix_json_keys(item)
        return json.loads(json.dumps(item, cls=CustomEncoder))


def fix_json_keys(item):
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
            'Unable to find parent (type %s) for path "%s" in object: %s'
            % (type(parent), path, target)
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
            LOG.warning(
                'Attempting to extract non-int index "%s" from list: %s' % (path_part, target)
            )
            return None
        target_new = target[path_part] if isinstance(target, list) else target.get(path_part)
        if target_new is None:
            if not auto_create:
                return
            target[path_part] = target_new = {}
        target = target_new
    return target


def save_file(file, content, append=False):
    mode = "a" if append else "w+"
    if not isinstance(content, six.string_types):
        mode = mode + "b"
    # make sure that the parent dir exsits
    mkdir(os.path.dirname(file))
    # store file contents
    with open(file, mode) as f:
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


def get_or_create_file(file_path, content=None):
    if os.path.exists(file_path):
        return load_file(file_path)
    content = "{}" if content is None else content
    try:
        save_file(file_path, content)
        return content
    except Exception:
        pass


def replace_in_file(search, replace, file_path):
    """Replace all occurrences of `search` with `replace` in the given file (overwrites in place!)"""
    content = load_file(file_path) or ""
    content_new = content.replace(search, replace)
    if content != content_new:
        save_file(file_path, content_new)


def to_str(obj, encoding=DEFAULT_ENCODING, errors="strict"):
    """If ``obj`` is an instance of ``binary_type``, return
    ``obj.decode(encoding, errors)``, otherwise return ``obj``"""
    return obj.decode(encoding, errors) if isinstance(obj, six.binary_type) else obj


def to_bytes(obj, encoding=DEFAULT_ENCODING, errors="strict"):
    """If ``obj`` is an instance of ``text_type``, return
    ``obj.encode(encoding, errors)``, otherwise return ``obj``"""
    return obj.encode(encoding, errors) if isinstance(obj, six.text_type) else obj


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


def last_index_of(array, value):
    """Return the last index of `value` in the given list, or -1 if it does not exist."""
    result = -1
    for i in reversed(range(len(array))):
        entry = array[i]
        if entry == value or (callable(value) and value(entry)):
            return i
    return result


def is_sub_dict(child_dict, parent_dict):
    """Returns whether the first dict is a sub-dict (subset) of the second dict."""
    return all(parent_dict.get(key) == val for key, val in child_dict.items())


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


def is_ip_address(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def is_zip_file(content):
    stream = io.BytesIO(content)
    return zipfile.is_zipfile(stream)


def unzip(path, target_dir, overwrite=True):
    is_in_alpine = is_alpine()
    if is_in_alpine:
        # Running the native command can be an order of magnitude faster in Alpine on Travis-CI
        flags = "-o" if overwrite else ""
        flags += " -q"
        try:
            return run("cd %s; unzip %s %s" % (target_dir, flags, path), print_error=False)
        except Exception as e:
            error_str = truncate(str(e), max_length=200)
            LOG.info(
                'Unable to use native "unzip" command (using fallback mechanism): %s' % error_str
            )

    try:
        zip_ref = zipfile.ZipFile(path, "r")
    except Exception as e:
        LOG.warning("Unable to open zip file: %s: %s" % (path, e))
        raise e

    def _unzip_file_entry(zip_ref, file_entry, target_dir):
        """Extracts a Zipfile entry and preserves permissions"""
        out_path = os.path.join(target_dir, file_entry.filename)
        if is_in_alpine and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
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
    out = run("whoami").strip()
    return out == "root"


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
        return all([os.path.exists(f) for f in files])

    def store_cert_key_files(base_filename):
        key_file_name = "%s.key" % base_filename
        cert_file_name = "%s.crt" % base_filename
        # TODO: Cleaner code to load the cert dinamically
        # extract key and cert from target_file and store into separate files
        content = load_file(target_file)
        key_start = re.search(r"-----BEGIN(.*)PRIVATE KEY-----", content)
        key_start = key_start.group(0)
        key_end = re.search(r"-----END(.*)PRIVATE KEY-----", content)
        key_end = key_end.group(0)
        cert_start = "-----BEGIN CERTIFICATE-----"
        cert_end = "-----END CERTIFICATE-----"
        key_content = content[content.index(key_start) : content.index(key_end) + len(key_end)]
        cert_content = content[content.index(cert_start) : content.rindex(cert_end) + len(cert_end)]
        save_file(key_file_name, key_content)
        save_file(cert_file_name, cert_content)
        return cert_file_name, key_file_name

    if target_file and not overwrite and os.path.exists(target_file):
        key_file_name = ""
        cert_file_name = ""
        try:
            cert_file_name, key_file_name = store_cert_key_files(target_file)
        except Exception as e:
            # fall back to temporary files if we cannot store/overwrite the files above
            LOG.info(
                "Error storing key/cert SSL files (falling back to random tmp file names): %s" % e
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
                        "Unable to store certificate file under %s, using tmp file instead: %s"
                        % (target_file, e)
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


def run_safe(_python_lambda, *args, **kwargs):
    print_error = kwargs.get("print_error", False)
    try:
        return _python_lambda(*args, **kwargs)
    except Exception as e:
        if print_error:
            LOG.warning("Unable to execute function: %s" % e)


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


def do_run(cmd: str, run_cmd: Callable, cache_duration_secs: int):
    if cache_duration_secs <= 0:
        return run_cmd()

    hashcode = md5(cmd)
    cache_file = CACHE_FILE_PATTERN.replace("*", hashcode)
    mkdir(os.path.dirname(CACHE_FILE_PATTERN))
    if os.path.isfile(cache_file):
        # check file age
        mod_time = os.path.getmtime(cache_file)
        time_now = now()
        if mod_time > (time_now - cache_duration_secs):
            with open(cache_file) as fd:
                return fd.read()
    result = run_cmd()
    with open(cache_file, "w+") as fd:
        fd.write(result)
    clean_cache()
    return result


def run(cmd, cache_duration_secs=0, **kwargs):
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


class _RequestsSafe(type):
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


# create class-of-a-class
class safe_requests(six.with_metaclass(_RequestsSafe)):
    pass


def make_http_request(url, data=None, headers=None, method="GET"):
    return requests.request(
        url=url, method=method, headers=headers, data=data, auth=NetrcBypassAuth(), verify=False
    )


class SafeStringIO(io.StringIO):
    """Safe StringIO implementation that doesn't fail if str is passed in Python 2."""

    def write(self, obj):
        if six.PY2 and isinstance(obj, str):
            obj = obj.decode("unicode-escape")
        return super(SafeStringIO, self).write(obj)


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


def truncate(data, max_length=100):
    data = str(data or "")
    return ("%s..." % data[:max_length]) if len(data) > max_length else data


def get_all_subclasses(clazz):
    """Recursively get all subclasses of the given class."""
    result = set()
    subs = clazz.__subclasses__()
    for sub in subs:
        result.add(sub)
        result.update(get_all_subclasses(sub))
    return result


def parallelize(func, arr, size=None):
    if not size:
        size = len(arr)
    if size <= 0:
        return None

    with Pool(size) as pool:
        return pool.map(func, arr)


def isoformat_milliseconds(t):
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


# Code that requires util functions from above
CACHE_FILE_PATTERN = CACHE_FILE_PATTERN.replace("_random_dir_", short_uid())
