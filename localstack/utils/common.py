import io
import os
import re
import sys
import pty
import json
import uuid
import time
import glob
import base64
import select
import socket
import hashlib
import decimal
import logging
import zipfile
import binascii
import tempfile
import threading
import traceback
import subprocess
import six
import shutil
import requests
from io import BytesIO
from functools import wraps
from contextlib import closing
from datetime import datetime
from six.moves.urllib.parse import urlparse
from six.moves import cStringIO as StringIO
from six import with_metaclass
from multiprocessing.dummy import Pool
from localstack.constants import ENV_DEV, LOCALSTACK_ROOT_FOLDER
from localstack.config import DEFAULT_ENCODING
from localstack import config

# arrays for temporary files and resources
TMP_FILES = []
TMP_THREADS = []

# cache clean variables
CACHE_CLEAN_TIMEOUT = 60 * 5
CACHE_MAX_AGE = 60 * 60
CACHE_FILE_PATTERN = os.path.join(tempfile.gettempdir(), 'cache.*.json')
last_cache_clean_time = {'time': 0}
mutex_clean = threading.Semaphore(1)
mutex_popen = threading.Semaphore(1)

# misc. constants
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S'
TIMESTAMP_FORMAT_MILLIS = '%Y-%m-%dT%H:%M:%S.%fZ'
CODEC_HANDLER_UNDERSCORE = 'underscore'

# chunk size for file downloads
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

# set up logger
LOGGER = logging.getLogger(__name__)

# flag to indicate whether we've received and processed the stop signal
INFRA_STOPPED = False


class CustomEncoder(json.JSONEncoder):
    """ Helper class to convert JSON documents with datetime, decimals, or bytes. """

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        if isinstance(o, datetime):
            return str(o)
        if isinstance(o, six.binary_type):
            return to_str(o)
        return super(CustomEncoder, self).default(o)


class FuncThread(threading.Thread):
    """ Helper class to run a Python function in a background thread. """

    def __init__(self, func, params=None, quiet=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self.params = params
        self.func = func
        self.quiet = quiet

    def run(self):
        try:
            self.func(self.params)
        except Exception:
            if not self.quiet:
                LOGGER.warning('Thread run method %s(%s) failed: %s' %
                    (self.func, self.params, traceback.format_exc()))

    def stop(self, quiet=False):
        if not quiet and not self.quiet:
            LOGGER.warning('Not implemented: FuncThread.stop(..)')


class ShellCommandThread(FuncThread):
    """ Helper class to run a shell command in a background thread. """

    def __init__(self, cmd, params={}, outfile=None, env_vars={}, stdin=False,
            quiet=True, inherit_cwd=False):
        self.cmd = cmd
        self.process = None
        self.outfile = outfile or os.devnull
        self.stdin = stdin
        self.env_vars = env_vars
        self.inherit_cwd = inherit_cwd
        FuncThread.__init__(self, self.run_cmd, params, quiet=quiet)

    def run_cmd(self, params):

        def convert_line(line):
            line = to_str(line or '')
            return line.strip() + '\r\n'

        try:
            self.process = run(self.cmd, asynchronous=True, stdin=self.stdin, outfile=self.outfile,
                env_vars=self.env_vars, inherit_cwd=self.inherit_cwd)
            if self.outfile:
                if self.outfile == subprocess.PIPE:
                    # get stdout/stderr from child process and write to parent output
                    streams = ((self.process.stdout, sys.stdout), (self.process.stderr, sys.stderr))
                    for instream, outstream in streams:
                        for line in iter(instream.readline, None):
                            # `line` should contain a newline at the end as we're iterating,
                            # hence we can safely break the loop if `line` is None or empty string
                            if line in [None, '', b'']:
                                break
                            if not (line and line.strip()) and self.is_killed():
                                break
                            line = convert_line(line)
                            outstream.write(line)
                            outstream.flush()
                self.process.wait()
            else:
                self.process.communicate()
        except Exception as e:
            if self.process and not self.quiet:
                LOGGER.warning('Shell command error "%s": %s' % (e, self.cmd))
        if self.process and not self.quiet and self.process.returncode != 0:
            LOGGER.warning('Shell command exit code "%s": %s' % (self.process.returncode, self.cmd))

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
        # Note: Do NOT import "psutil" at the root scope, as this leads
        # to problems when importing this file from our test Lambdas in Docker
        # (Error: libc.musl-x86_64.so.1: cannot open shared object file)
        import psutil

        if not self.process:
            LOGGER.warning("No process found for command '%s'" % self.cmd)
            return

        parent_pid = self.process.pid
        try:
            parent = psutil.Process(parent_pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
            self.process = None
        except Exception:
            if not quiet:
                LOGGER.warning('Unable to kill process with pid %s' % parent_pid)


class JsonObject(object):
    """ Generic JSON serializable object for simplified subclassing """

    def to_json(self, indent=None):
        return json.dumps(self,
            default=lambda o: ((float(o) if o % 1 > 0 else int(o))
                if isinstance(o, decimal.Decimal) else o.__dict__),
            sort_keys=True, indent=indent)

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
    def from_json_list(cls, l):
        return [cls.from_json(j) for j in l]

    @classmethod
    def as_dict(cls, obj):
        if isinstance(obj, dict):
            return obj
        return obj.to_dict()

    def __str__(self):
        return self.to_json()

    def __repr__(self):
        return self.__str__()


class CaptureOutput(object):
    """ A context manager that captures stdout/stderr of the current thread. Use it as follows:

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
            if isinstance(s, str) and hasattr(s, 'decode'):
                s = s.decode('unicode-escape')
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
            self._set(LocalProxy(self._proxy(sys.stdout, 'stdout')),
                      LocalProxy(self._proxy(sys.stderr, 'stderr')),
                      LocalProxy(self._proxy(sys.__stdout__, 'stdout')),
                      LocalProxy(self._proxy(sys.__stderr__, 'stderr')))
        return self

    def __exit__(self, type, value, traceback):
        ident = self._ident()
        removed = self.CONTEXTS_BY_THREAD.pop(ident, None)
        if not self.CONTEXTS_BY_THREAD:
            # reset pointers
            self._set(self.orig_stdout, self.orig_stderr, self.orig___stdout, self.orig___stderr)
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
        sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__ = (out, err, __out, __err)

    def _proxy(self, original_stream, type):
        def proxy():
            ident = self._ident()
            ctx = self.CONTEXTS_BY_THREAD.get(ident)
            if ctx:
                return ctx._stdout if type == 'stdout' else ctx._stderr
            return original_stream

        return proxy

    def _ident(self):
        return threading.currentThread().ident

    def stdout(self):
        return self._stdout.getvalue() if hasattr(self._stdout, 'getvalue') else self._stdout

    def stderr(self):
        return self._stderr.getvalue() if hasattr(self._stderr, 'getvalue') else self._stderr


# ----------------
# UTILITY METHODS
# ----------------


def is_string(s, include_unicode=True):
    if isinstance(s, str):
        return True
    if include_unicode and isinstance(s, six.text_type):
        return True
    return False


def is_string_or_bytes(s):
    return is_string(s) or isinstance(s, six.string_types) or isinstance(s, bytes)


def md5(string):
    m = hashlib.md5()
    m.update(to_bytes(string))
    return m.hexdigest()


def in_ci():
    """ Whether or not we are running in a CI environment """
    for key in ('CI', 'TRAVIS'):
        if os.environ.get(key, '') not in [False, '', '0', 'false']:
            return True
    return False


def in_docker():
    return config.in_docker()


def is_port_open(port_or_url, http_path=None, expect_success=True):
    port = port_or_url
    host = 'localhost'
    protocol = 'http'
    if isinstance(port, six.string_types):
        url = urlparse(port_or_url)
        port = url.port
        host = url.hostname
        protocol = url.scheme
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result != 0:
            return False
    if not http_path:
        return True
    url = '%s://%s:%s%s' % (protocol, host, port, http_path)
    try:
        response = safe_requests.get(url)
        return not expect_success or response.status_code < 400
    except Exception:
        return False


def wait_for_port_open(port, http_path=None, expect_success=True, retries=10, sleep_time=0.5):
    """ Ping the given network port until it becomes available (for a given number of retries).
        If 'http_path' is set, make a GET request to this path and assert a non-error response. """
    def check():
        if not is_port_open(port, http_path=http_path, expect_success=expect_success):
            raise Exception()

    return retry(check, sleep=sleep_time, retries=retries)


def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port


def get_service_protocol():
    return 'https' if config.USE_SSL else 'http'


def timestamp(time=None, format=TIMESTAMP_FORMAT):
    if not time:
        time = datetime.utcnow()
    if isinstance(time, six.integer_types + (float, )):
        time = datetime.fromtimestamp(time)
    return time.strftime(format)


def retry(function, retries=3, sleep=1, sleep_before=0, **kwargs):
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


def dump_thread_info():
    for t in threading.enumerate():
        print(t)
    print(run("ps aux | grep 'node\\|java\\|python'"))


def merge_recursive(source, destination):
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge_recursive(value, node)
        else:
            if not isinstance(destination, dict):
                LOGGER.warning('Destination for merging %s=%s is not dict: %s' %
                    (key, value, destination))
            destination[key] = value
    return destination


def merge_dicts(*dicts, **kwargs):
    """ Merge all dicts in `*dicts` into a single dict, and return the result. If any of the entries
        in `*dicts` is None, and `default` is specified as keyword argument, then return `default`. """
    result = {}
    for d in dicts:
        if d is None and 'default' in kwargs:
            return kwargs['default']
        if d:
            result.update(d)
    return result


def base64_to_hex(b64_string):
    return binascii.hexlify(base64.b64decode(b64_string))


def now_utc():
    return mktime(datetime.utcnow())


def now():
    return mktime(datetime.now())


def mktime(timestamp):
    return time.mktime(timestamp.timetuple())


def mkdir(folder):
    if not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except OSError as err:
            # Ignore rare 'File exists' race conditions.
            if err.errno != 17:
                raise


def ensure_readable(file_path, default_perms=None):
    if default_perms is None:
        default_perms = 0o644
    try:
        with open(file_path, 'rb'):
            pass
    except Exception:
        LOGGER.info('Updating permissions as file is currently not readable: %s' % file_path)
        os.chmod(file_path, default_perms)


def chmod_r(path, mode):
    """Recursive chmod"""
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
    # Make sure all files are writeable and dirs executable to remove
    chmod_r(path, 0o777)
    if os.path.isfile(path):
        os.remove(path)
    else:
        shutil.rmtree(path)


def cp_r(src, dst):
    """Recursively copies file/directory"""
    if os.path.isfile(src):
        shutil.copy(src, dst)
    else:
        shutil.copytree(src, dst)


def download(url, path, verify_ssl=True):
    """Downloads file at url to the given path"""
    # make sure we're creating a new session here to
    # enable parallel file downloads during installation!
    s = requests.Session()
    r = s.get(url, stream=True, verify=verify_ssl)
    total = 0
    try:
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        LOGGER.debug('Starting download from %s to %s (%s bytes)' % (url, path, r.headers.get('content-length')))
        with open(path, 'wb') as f:
            for chunk in r.iter_content(DOWNLOAD_CHUNK_SIZE):
                total += len(chunk)
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                    LOGGER.debug('Writing %s bytes (total %s) to %s' % (len(chunk), total, path))
                else:
                    LOGGER.debug('Empty chunk %s (total %s) from %s' % (chunk, total, url))
            f.flush()
            os.fsync(f)
    finally:
        LOGGER.debug('Done downloading %s, response code %s' % (url, r.status_code))
        r.close()
        s.close()


def parse_chunked_data(data):
    """ Parse the body of an HTTP message transmitted with chunked transfer encoding. """
    data = (data or '').strip()
    chunks = []
    while data:
        length = re.match(r'^([0-9a-zA-Z]+)\r\n.*', data)
        if not length:
            break
        length = length.group(1).lower()
        length = int(length, 16)
        data = data.partition('\r\n')[2]
        chunks.append(data[:length])
        data = data[length:].strip()
    return ''.join(chunks)


def is_number(s):
    try:
        float(s)  # for int, long and float
        return True
    except ValueError:
        return False


def short_uid():
    return str(uuid.uuid4())[0:8]


def json_safe(item):
    """ return a copy of the given object (e.g., dict) that is safe for JSON dumping """
    try:
        return json.loads(json.dumps(item, cls=CustomEncoder))
    except Exception:
        item = fix_json_keys(item)
        return json.loads(json.dumps(item, cls=CustomEncoder))


def fix_json_keys(item):
    """ make sure the keys of a JSON are strings (not binary type or other) """
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


def save_file(file, content, append=False):
    mode = 'a' if append else 'w+'
    if not isinstance(content, six.string_types):
        mode = mode + 'b'
    with open(file, mode) as f:
        f.write(content)
        f.flush()


def load_file(file_path, default=None, mode=None):
    if not os.path.isfile(file_path):
        return default
    if not mode:
        mode = 'r'
    with open(file_path, mode) as f:
        result = f.read()
    return result


def docker_container_running(container_name):
    container_names = re.split(r'\s+', run("docker ps --format '{{.Names}}'").replace('\n', ' '))
    return container_name in container_names


def to_str(obj, encoding=DEFAULT_ENCODING, errors='strict'):
    """ If ``obj`` is an instance of ``binary_type``, return
    ``obj.decode(encoding, errors)``, otherwise return ``obj`` """
    return obj.decode(encoding, errors) if isinstance(obj, six.binary_type) else obj


def to_bytes(obj, encoding=DEFAULT_ENCODING, errors='strict'):
    """ If ``obj`` is an instance of ``text_type``, return
    ``obj.encode(encoding, errors)``, otherwise return ``obj`` """
    return obj.encode(encoding, errors) if isinstance(obj, six.text_type) else obj


def cleanup(files=True, env=ENV_DEV, quiet=True):
    if files:
        cleanup_tmp_files()


def cleanup_threads_and_processes(quiet=True):
    for t in TMP_THREADS:
        t.stop(quiet=quiet)
    # clear list
    clear_list(TMP_THREADS)


def clear_list(l):
    while len(l):
        del l[0]


def cleanup_tmp_files():
    for tmp in TMP_FILES:
        try:
            if os.path.isdir(tmp):
                run('rm -rf "%s"' % tmp)
            else:
                os.remove(tmp)
        except Exception:
            pass  # file likely doesn't exist, or permission denied
    del TMP_FILES[:]


def new_tmp_file():
    """ Return a path to a new temporary file. """
    tmp_file, tmp_path = tempfile.mkstemp()
    os.close(tmp_file)
    TMP_FILES.append(tmp_path)
    return tmp_path


def is_ip_address(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def is_zip_file(content):
    stream = BytesIO(content)
    return zipfile.is_zipfile(stream)


def unzip(path, target_dir):
    try:
        zip_ref = zipfile.ZipFile(path, 'r')
    except Exception as e:
        LOGGER.warning('Unable to open zip file: %s: %s' % (path, e))
        raise e
    # Make sure to preserve file permissions in the zip file
    # https://www.burgundywall.com/post/preserving-file-perms-with-python-zipfile-module
    for file_entry in zip_ref.infolist():
        _unzip_file_entry(zip_ref, file_entry, target_dir)
    zip_ref.close()


def _unzip_file_entry(zip_ref, file_entry, target_dir):
    """
    Extracts a Zipfile entry and preserves permissions
    """
    zip_ref.extract(file_entry.filename, path=target_dir)
    out_path = os.path.join(target_dir, file_entry.filename)
    perm = file_entry.external_attr >> 16
    os.chmod(out_path, perm or 0o777)


def is_jar_archive(content):
    has_class_content = False
    try:
        has_class_content = 'class' in content
    except TypeError:
        # in Python 3 we need to use byte strings for byte-based file content
        has_class_content = b'class' in content
    if not has_class_content:
        return False
    try:
        with tempfile.NamedTemporaryFile() as tf:
            tf.write(content)
            tf.flush()
            with zipfile.ZipFile(tf.name, 'r') as zf:
                zf.infolist()
    except Exception:
        return False
    return True


def is_root():
    out = run('whoami').strip()
    return out == 'root'


def cleanup_resources():
    cleanup_tmp_files()
    cleanup_threads_and_processes()


def generate_ssl_cert(target_file=None, overwrite=False, random=False):
    # Note: Do NOT import "OpenSSL" at the root scope
    # (Our test Lambdas are importing this file but don't have the module installed)
    from OpenSSL import crypto

    if os.path.exists(target_file):
        key_file_name = '%s.key' % target_file
        cert_file_name = '%s.crt' % target_file
        return target_file, cert_file_name, key_file_name
    if random and target_file:
        if '.' in target_file:
            target_file = target_file.replace('.', '.%s.' % short_uid(), 1)
        else:
            target_file = '%s.%s' % (target_file, short_uid())
    if target_file and not overwrite and os.path.exists(target_file):
        return

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    subj = cert.get_subject()
    subj.C = 'AU'
    subj.ST = 'Some-State'
    subj.L = 'Some-Locality'
    subj.O = 'LocalStack Org'  # noqa
    subj.OU = 'Testing'
    subj.CN = 'LocalStack'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    cert_file = StringIO()
    key_file = StringIO()
    cert_file.write(to_str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
    key_file.write(to_str(crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))
    cert_file_content = cert_file.getvalue().strip()
    key_file_content = key_file.getvalue().strip()
    file_content = '%s\n%s' % (key_file_content, cert_file_content)
    if target_file:
        save_file(target_file, file_content)
        key_file_name = '%s.key' % target_file
        cert_file_name = '%s.crt' % target_file
        save_file(key_file_name, key_file_content)
        save_file(cert_file_name, cert_file_content)
        TMP_FILES.append(target_file)
        TMP_FILES.append(key_file_name)
        TMP_FILES.append(cert_file_name)
        if random:
            return target_file, cert_file_name, key_file_name
        return file_content
    return file_content


def run_safe(_python_lambda, print_error=True, **kwargs):
    try:
        return _python_lambda(**kwargs)
    except Exception as e:
        if print_error:
            print('Unable to execute function: %s' % e)


def run_cmd_safe(**kwargs):
    return run_safe(run, print_error=False, **kwargs)


def run(cmd, cache_duration_secs=0, print_error=True, asynchronous=False, stdin=False,
        stderr=subprocess.STDOUT, outfile=None, env_vars=None, inherit_cwd=False, tty=False):
    # don't use subprocess module inn Python 2 as it is not thread-safe
    # http://stackoverflow.com/questions/21194380/is-subprocess-popen-not-thread-safe
    if six.PY2:
        import subprocess32 as subprocess
    else:
        import subprocess

    env_dict = os.environ.copy()
    if env_vars:
        env_dict.update(env_vars)

    if tty:
        asynchronous = True
        stdin = True

    def do_run(cmd):
        try:
            cwd = os.getcwd() if inherit_cwd else None
            if not asynchronous:
                if stdin:
                    return subprocess.check_output(cmd, shell=True, stderr=stderr, env=env_dict,
                        stdin=subprocess.PIPE, cwd=cwd)
                output = subprocess.check_output(cmd, shell=True, stderr=stderr, env=env_dict, cwd=cwd)
                return output.decode(DEFAULT_ENCODING)

            # subprocess.Popen is not thread-safe, hence use a mutex here.. (TODO: mutex still needed?)
            with mutex_popen:
                stdin_arg = subprocess.PIPE if stdin else None
                stdout_arg = open(outfile, 'wb') if isinstance(outfile, six.string_types) else outfile
                stderr_arg = stderr
                if tty:
                    master_fd, slave_fd = pty.openpty()
                    stdin_arg = slave_fd
                    stdout_arg = stderr_arg = None

                # start the actual sub process
                process = subprocess.Popen(cmd, shell=True, stdin=stdin_arg, bufsize=-1,
                    stderr=stderr_arg, stdout=stdout_arg, env=env_dict, cwd=cwd, preexec_fn=os.setsid)

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

    if cache_duration_secs <= 0:
        return do_run(cmd)
    hash = md5(cmd)
    cache_file = CACHE_FILE_PATTERN.replace('*', hash)
    if os.path.isfile(cache_file):
        # check file age
        mod_time = os.path.getmtime(cache_file)
        time_now = now()
        if mod_time > (time_now - cache_duration_secs):
            f = open(cache_file)
            result = f.read()
            f.close()
            return result
    result = do_run(cmd)
    f = open(cache_file, 'w+')
    f.write(result)
    f.close()
    clean_cache()
    return result


def clone(item):
    return json.loads(json.dumps(item))


def remove_non_ascii(text):
    # text = unicode(text, "utf-8")
    text = text.decode('utf-8', CODEC_HANDLER_UNDERSCORE)
    # text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', CODEC_HANDLER_UNDERSCORE)
    return text


class NetrcBypassAuth(requests.auth.AuthBase):
    def __call__(self, r):
        return r


class _RequestsSafe(type):
    """ Wrapper around requests library, which can prevent it from verifying
    SSL certificates or reading credentials from ~/.netrc file """
    verify_ssl = True

    def __getattr__(self, name):
        method = requests.__dict__.get(name.lower())
        if not method:
            return method

        def _wrapper(*args, **kwargs):
            if 'auth' not in kwargs:
                kwargs['auth'] = NetrcBypassAuth()
            if not self.verify_ssl and args[0].startswith('https://') and 'verify' not in kwargs:
                kwargs['verify'] = False
            return method(*args, **kwargs)
        return _wrapper


# create class-of-a-class
class safe_requests(with_metaclass(_RequestsSafe)):
    pass


def make_http_request(url, data=None, headers=None, method='GET'):

    if is_string(method):
        method = requests.__dict__[method.lower()]

    return method(url, headers=headers, data=data, auth=NetrcBypassAuth(), verify=False)


class SafeStringIO(io.StringIO):
    """ Safe StringIO implementation that doesn't fail if str is passed in Python 2. """
    def write(self, obj):
        if six.PY2 and isinstance(obj, str):
            obj = obj.decode('unicode-escape')
        return super(SafeStringIO, self).write(obj)


def profiled(lines=50):
    """ Function decorator that profiles code execution. """
    skipped_lines = ['site-packages', 'lib/python']
    skipped_lines = []

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            import yappi
            yappi.start()
            try:
                return f(*args, **kwargs)
            finally:
                result = list(yappi.get_func_stats())
                yappi.stop()
                yappi.clear_stats()
                result = [l for l in result if all([s not in l.full_name for s in skipped_lines])]
                entries = result[:lines]
                prefix = LOCALSTACK_ROOT_FOLDER
                result = []
                result.append('ncall\tttot\ttsub\ttavg\tname')

                def c(num):
                    return str(num)[:7]

                for e in entries:
                    name = e.full_name.replace(prefix, '')
                    result.append('%s\t%s\t%s\t%s\t%s' % (c(e.ncall), c(e.ttot), c(e.tsub), c(e.tavg), name))
                result = '\n'.join(result)
                print(result)
        return wrapped
    return wrapper


def clean_cache(file_pattern=CACHE_FILE_PATTERN,
        last_clean_time=last_cache_clean_time, max_age=CACHE_MAX_AGE):

    mutex_clean.acquire()
    time_now = now()
    try:
        if last_clean_time['time'] > time_now - CACHE_CLEAN_TIMEOUT:
            return
        for cache_file in set(glob.glob(file_pattern)):
            mod_time = os.path.getmtime(cache_file)
            if time_now > mod_time + max_age:
                rm_rf(cache_file)
        last_clean_time['time'] = time_now
    finally:
        mutex_clean.release()
    return time_now


def truncate(data, max_length=100):
    return (data[:max_length] + '...') if len(data) > max_length else data


def parallelize(func, list, size=None):
    if not size:
        size = len(list)
    if size <= 0:
        return None
    pool = Pool(size)
    result = pool.map(func, list)
    pool.close()
    pool.join()
    return result


def isoformat_milliseconds(t):
    try:
        return t.isoformat(timespec='milliseconds')
    except TypeError:
        return t.isoformat()[:-3]
