from __future__ import print_function

import threading
import traceback
import os
import sys
import hashlib
import uuid
import time
import glob
import subprocess
import six
import shutil
import socket
import json
import decimal
import logging
import tempfile
import requests
import zipfile
from io import BytesIO
from contextlib import closing
from datetime import datetime
from six.moves.urllib.parse import urlparse
from six.moves import cStringIO as StringIO
from six import with_metaclass
from multiprocessing.dummy import Pool
from localstack.constants import ENV_DEV
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


# Helper class to convert JSON documents with datetime, decimals, or bytes.
class CustomEncoder(json.JSONEncoder):
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


class FuncThread (threading.Thread):
    def __init__(self, func, params, quiet=False):
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


class ShellCommandThread (FuncThread):
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
            line = to_str(line)
            return line.strip() + '\r\n'

        try:
            self.process = run(self.cmd, async=True, stdin=self.stdin, outfile=self.outfile,
                env_vars=self.env_vars, inherit_cwd=self.inherit_cwd)
            if self.outfile:
                if self.outfile == subprocess.PIPE:
                    # get stdout/stderr from child process and write to parent output
                    for line in iter(self.process.stdout.readline, ''):
                        if not (line and line.strip()) and self.is_killed():
                            break
                        line = convert_line(line)
                        sys.stdout.write(line)
                        sys.stdout.flush()
                    for line in iter(self.process.stderr.readline, ''):
                        if not (line and line.strip()) and self.is_killed():
                            break
                        line = convert_line(line)
                        sys.stderr.write(line)
                        sys.stderr.flush()
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


# Generic JSON serializable object for simplified subclassing
class JsonObject(object):

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


# ----------------
# UTILITY METHODS
# ----------------


def is_string(s, include_unicode=True):
    if isinstance(s, str):
        return True
    if include_unicode and isinstance(s, six.text_type):
        return True
    return False


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


def is_port_open(port_or_url):
    port = port_or_url
    host = '127.0.0.1'
    if isinstance(port, six.string_types):
        url = urlparse(port_or_url)
        port = url.port
        host = url.hostname
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        return result == 0


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


def now_utc():
    return mktime(datetime.utcnow())


def now():
    return mktime(datetime.now())


def mktime(timestamp):
    return time.mktime(timestamp.timetuple())


def mkdir(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)


def chmod_r(path, mode):
    """Recursive chmod"""
    os.chmod(path, mode)

    for root, dirnames, filenames in os.walk(path):
        for dirname in dirnames:
            os.chmod(os.path.join(root, dirname), mode)
        for filename in filenames:
            os.chmod(os.path.join(root, filename), mode)


def rm_rf(path):
    """Recursively removes file/directory"""
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


def short_uid():
    return str(uuid.uuid4())[0:8]


def json_safe(item):
    """ return a copy of the given object (e.g., dict) that is safe for JSON dumping """
    try:
        return json.loads(json.dumps(item, cls=CustomEncoder))
    except:
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


def to_str(obj, encoding=DEFAULT_ENCODING, errors='strict'):
    """If ``obj`` is an instance of ``binary_type``, return
    ``obj.decode(encoding, errors)``, otherwise return ``obj``
    """
    return obj.decode(encoding, errors) if isinstance(obj, six.binary_type) else obj


def to_bytes(obj, encoding=DEFAULT_ENCODING, errors='strict'):
    """ If ``obj`` is an instance of ``text_type``, return
    ``obj.encode(encoding, errors)``, otherwise return ``obj``
    """
    return obj.encode(encoding, errors) if isinstance(obj, six.text_type) else obj


def cleanup(files=True, env=ENV_DEV, quiet=True):
    if files:
        cleanup_tmp_files()


def cleanup_threads_and_processes(quiet=True):
    for t in TMP_THREADS:
        t.stop(quiet=quiet)


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
    zip_ref.extractall(target_dir)
    zip_ref.close()


def is_jar_archive(content):
    # TODO Simple stupid heuristic to determine whether a file is a JAR archive
    try:
        return 'class' in content and 'META-INF' in content
    except TypeError:
        # in Python 3 we need to use byte strings for byte-based file content
        return b'class' in content and b'META-INF' in content


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
    cert.get_subject().C = 'AU'
    cert.get_subject().ST = 'Some-State'
    cert.get_subject().L = 'Some-Locality'
    cert.get_subject().O = 'LocalStack Org'
    cert.get_subject().OU = 'Testing'
    cert.get_subject().CN = 'LocalStack'
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
        _python_lambda(**kwargs)
    except Exception as e:
        if print_error:
            print('Unable to execute function: %s' % e)


def run_cmd_safe(**kwargs):
    return run_safe(run, print_error=False, **kwargs)


def run(cmd, cache_duration_secs=0, print_error=True, async=False, stdin=False,
        stderr=subprocess.STDOUT, outfile=None, env_vars=None, inherit_cwd=False):
    # don't use subprocess module as it is not thread-safe
    # http://stackoverflow.com/questions/21194380/is-subprocess-popen-not-thread-safe
    # import subprocess
    if six.PY2:
        import subprocess32 as subprocess
    else:
        import subprocess

    env_dict = os.environ.copy()
    if env_vars:
        env_dict.update(env_vars)

    def do_run(cmd):
        try:
            cwd = os.getcwd() if inherit_cwd else None
            if not async:
                if stdin:
                    return subprocess.check_output(cmd, shell=True,
                        stderr=stderr, stdin=subprocess.PIPE, env=env_dict, cwd=cwd)
                output = subprocess.check_output(cmd, shell=True, stderr=stderr, env=env_dict, cwd=cwd)
                return output.decode(DEFAULT_ENCODING)
            # subprocess.Popen is not thread-safe, hence use a mutex here..
            try:
                mutex_popen.acquire()
                stdin_arg = subprocess.PIPE if stdin else None
                stdout_arg = open(outfile, 'wb') if isinstance(outfile, six.string_types) else outfile
                process = subprocess.Popen(cmd, shell=True, stdin=stdin_arg, bufsize=-1,
                    stderr=stderr, stdout=stdout_arg, env=env_dict, cwd=cwd)
                return process
            finally:
                mutex_popen.release()
        except subprocess.CalledProcessError as e:
            if print_error:
                print("ERROR: '%s': %s" % (cmd, e.output))
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
    # print("NO CACHED result available for (timeout %s): %s" % (cache_duration_secs,cmd))
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
