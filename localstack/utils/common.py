import threading
import traceback
import os
import hashlib
import uuid
import time
import glob
import requests
import sh
from datetime import datetime
from multiprocessing.dummy import Pool
from localstack.constants import *

# arrays for temporary files and resources
TMP_FILES = []
TMP_THREADS = []

# cache clean variables
CACHE_CLEAN_TIMEOUT = 60 * 5
CACHE_MAX_AGE = 60 * 60
CACHE_FILE_PATTERN = '/tmp/cache.*.json'
last_cache_clean_time = {'time': 0}
mutex_clean = threading.Semaphore(1)
mutex_popen = threading.Semaphore(1)

# misc. constants
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S'


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
        except Exception, e:
            if not self.quiet:
                print("Thread run method %s(%s) failed: %s" %
                    (self.func, self.params, traceback.format_exc()))

    def stop(self, quiet=False):
        if not quiet and not self.quiet:
            print("WARN: not implemented: FuncThread.stop(..)")


class ShellCommandThread (FuncThread):
    def __init__(self, cmd, params={}, outfile=None, env_vars={}, stdin=False,
            quiet=True, inherit_cwd=False):
        self.cmd = cmd
        self.process = None
        self.outfile = outfile
        self.stdin = stdin
        self.env_vars = env_vars
        self.inherit_cwd = inherit_cwd
        FuncThread.__init__(self, self.run_cmd, params, quiet=quiet)

    def run_cmd(self, params):
        try:
            self.process = run(self.cmd, async=True, stdin=self.stdin, outfile=self.outfile,
                env_vars=self.env_vars, inherit_cwd=self.inherit_cwd)
            if self.outfile:
                self.process.wait()
            else:
                self.process.communicate()
        except Exception, e:
            if self.process and not self.quiet:
                print('Shell command error "%s": %s' % (e, self.cmd))
        if self.process and not self.quiet and self.process.returncode != 0:
            print('Shell command exit code "%s": %s' % (self.process.returncode, self.cmd))

    def is_killed(self):
        if not self.process:
            return True
        pid = self.process.pid
        out = run("ps aux 2>&1 | grep '[^\s]*\s*%s\s' | grep -v grep |  grep ''" % pid)
        return (not out)

    def stop(self, quiet=False):
        SIGINT = 2
        SIGKILL = 9
        if not self.process:
            print("WARN: No process found for command '%s'" % self.cmd)
            return
        pid = self.process.pid
        try:
            os.kill(pid, SIGTERM)
        except Exception, e:
            if not quiet:
                print('WARN: Unable to kill process with pid %s' % pid)
        finally:
            try:
                os.kill(pid, SIGINT)
            except Exception, e:
                pass


def is_string(s, include_unicode=True):
    if isinstance(s, str):
        return True
    if include_unicode and isinstance(s, unicode):
        return True
    return False


def md5(string):
    m = hashlib.md5()
    m.update(string)
    return m.hexdigest()


def timestamp(time=None, format=TIMESTAMP_FORMAT):
    if not time:
        time = datetime.utcnow()
    if isinstance(time, (int, long, float)):
        time = datetime.fromtimestamp(time)
    return time.strftime(format)


def retry(function, retries=3, sleep=1, sleep_before=0, **kwargs):
    error = None
    if sleep_before > 0:
        time.sleep(sleep_before)
    for i in range(0, retries + 1):
        try:
            return function(**kwargs)
        except Exception, error:
            time.sleep(sleep)
    raise error


def now():
    return time.mktime(datetime.utcnow().timetuple())


def short_uid():
    return str(uuid.uuid4())[0:8]


def save_file(file, content, append=False):
    with open(file, 'a' if append else 'w+') as f:
        f.write(content)
        f.flush()


def load_file(file, default=None):
    if not os.path.isfile(file):
        return default
    with open(file) as f:
        result = f.read()
    return result


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
        except Exception, e:
            pass  # file likely doesn't exist, or permission denied
    del TMP_FILES[:]


def is_jar_archive(content):
    # TODO Simple stupid heuristic to determine whether a file is a JAR archive
    return 'KinesisEvent' in content and 'class' in content and 'META-INF' in content


def cleanup_resources():
    cleanup_tmp_files()
    cleanup_threads_and_processes()


def run(cmd, cache_duration_secs=0, print_error=True, async=False, stdin=False, outfile=None,
        env_vars=None, inherit_cwd=False):
    # don't use subprocess module as it is not thread-safe
    # http://stackoverflow.com/questions/21194380/is-subprocess-popen-not-thread-safe
    # import subprocess
    import subprocess32 as subprocess

    env_dict = os.environ.copy()
    if env_vars:
        env_dict.update(env_vars)

    def do_run(cmd):
        try:
            cwd = os.getcwd() if inherit_cwd else None
            if not async:
                if stdin:
                    return subprocess.check_output(cmd, shell=True,
                        stderr=subprocess.STDOUT, stdin=subprocess.PIPE, env=env_dict, cwd=cwd)
                return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, env=env_dict, cwd=cwd)
            # subprocess.Popen is not thread-safe, hence use a mutex here..
            try:
                mutex_popen.acquire()
                stdin_arg = subprocess.PIPE if stdin else None
                stdout_arg = (open(outfile, 'wb') if isinstance(outfile, basestring) else
                    outfile if outfile else open(os.devnull, 'w'))
                process = subprocess.Popen(cmd, shell=True, stdin=stdin_arg,
                    stderr=subprocess.STDOUT, stdout=stdout_arg, env=env_dict, cwd=cwd)
                return process
            finally:
                mutex_popen.release()
        except subprocess.CalledProcessError, e:
            if print_error:
                print("ERROR: '%s': %s" % (cmd, e.output))
            raise e
    if cache_duration_secs <= 0:
        return do_run(cmd)
    hash = md5(cmd)
    cache_file = CACHE_FILE_PATTERN.replace('*', '%s') % hash
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


def remove_non_ascii(text):
    # text = unicode(text, "utf-8")
    text = text.decode('utf-8', CODEC_HANDLER_UNDERSCORE)
    # text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', CODEC_HANDLER_UNDERSCORE)
    return text


def make_http_request(url, data=None, headers=None, method='GET'):
    if is_string(method):
        method = requests.__dict__[method.lower()]

    class NetrcBypassAuth(requests.auth.AuthBase):
        """avoid requests library reading credentials from ~/.netrc file"""
        def __call__(self, r):
            return r

    return method(url, headers=headers, data=data, auth=NetrcBypassAuth())


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
                sh.rm('-r', cache_file)
        last_clean_time['time'] = time_now
    finally:
        mutex_clean.release()
    return time_now


def truncate(data, max_length=100):
    return (data[:max_length] + '...') if len(data) > max_length else data


def parallelize(func, list, size=None):
    if not size:
        size = len(list)
    pool = Pool(size)
    result = pool.map(func, list)
    pool.close()
    pool.join()
    return result
