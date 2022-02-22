import glob
import io
import logging
import os
import re
import tempfile
import threading
from typing import Callable, Optional

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
    is_none_or_empty,
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
from localstack.utils.functions import (  # noqa
    call_safe,
    empty_context_manager,
    prevent_stack_overflow,
    run_safe,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.http import (  # noqa
    NetrcBypassAuth,
    _RequestsSafe,
    download,
    get_proxies,
    make_http_request,
    parse_request_data,
    replace_response_content,
    safe_requests,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.json import (  # noqa
    CustomEncoder,
    FileMappedDocument,
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
    PortNotAvailableException,
    PortRange,
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

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.run import (  # noqa
    CaptureOutput,
    ShellCommandThread,
    get_os_user,
    is_command_available,
    is_root,
    kill_process_tree,
    run,
    run_for_max_seconds,
)

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.strings import (  # noqa
    base64_to_hex,
    camel_to_snake_case,
    canonicalize_bool_to_str,
    convert_to_printable_chars,
    first_char_to_lower,
    first_char_to_upper,
    is_base64,
    is_string,
    is_string_or_bytes,
    long_uid,
    md5,
    short_uid,
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
from localstack.utils.threads import (  # noqa
    TMP_PROCESSES,
    TMP_THREADS,
    FuncThread,
    cleanup_threads_and_processes,
    parallelize,
    start_thread,
    start_worker_thread,
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
from localstack.utils.urls import path_from_url  # noqa

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.xml import obj_to_xml, strip_xmlns  # noqa

# set up logger
LOG = logging.getLogger(__name__)

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


class ExternalServicePortsManager(PortRange):
    """Manages the ports used for starting external services like ElasticSearch, OpenSearch,..."""

    def __init__(self):
        super().__init__(config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END)


external_service_ports = ExternalServicePortsManager()


def get_service_protocol():
    return "https" if config.USE_SSL else "http"


def edge_ports_info():
    if config.EDGE_PORT_HTTP:
        result = "ports %s/%s" % (config.EDGE_PORT, config.EDGE_PORT_HTTP)
    else:
        result = "port %s" % config.EDGE_PORT
    result = "%s %s" % (get_service_protocol(), result)
    return result


def cleanup(files=True, env=ENV_DEV, quiet=True):
    if files:
        cleanup_tmp_files()


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


# TODO: replace references to safe_run with localstack.utils.run.run
safe_run = run


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


# Code that requires util functions from above
CACHE_FILE_PATTERN = CACHE_FILE_PATTERN.replace("_random_dir_", short_uid())
