from localstack import config

# TODO: remove imports from here (need to update any client code that imports these from utils.common)
from localstack.utils.archives import get_unzipped_size, is_zip_file, untar, unzip  # noqa

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
from localstack.utils.crypto import (  # noqa
    PEM_CERT_END,
    PEM_CERT_START,
    PEM_KEY_END_REGEX,
    PEM_KEY_START_REGEX,
    generate_ssl_cert,
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
    short_uid_from_seed,
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


# TODO: move somewhere sensible (probably localstack.runtime)
class ExternalServicePortsManager(PortRange):
    """Manages the ports used for starting external services like ElasticSearch, OpenSearch,..."""

    def __init__(self):
        super().__init__(config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END)


external_service_ports = ExternalServicePortsManager()
"""The PortRange object of LocalStack's external service port range. This port range is by default exposed by the
localstack container when starting via the CLI."""

# TODO: replace references with config.get_protocol/config.edge_ports_info
get_service_protocol = config.get_protocol

# TODO: replace references to safe_run with localstack.utils.run.run
safe_run = run
