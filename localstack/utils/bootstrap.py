import logging
import os
import pkgutil
import re
import shlex
import sys
import threading
import time
import warnings
from datetime import datetime
from functools import wraps

import six

from localstack import config, constants
from localstack.constants import LS_LOG_TRACE_INTERNAL, TRACE_LOG_LEVELS
from localstack.utils.docker_utils import DOCKER_CLIENT, ContainerException, PortMappings

# set up logger
from localstack.utils.run import run, to_str

LOG = logging.getLogger(os.path.basename(__file__))

# maps plugin scope ("services", "commands") to flags which indicate whether plugins have been loaded
PLUGINS_LOADED = {}

# predefined list of plugin modules, to speed up the plugin loading at startup
# note: make sure to load localstack_ext before localstack
PLUGIN_MODULES = ["localstack_ext", "localstack"]

# marker for extended/ignored libs in requirements.txt
IGNORED_LIB_MARKER = "#extended-lib"
BASIC_LIB_MARKER = "#basic-lib"

# whether or not to manually fix permissions on /var/run/docker.sock (currently disabled)
DO_CHMOD_DOCKER_SOCK = False

# log format strings
LOG_FORMAT = "%(asctime)s:%(levelname)s:%(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

# plugin scopes
PLUGIN_SCOPE_SERVICES = "services"
PLUGIN_SCOPE_COMMANDS = "commands"

# maps from API names to list of other API names that they depend on
API_DEPENDENCIES = {
    "dynamodb": ["dynamodbstreams"],
    "dynamodbstreams": ["kinesis"],
    "es": ["elasticsearch"],
    "lambda": ["logs", "cloudwatch"],
    "kinesis": ["dynamodb"],
    "firehose": ["kinesis"],
}
# composites define an abstract name like "serverless" that maps to a set of services
API_COMPOSITES = {
    "serverless": [
        "cloudformation",
        "cloudwatch",
        "iam",
        "sts",
        "lambda",
        "dynamodb",
        "apigateway",
        "s3",
    ],
    "cognito": ["cognito-idp", "cognito-identity"],
}

# main container name determined via "docker inspect"
MAIN_CONTAINER_NAME_CACHED = None

# environment variable that indicates that we're executing in
# the context of the script that starts the Docker container
ENV_SCRIPT_STARTING_DOCKER = "LS_SCRIPT_STARTING_DOCKER"


def log_duration(name=None, min_ms=500):
    """Function decorator to log the duration of function invocations."""

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            from time import perf_counter

            start_time = perf_counter()
            try:
                return f(*args, **kwargs)
            finally:
                end_time = perf_counter()
                func_name = name or f.__name__
                duration = (end_time - start_time) * 1000
                if duration > min_ms:
                    LOG.info('Execution of "%s" took %.2fms', func_name, duration)

        return wrapped

    return wrapper


@log_duration()
def load_plugin_from_path(file_path, scope=None):
    if os.path.exists(file_path):
        delimiters = r"[\\/]"
        not_delimiters = r"[^\\/]"
        regex = r"(^|.+{d})({n}+){d}plugins.py".format(d=delimiters, n=not_delimiters)
        module = re.sub(regex, r"\2", file_path)
        method_name = "register_localstack_plugins"
        scope = scope or PLUGIN_SCOPE_SERVICES
        if scope == PLUGIN_SCOPE_COMMANDS:
            method_name = "register_localstack_commands"
        try:
            namespace = {}
            exec("from %s.plugins import %s" % (module, method_name), namespace)
            method_to_execute = namespace[method_name]
        except Exception as e:
            if not re.match(r".*cannot import name .*%s.*" % method_name, str(e)) and (
                "No module named" not in str(e)
            ):
                LOG.debug("Unable to load plugins from module %s: %s" % (module, e))
            return
        try:
            LOG.debug(
                'Loading plugins - scope "%s", module "%s": %s' % (scope, module, method_to_execute)
            )
            return method_to_execute()
        except Exception as e:
            if not os.environ.get(ENV_SCRIPT_STARTING_DOCKER):
                LOG.warning("Unable to load plugins from file %s: %s" % (file_path, e))


def should_load_module(module, scope):
    if module == "localstack_ext" and not os.environ.get("LOCALSTACK_API_KEY"):
        return False
    return True


@log_duration()
def load_plugins(scope=None):
    scope = scope or PLUGIN_SCOPE_SERVICES
    if PLUGINS_LOADED.get(scope):
        return PLUGINS_LOADED[scope]

    t1 = now_utc()
    is_infra_process = (
        os.environ.get(constants.LOCALSTACK_INFRA_PROCESS) in ["1", "true"] or "--host" in sys.argv
    )
    log_level = logging.WARNING if scope == PLUGIN_SCOPE_COMMANDS and not is_infra_process else None
    setup_logging(log_level=log_level)

    loaded_files = []
    result = []

    # Use a predefined list of plugin modules for now, to speed up the plugin loading at startup
    # search_modules = pkgutil.iter_modules()
    search_modules = PLUGIN_MODULES

    for module in search_modules:
        if not should_load_module(module, scope):
            continue
        file_path = None
        if isinstance(module, six.string_types):
            loader = pkgutil.get_loader(module)
            if loader:
                path = getattr(loader, "path", "") or getattr(loader, "filename", "")
                if "__init__.py" in path:
                    path = os.path.dirname(path)
                file_path = os.path.join(path, "plugins.py")
        elif six.PY3 and not isinstance(module, tuple):
            file_path = os.path.join(module.module_finder.path, module.name, "plugins.py")
        elif six.PY3 or isinstance(module[0], pkgutil.ImpImporter):
            if hasattr(module[0], "path"):
                file_path = os.path.join(module[0].path, module[1], "plugins.py")
        if file_path and file_path not in loaded_files:
            plugin_config = load_plugin_from_path(file_path, scope=scope)
            if plugin_config:
                result.append(plugin_config)
            loaded_files.append(file_path)
    # set global flag
    PLUGINS_LOADED[scope] = result

    # debug plugin loading time
    load_time = now_utc() - t1
    if load_time > 5:
        LOG.debug("Plugin loading took %s sec" % load_time)

    return result


def get_docker_image_details(image_name=None):
    image_name = image_name or get_docker_image_to_start()
    try:
        result = DOCKER_CLIENT.inspect_image(image_name)
    except ContainerException:
        return {}
    result = {
        "id": result["Id"].replace("sha256:", "")[:12],
        "tag": (result.get("RepoTags") or ["latest"])[0].split(":")[-1],
        "created": result["Created"].split(".")[0],
    }
    return result


def get_main_container_ip():
    container_name = get_main_container_name()
    return DOCKER_CLIENT.get_container_ip(container_name)


def get_main_container_id():
    container_name = get_main_container_name()
    try:
        return DOCKER_CLIENT.get_container_id(container_name)
    except ContainerException:
        return None


def get_main_container_name():
    global MAIN_CONTAINER_NAME_CACHED
    if MAIN_CONTAINER_NAME_CACHED is None:
        hostname = os.environ.get("HOSTNAME")
        if hostname:
            try:
                MAIN_CONTAINER_NAME_CACHED = DOCKER_CLIENT.get_container_name(hostname)
            except ContainerException:
                MAIN_CONTAINER_NAME_CACHED = config.MAIN_CONTAINER_NAME
        else:
            MAIN_CONTAINER_NAME_CACHED = config.MAIN_CONTAINER_NAME
    return MAIN_CONTAINER_NAME_CACHED


def get_server_version():
    try:
        # try to extract from existing running container
        container_name = get_main_container_name()
        version, _ = DOCKER_CLIENT.exec_in_container(
            container_name, interactive=True, command=["bin/localstack", "--version"]
        )
        version = to_str(version).strip().splitlines()[-1]
        return version
    except ContainerException:
        try:
            # try to extract by starting a new container
            img_name = get_docker_image_to_start()
            version, _ = DOCKER_CLIENT.run_container(
                img_name,
                remove=True,
                interactive=True,
                entrypoint="",
                command=["bin/localstack", "--version"],
            )
            version = to_str(version).strip().splitlines()[-1]
            return version
        except ContainerException:
            # fall back to default constant
            return constants.VERSION


def setup_logging(log_level=None):
    """Determine and set log level"""

    if PLUGINS_LOADED.get("_logging_"):
        return
    PLUGINS_LOADED["_logging_"] = True

    # log level set by DEBUG env variable
    log_level = log_level or (logging.DEBUG if config.DEBUG else logging.INFO)

    # overriding the log level if LS_LOG has been set
    if config.LS_LOG:
        log_level = str(config.LS_LOG).upper()
        if log_level.lower() in TRACE_LOG_LEVELS:
            log_level = "DEBUG"
        log_level = logging._nameToLevel[log_level]
        logging.getLogger("").setLevel(log_level)
        logging.getLogger("localstack").setLevel(log_level)

    logging.basicConfig(level=log_level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    # set up werkzeug logger

    class WerkzeugLogFilter(logging.Filter):
        def filter(self, record):
            return record.name != "werkzeug"

    root_handlers = logging.getLogger().handlers
    if len(root_handlers) > 0:
        root_handlers[0].addFilter(WerkzeugLogFilter())
        if config.DEBUG:
            format = "%(asctime)s:API: %(message)s"
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            handler.setFormatter(logging.Formatter(format))
            logging.getLogger("werkzeug").addHandler(handler)

    # disable some logs and warnings
    warnings.filterwarnings("ignore")
    logging.captureWarnings(True)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("boto3").setLevel(logging.INFO)
    logging.getLogger("botocore").setLevel(logging.ERROR)
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("elasticsearch").setLevel(logging.ERROR)
    logging.getLogger("moto").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("s3transfer").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    if config.LS_LOG != LS_LOG_TRACE_INTERNAL:
        # disable werkzeug API logs, unless detailed internal trace logging is enabled
        logging.getLogger("werkzeug").setLevel(logging.WARNING)


# --------------
# INFRA STARTUP
# --------------


def canonicalize_api_names(apis=None):
    """Finalize the list of API names by
    (1) resolving and adding dependencies (e.g., "dynamodbstreams" requires "kinesis"),
    (2) resolving and adding composites (e.g., "serverless" describes an ensemble
            including "iam", "lambda", "dynamodb", "apigateway", "s3", "sns", and "logs"), and
    (3) removing duplicates from the list."""

    # TODO: cache the result, as the code below is a relatively expensive operation!

    apis = apis or list(config.SERVICE_PORTS.keys())

    def contains(apis, api):
        for a in apis:
            if a == api:
                return True

    # TODO: enable recursive lookup - e.g., having service "amplify" depend (via API_DEPENDENCIES)
    #  on composite "serverless", which should add services "s3", "apigateway", etc...

    # resolve composites
    for comp, deps in API_COMPOSITES.items():
        if contains(apis, comp):
            apis.extend(deps)
            config.SERVICE_PORTS.pop(comp)

    # resolve dependencies
    for i, api in enumerate(apis):
        for dep in API_DEPENDENCIES.get(api, []):
            if not contains(apis, dep):
                apis.append(dep)

    # remove duplicates and composite names
    apis = list(set([a for a in apis if a not in API_COMPOSITES.keys()]))

    # make sure we have port mappings for each API
    for api in apis:
        if api not in config.SERVICE_PORTS:
            config.SERVICE_PORTS[api] = config.DEFAULT_SERVICE_PORTS.get(api)
    config.populate_configs(config.SERVICE_PORTS)

    return apis


def is_api_enabled(api):
    apis = canonicalize_api_names()
    for a in apis:
        if a == api or a.startswith("%s:" % api):
            return True


def start_infra_locally():
    from localstack.services import infra

    return infra.start_infra()


def validate_localstack_config(name):
    # TODO: separate functionality from CLI output
    #  (use exceptions to communicate errors, and return list of warnings)
    from subprocess import CalledProcessError

    from localstack.cli import console

    dirname = os.getcwd()
    compose_file_name = name if os.path.isabs(name) else os.path.join(dirname, name)
    warns = []

    # validating docker-compose file
    cmd = ["docker-compose", "-f", compose_file_name, "config"]
    try:
        run(cmd, shell=False, print_error=False)
    except CalledProcessError as e:
        msg = f"{e}\n{to_str(e.output)}".strip()
        raise ValueError(msg)

    # validating docker-compose variable
    import yaml  # keep import here to avoid issues in test Lambdas

    with open(compose_file_name) as file:
        compose_content = yaml.full_load(file)
    services_config = compose_content.get("services", {})
    ls_service_name = [
        name for name, svc in services_config.items() if "localstack" in svc.get("image", "")
    ]
    if not ls_service_name:
        raise Exception(
            'No LocalStack service found in config (looking for image names containing "localstack")'
        )
    if len(ls_service_name) > 1:
        warns.append(f"Multiple candidates found for LocalStack service: {ls_service_name}")
    ls_service_name = ls_service_name[0]
    ls_service_details = services_config[ls_service_name]
    image_name = ls_service_details.get("image", "")
    if image_name.split(":")[0] not in constants.OFFICIAL_IMAGES:
        warns.append(
            'Using custom image "%s", we recommend using an official image: %s'
            % (image_name, constants.OFFICIAL_IMAGES)
        )

    # prepare config options
    network_mode = ls_service_details.get("network_mode")
    image_name = ls_service_details.get("image")
    container_name = ls_service_details.get("container_name") or ""
    docker_ports = (port.split(":")[-2] for port in ls_service_details.get("ports", []))
    docker_env = dict(
        (env.split("=")[0], env.split("=")[1]) for env in ls_service_details.get("environment", {})
    )
    edge_port = str(docker_env.get("EDGE_PORT") or config.EDGE_PORT)
    main_container = config.MAIN_CONTAINER_NAME

    # docker-compose file validation cases

    if (
        docker_env.get("PORT_WEB_UI") not in ["${PORT_WEB_UI- }", None, ""]
        and image_name == "localstack/localstack"
    ):
        warns.append(
            '"PORT_WEB_UI" Web UI is now deprecated, '
            'and requires to use the "localstack/localstack-full" image.'
        )

    if not docker_env.get("HOST_TMP_FOLDER"):
        warns.append(
            'Please configure the "HOST_TMP_FOLDER" environment variable to point to the '
            + "absolute path of a temp folder on your host system (e.g., HOST_TMP_FOLDER=${TMPDIR})"
        )

    if (main_container not in container_name) and not docker_env.get("MAIN_CONTAINER_NAME"):
        warns.append(
            'Please use "container_name: %s" or add "MAIN_CONTAINER_NAME" in "environment".'
            % main_container
        )

    def port_exposed(port):
        for exposed in docker_ports:
            if re.match(r"^([0-9]+-)?%s(-[0-9]+)?$" % port, exposed):
                return True

    if not port_exposed(edge_port):
        warns.append(
            (
                "Edge port %s is not exposed. You may have to add the entry "
                'to the "ports" section of the docker-compose file.'
            )
            % edge_port
        )

    if network_mode != "bridge" and not docker_env.get("LAMBDA_DOCKER_NETWORK"):
        warns.append(
            'Network mode is not set to "bridge" which may cause networking issues in Lambda containers. '
            'Consider adding "network_mode: bridge" to your docker-compose file, or configure '
            "LAMBDA_DOCKER_NETWORK with the name of the Docker network of your compose stack."
        )

    # print warning/info messages
    for warning in warns:
        console.print("[yellow]:warning:[/yellow]", warning)
    if not warns:
        return True
    return False


def get_docker_image_to_start():
    image_name = os.environ.get("IMAGE_NAME")
    if not image_name:
        image_name = constants.DOCKER_IMAGE_NAME
        if os.environ.get("USE_LIGHT_IMAGE") in constants.FALSE_STRINGS:
            image_name = constants.DOCKER_IMAGE_NAME_FULL
    return image_name


def extract_port_flags(user_flags, port_mappings):
    regex = r"-p\s+([0-9]+)(\-([0-9]+))?:([0-9]+)(\-([0-9]+))?"
    matches = re.match(".*%s" % regex, user_flags)
    start = end = 0
    if matches:
        for match in re.findall(regex, user_flags):
            start = int(match[0])
            end = int(match[2] or match[0])
            start_target = int(match[3] or start)
            end_target = int(match[5] or end)
            port_mappings.add([start, end], [start_target, end_target])
        user_flags = re.sub(regex, r"", user_flags)
    return user_flags


def start_infra_in_docker():
    container_name = config.MAIN_CONTAINER_NAME

    if DOCKER_CLIENT.is_container_running(container_name):
        raise Exception('LocalStack container named "%s" is already running' % container_name)
    if config.TMP_FOLDER != config.HOST_TMP_FOLDER and not config.LAMBDA_REMOTE_DOCKER:
        print(
            f"WARNING: The detected temp folder for localstack ({config.TMP_FOLDER}) is not equal to the "
            f"HOST_TMP_FOLDER environment variable set ({config.HOST_TMP_FOLDER})."
        )  # Logger is not initialized at this point, so the warning is displayed via print

    os.environ[ENV_SCRIPT_STARTING_DOCKER] = "1"

    # load plugins before starting the docker container
    plugin_configs = load_plugins()

    # prepare APIs
    canonicalize_api_names()

    entrypoint = os.environ.get("ENTRYPOINT", "")
    cmd = os.environ.get("CMD", "")
    user_flags = config.DOCKER_FLAGS
    image_name = get_docker_image_to_start()
    service_ports = config.SERVICE_PORTS
    force_noninteractive = os.environ.get("FORCE_NONINTERACTIVE", "")

    # get run params
    plugin_run_params = " ".join(
        [entry.get("docker", {}).get("run_flags", "") for entry in plugin_configs]
    )

    # container for port mappings
    port_mappings = PortMappings(bind_host=config.EDGE_BIND_HOST)

    # get port ranges defined via DOCKER_FLAGS (if any)
    user_flags = extract_port_flags(user_flags, port_mappings)
    plugin_run_params = extract_port_flags(plugin_run_params, port_mappings)

    # construct default port mappings
    if service_ports.get("edge") == 0:
        service_ports.pop("edge")
    for port in service_ports.values():
        port_mappings.add(port)

    env_vars = {}
    for env_var in config.CONFIG_ENV_VARS:
        value = os.environ.get(env_var, None)
        if value is not None:
            env_vars[env_var] = value

    bind_mounts = []
    data_dir = os.environ.get("DATA_DIR", None)
    if data_dir is not None:
        container_data_dir = "/tmp/localstack_data"
        bind_mounts.append((data_dir, container_data_dir))
        env_vars["DATA_DIR"] = container_data_dir
    bind_mounts.append((config.TMP_FOLDER, "/tmp/localstack"))
    bind_mounts.append((config.DOCKER_SOCK, config.DOCKER_SOCK))
    env_vars["DOCKER_HOST"] = f"unix://{config.DOCKER_SOCK}"
    env_vars["HOST_TMP_FOLDER"] = config.HOST_TMP_FOLDER

    if config.DEVELOP:
        port_mappings.add(config.DEVELOP_PORT)

    docker_cmd = [config.DOCKER_CMD, "run"]
    if not force_noninteractive and not in_ci():
        docker_cmd.append("-it")
    if entrypoint:
        docker_cmd += shlex.split(entrypoint)
    if env_vars:
        docker_cmd += [item for k, v in env_vars.items() for item in ["-e", "{}={}".format(k, v)]]
    if user_flags:
        docker_cmd += shlex.split(user_flags)
    if plugin_run_params:
        docker_cmd += shlex.split(plugin_run_params)
    docker_cmd += ["--rm", "--privileged"]
    docker_cmd += ["--name", container_name]
    docker_cmd += port_mappings.to_list()
    docker_cmd += [
        volume
        for host_path, docker_path in bind_mounts
        for volume in ["-v", f"{host_path}:{docker_path}"]
    ]
    docker_cmd.append(image_name)
    docker_cmd += shlex.split(cmd)

    mkdir(config.TMP_FOLDER)
    try:
        run(["chmod", "-R", "777", config.TMP_FOLDER], print_error=False, shell=False)
    except Exception:
        pass

    class ShellRunnerThread(threading.Thread):
        def __init__(self, cmd):
            threading.Thread.__init__(self)
            self.daemon = True
            self.cmd = cmd

        def run(self):
            self.process = run(self.cmd, asynchronous=True, shell=False)

    # keep this print output here for debugging purposes
    print(docker_cmd)
    t = ShellRunnerThread(docker_cmd)
    t.start()
    time.sleep(2)

    if DO_CHMOD_DOCKER_SOCK:
        # fix permissions on /var/run/docker.sock
        for i in range(0, 100):
            if DOCKER_CLIENT.is_container_running(container_name):
                break
            time.sleep(2)
        DOCKER_CLIENT.exec_in_container(
            container_name, command=["chmod", "777", "/var/run/docker.sock"], user="root"
        )

    t.process.wait()
    sys.exit(t.process.returncode)


# ---------------
# UTIL FUNCTIONS
# ---------------


def now_utc():
    epoch = datetime.utcfromtimestamp(0)
    return (datetime.utcnow() - epoch).total_seconds()


def in_ci():
    """Whether or not we are running in a CI environment"""
    for key in ("CI", "TRAVIS"):
        if os.environ.get(key, "") not in [False, "", "0", "false"]:
            return True
    return False


def mkdir(folder):
    if not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except OSError as err:
            # Ignore rare 'File exists' race conditions.
            if err.errno != 17:
                raise
