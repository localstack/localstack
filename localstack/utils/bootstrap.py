import os
import re
import sys
import json
import time
import select
import pkgutil
import logging
import warnings
import threading
import traceback
import subprocess
import six
import shutil
import pip as pip_mod
from datetime import datetime
from concurrent.futures._base import Future
from localstack import constants, config
from localstack.utils.analytics.profiler import log_duration

# set up logger
LOG = logging.getLogger(os.path.basename(__file__))

# maps plugin scope ("services", "commands") to flags which indicate whether plugins have been loaded
PLUGINS_LOADED = {}

# predefined list of plugin modules, to speed up the plugin loading at startup
# note: make sure to load localstack_ext before localstack
PLUGIN_MODULES = ['localstack_ext', 'localstack']

# marker for extended/ignored libs in requirements.txt
IGNORED_LIB_MARKER = '#extended-lib'
BASIC_LIB_MARKER = '#basic-lib'

# whether or not to manually fix permissions on /var/run/docker.sock (currently disabled)
DO_CHMOD_DOCKER_SOCK = False

# log format strings
LOG_FORMAT = '%(asctime)s:%(levelname)s:%(name)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'

# plugin scopes
PLUGIN_SCOPE_SERVICES = 'services'
PLUGIN_SCOPE_COMMANDS = 'commands'

# maps from API names to list of other API names that they depend on
API_DEPENDENCIES = {
    'dynamodb': ['dynamodbstreams'],
    'dynamodbstreams': ['kinesis'],
    'es': ['elasticsearch'],
    'lambda': ['logs', 'cloudwatch'],
    'kinesis': ['dynamodb'],
    'firehose': ['kinesis']
}
# composites define an abstract name like "serverless" that maps to a set of services
API_COMPOSITES = {
    'serverless': ['cloudformation', 'cloudwatch', 'iam', 'sts', 'lambda', 'dynamodb', 'apigateway', 's3'],
    'cognito': ['cognito-idp', 'cognito-identity']
}

# environment variable that indicates that we're executing in
# the context of the script that starts the Docker container
ENV_SCRIPT_STARTING_DOCKER = 'LS_SCRIPT_STARTING_DOCKER'


def bootstrap_installation():
    try:
        from localstack.services import infra
        assert infra
    except Exception:
        install_dependencies()


def install_dependencies():
    # determine requirements
    root_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')
    reqs_file = os.path.join(root_folder, 'requirements.txt')
    reqs_copy_file = os.path.join(root_folder, 'localstack', 'requirements.copy.txt')
    if not os.path.exists(reqs_copy_file):
        shutil.copy(reqs_file, reqs_copy_file)
    with open(reqs_copy_file) as f:
        requirements = f.read()
    install_requires = []
    for line in re.split('\n', requirements):
        if line and line[0] != '#':
            if BASIC_LIB_MARKER not in line and IGNORED_LIB_MARKER not in line:
                line = line.split(' #')[0].strip()
                install_requires.append(line)
    LOG.info('Lazily installing missing pip dependencies, this could take a while: %s' %
             ', '.join(install_requires))
    args = ['install'] + install_requires
    return run_pip_main(args)


def run_pip_main(args):
    if hasattr(pip_mod, 'main'):
        return pip_mod.main(args)
    import pip._internal
    if hasattr(pip._internal, 'main'):
        return pip._internal.main(args)
    import pip._internal.main
    return pip._internal.main.main(args)


@log_duration()
def load_plugin_from_path(file_path, scope=None):
    if os.path.exists(file_path):
        module = re.sub(r'(^|.+/)([^/]+)/plugins.py', r'\2', file_path)
        method_name = 'register_localstack_plugins'
        scope = scope or PLUGIN_SCOPE_SERVICES
        if scope == PLUGIN_SCOPE_COMMANDS:
            method_name = 'register_localstack_commands'
        try:
            namespace = {}
            exec('from %s.plugins import %s' % (module, method_name), namespace)
            method_to_execute = namespace[method_name]
        except Exception as e:
            if (not re.match(r'.*cannot import name .*%s.*' % method_name, str(e)) and
                    ('No module named' not in str(e))):
                LOG.debug('Unable to load plugins from module %s: %s' % (module, e))
            return
        try:
            LOG.debug('Loading plugins - scope "%s", module "%s": %s' % (scope, module, method_to_execute))
            return method_to_execute()
        except Exception as e:
            if not os.environ.get(ENV_SCRIPT_STARTING_DOCKER):
                LOG.warning('Unable to load plugins from file %s: %s' % (file_path, e))


def should_load_module(module, scope):
    if module == 'localstack_ext' and not os.environ.get('LOCALSTACK_API_KEY'):
        return False
    return True


@log_duration()
def load_plugins(scope=None):
    scope = scope or PLUGIN_SCOPE_SERVICES
    if PLUGINS_LOADED.get(scope):
        return PLUGINS_LOADED[scope]

    t1 = now_utc()
    is_infra_process = os.environ.get(constants.LOCALSTACK_INFRA_PROCESS) in ['1', 'true'] or '--host' in sys.argv
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
                path = getattr(loader, 'path', '') or getattr(loader, 'filename', '')
                if '__init__.py' in path:
                    path = os.path.dirname(path)
                file_path = os.path.join(path, 'plugins.py')
        elif six.PY3 and not isinstance(module, tuple):
            file_path = os.path.join(module.module_finder.path, module.name, 'plugins.py')
        elif six.PY3 or isinstance(module[0], pkgutil.ImpImporter):
            if hasattr(module[0], 'path'):
                file_path = os.path.join(module[0].path, module[1], 'plugins.py')
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
        LOG.debug('Plugin loading took %s sec' % load_time)

    return result


def docker_container_running(container_name):
    container_names = get_docker_container_names()
    return container_name in container_names


def get_docker_image_details(image_name=None):
    image_name = image_name or get_docker_image_to_start()
    try:
        result = run('%s inspect %s' % (config.DOCKER_CMD, image_name), print_error=False)
        result = json.loads(to_str(result))
        assert len(result)
    except Exception:
        return {}
    if len(result) > 1:
        LOG.warning('Found multiple images (%s) named "%s"' % (len(result), image_name))
    result = result[0]
    result = {
        'id': result['Id'].replace('sha256:', '')[:12],
        'tag': (result.get('RepoTags') or ['latest'])[0].split(':')[-1],
        'created': result['Created'].split('.')[0]
    }
    return result


def get_docker_container_names():
    cmd = "%s ps --format '{{.Names}}'" % config.DOCKER_CMD
    try:
        output = to_str(run(cmd))
        container_names = re.split(r'\s+', output.strip().replace('\n', ' '))
        return container_names
    except Exception as e:
        LOG.info('Unable to list Docker containers via "%s": %s' % (cmd, e))
        return []


def get_main_container_ip():
    container_name = get_main_container_name()
    cmd = ("%s inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s" %
        (config.DOCKER_CMD, container_name))
    return run(cmd).strip()


def get_main_container_name():
    cmd = "%s inspect -f '{{ .Name }}' %s" % (config.DOCKER_CMD, config.HOSTNAME)
    try:
        return run(cmd, print_error=False).strip().lstrip('/')
    except Exception:
        return config.MAIN_CONTAINER_NAME


def get_server_version():
    docker_cmd = config.DOCKER_CMD
    try:
        # try to extract from existing running container
        container_name = get_main_container_name()
        version = run('%s exec -it %s bin/localstack --version' % (docker_cmd, container_name), print_error=False)
        version = version.strip().split('\n')[-1]
        return version
    except Exception:
        try:
            # try to extract by starting a new container
            img_name = get_docker_image_to_start()
            version = run('%s run --entrypoint= -it %s bin/localstack --version' % (docker_cmd, img_name))
            version = version.strip().split('\n')[-1]
            return version
        except Exception:
            # fall back to default constant
            return constants.VERSION


def setup_logging(log_level=None):
    """ Determine and set log level """

    if PLUGINS_LOADED.get('_logging_'):
        return
    PLUGINS_LOADED['_logging_'] = True

    log_level = log_level or (logging.DEBUG if is_debug() else logging.INFO)
    logging.basicConfig(level=log_level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    # set up werkzeug logger

    class WerkzeugLogFilter(logging.Filter):
        def filter(self, record):
            return record.name != 'werkzeug'

    root_handlers = logging.getLogger().handlers
    if len(root_handlers) > 0:
        root_handlers[0].addFilter(WerkzeugLogFilter())
        if is_debug():
            format = '%(asctime)s:API: %(message)s'
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            handler.setFormatter(logging.Formatter(format))
            logging.getLogger('werkzeug').addHandler(handler)

    # disable some logs and warnings
    warnings.filterwarnings('ignore')
    logging.captureWarnings(True)
    logging.getLogger('asyncio').setLevel(logging.INFO)
    logging.getLogger('boto3').setLevel(logging.INFO)
    logging.getLogger('s3transfer').setLevel(logging.INFO)
    logging.getLogger('docker').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('elasticsearch').setLevel(logging.ERROR)


# --------------
# INFRA STARTUP
# --------------


def canonicalize_api_names(apis=None):
    """ Finalize the list of API names by
        (1) resolving and adding dependencies (e.g., "dynamodbstreams" requires "kinesis"),
        (2) resolving and adding composites (e.g., "serverless" describes an ensemble
                including "iam", "lambda", "dynamodb", "apigateway", "s3", "sns", and "logs"), and
        (3) removing duplicates from the list. """

    apis = apis or list(config.SERVICE_PORTS.keys())

    def contains(apis, api):
        for a in apis:
            if a == api:
                return True

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
        if a == api or a.startswith('%s:' % api):
            return True


def start_infra_locally():
    bootstrap_installation()
    from localstack.services import infra
    return infra.start_infra()


class PortMappings(object):
    """ Maps source to target port ranges for Docker port mappings. """

    class HashableList(list):
        def __hash__(self):
            result = 0
            for i in self:
                result += hash(i)
            return result

    def __init__(self):
        self.mappings = {}

    def add(self, port, mapped=None):
        mapped = mapped or port
        if isinstance(port, list):
            for i in range(port[1] - port[0] + 1):
                self.add(port[0] + i, mapped[0] + i)
            return
        if port is None or int(port) <= 0:
            raise Exception('Unable to add mapping for invalid port: %s' % port)
        if self.contains(port):
            return
        for from_range, to_range in self.mappings.items():
            if not self.in_expanded_range(port, from_range):
                continue
            if not self.in_expanded_range(mapped, to_range):
                continue
            self.expand_range(port, from_range)
            self.expand_range(mapped, to_range)
            return
        self.mappings[self.HashableList([port, port])] = [mapped, mapped]

    def to_str(self):
        def entry(k, v):
            if k[0] == k[1] and v[0] == v[1]:
                return '-p %s:%s' % (k[0], v[0])
            return '-p %s-%s:%s-%s' % (k[0], k[1], v[0], v[1])

        return ' '.join([entry(k, v) for k, v in self.mappings.items()])

    def contains(self, port):
        for from_range, to_range in self.mappings.items():
            if self.in_range(port, from_range):
                return True

    def in_range(self, port, range):
        return port >= range[0] and port <= range[1]

    def in_expanded_range(self, port, range):
        return port >= range[0] - 1 and port <= range[1] + 1

    def expand_range(self, port, range):
        if self.in_range(port, range):
            return
        if port == range[0] - 1:
            range[0] = port
        elif port == range[1] + 1:
            range[1] = port
        else:
            raise Exception('Unable to add port %s to existing range %s' % (port, range))


def get_docker_image_to_start():
    image_name = os.environ.get('IMAGE_NAME')
    if not image_name:
        image_name = constants.DOCKER_IMAGE_NAME
        if os.environ.get('USE_LIGHT_IMAGE') in constants.FALSE_STRINGS:
            image_name = constants.DOCKER_IMAGE_NAME_FULL
    return image_name


def extract_port_flags(user_flags, port_mappings):
    regex = r'-p\s+([0-9]+)(\-([0-9]+))?:([0-9]+)(\-([0-9]+))?'
    matches = re.match('.*%s' % regex, user_flags)
    start = end = 0
    if matches:
        for match in re.findall(regex, user_flags):
            start = int(match[0])
            end = int(match[2] or match[0])
            start_target = int(match[3] or start)
            end_target = int(match[5] or end)
            port_mappings.add([start, end], [start_target, end_target])
        user_flags = re.sub(regex, r'', user_flags)
    return user_flags


def start_infra_in_docker():

    container_name = config.MAIN_CONTAINER_NAME

    if docker_container_running(container_name):
        raise Exception('LocalStack container named "%s" is already running' % container_name)

    os.environ[ENV_SCRIPT_STARTING_DOCKER] = '1'

    # load plugins before starting the docker container
    plugin_configs = load_plugins()

    # prepare APIs
    canonicalize_api_names()

    entrypoint = os.environ.get('ENTRYPOINT', '')
    cmd = os.environ.get('CMD', '')
    user_flags = config.DOCKER_FLAGS
    image_name = get_docker_image_to_start()
    service_ports = config.SERVICE_PORTS
    force_noninteractive = os.environ.get('FORCE_NONINTERACTIVE', '')

    # get run params
    plugin_run_params = ' '.join([
        entry.get('docker', {}).get('run_flags', '') for entry in plugin_configs])

    # container for port mappings
    port_mappings = PortMappings()

    # get port ranges defined via DOCKER_FLAGS (if any)
    user_flags = extract_port_flags(user_flags, port_mappings)
    plugin_run_params = extract_port_flags(plugin_run_params, port_mappings)

    # construct default port mappings
    if service_ports.get('edge') == 0:
        service_ports.pop('edge')
    service_ports.pop('dashboard', None)
    for port in service_ports.values():
        port_mappings.add(port)

    env_str = ''
    for env_var in config.CONFIG_ENV_VARS:
        value = os.environ.get(env_var, None)
        if value is not None:
            env_str += '-e %s="%s" ' % (env_var, value)

    data_dir_mount = ''
    data_dir = os.environ.get('DATA_DIR', None)
    if data_dir is not None:
        container_data_dir = '/tmp/localstack_data'
        data_dir_mount = '-v "%s:%s"' % (data_dir, container_data_dir)
        env_str += '-e DATA_DIR="%s" ' % container_data_dir

    interactive = '' if force_noninteractive or in_ci() else '-it '

    # append space if parameter is set
    user_flags = '%s ' % user_flags if user_flags else user_flags
    entrypoint = '%s ' % entrypoint if entrypoint else entrypoint
    plugin_run_params = '%s ' % plugin_run_params if plugin_run_params else plugin_run_params
    if config.START_WEB:
        for port in [config.PORT_WEB_UI, config.PORT_WEB_UI_SSL]:
            port_mappings.add(port)

    docker_cmd = ('%s run %s%s%s%s%s' +
        '--rm --privileged ' +
        '--name %s ' +
        '%s %s ' +
        '-v "%s:/tmp/localstack" -v "%s:%s" ' +
        '-e DOCKER_HOST="unix://%s" ' +
        '-e HOST_TMP_FOLDER="%s" "%s" %s') % (
            config.DOCKER_CMD, interactive, entrypoint, env_str, user_flags, plugin_run_params,
            container_name, port_mappings.to_str(), data_dir_mount,
            config.TMP_FOLDER, config.DOCKER_SOCK, config.DOCKER_SOCK, config.DOCKER_SOCK,
            config.HOST_TMP_FOLDER, image_name, cmd
    )

    mkdir(config.TMP_FOLDER)
    try:
        run('chmod -R 777 "%s"' % config.TMP_FOLDER)
    except Exception:
        pass

    class ShellRunnerThread(threading.Thread):
        def __init__(self, cmd):
            threading.Thread.__init__(self)
            self.daemon = True
            self.cmd = cmd

        def run(self):
            self.process = run(self.cmd, asynchronous=True)

    print(docker_cmd)
    t = ShellRunnerThread(docker_cmd)
    t.start()
    time.sleep(2)

    if DO_CHMOD_DOCKER_SOCK:
        # fix permissions on /var/run/docker.sock
        for i in range(0, 100):
            if docker_container_running(container_name):
                break
            time.sleep(2)
        run('%s exec -u root "%s" chmod 777 /var/run/docker.sock' % (config.DOCKER_CMD, container_name))

    t.process.wait()
    sys.exit(t.process.returncode)


# ---------------
# UTIL FUNCTIONS
# ---------------

def now_utc():
    epoch = datetime.utcfromtimestamp(0)
    return (datetime.utcnow() - epoch).total_seconds()


def to_str(obj, errors='strict'):
    return obj.decode('utf-8', errors) if isinstance(obj, six.binary_type) else obj


def in_ci():
    """ Whether or not we are running in a CI environment """
    for key in ('CI', 'TRAVIS'):
        if os.environ.get(key, '') not in [False, '', '0', 'false']:
            return True
    return False


class FuncThread(threading.Thread):
    """ Helper class to run a Python function in a background thread. """

    def __init__(self, func, params=None, quiet=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self.params = params
        self.func = func
        self.quiet = quiet
        self.result_future = Future()

    def run(self):
        result = None
        try:
            result = self.func(self.params)
        except Exception as e:
            result = e
            if not self.quiet:
                LOG.warning('Thread run method %s(%s) failed: %s %s' %
                    (self.func, self.params, e, traceback.format_exc()))
        finally:
            try:
                self.result_future.set_result(result)
            except Exception:
                # this can happen as InvalidStateError on shutdown, if the task is already canceled
                pass

    def stop(self, quiet=False):
        if not quiet and not self.quiet:
            LOG.warning('Not implemented: FuncThread.stop(..)')


def run(cmd, print_error=True, asynchronous=False, stdin=False, stderr=subprocess.STDOUT,
        outfile=None, env_vars=None, inherit_cwd=False, inherit_env=True, tty=False):
    env_dict = os.environ.copy() if inherit_env else {}
    if env_vars:
        env_dict.update(env_vars)
    env_dict = dict([(k, to_str(str(v))) for k, v in env_dict.items()])

    if tty:
        asynchronous = True
        stdin = True

    try:
        cwd = os.getcwd() if inherit_cwd else None
        if not asynchronous:
            if stdin:
                return subprocess.check_output(cmd, shell=True, stderr=stderr, env=env_dict,
                    stdin=subprocess.PIPE, cwd=cwd)
            output = subprocess.check_output(cmd, shell=True, stderr=stderr, env=env_dict, cwd=cwd)
            return output.decode(config.DEFAULT_ENCODING)

        stdin_arg = subprocess.PIPE if stdin else None
        stdout_arg = open(outfile, 'ab') if isinstance(outfile, six.string_types) else outfile
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
            kwargs['preexec_fn'] = os.setsid
        process = subprocess.Popen(cmd, shell=True, stdin=stdin_arg, bufsize=-1,
            stderr=stderr_arg, stdout=stdout_arg, env=env_dict, cwd=cwd, **kwargs)

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


def is_mac_os():
    return 'Darwin' in get_uname()


def is_linux():
    return 'Linux' in get_uname()


def get_uname():
    try:
        return to_str(subprocess.check_output('uname -a', shell=True))
    except Exception:
        return ''


def mkdir(folder):
    if not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except OSError as err:
            # Ignore rare 'File exists' race conditions.
            if err.errno != 17:
                raise


def is_debug():
    return os.environ.get('DEBUG', '').strip() not in ['', '0', 'false']
