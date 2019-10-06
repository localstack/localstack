import os
import re
import sys
import time
import select
import pkgutil
import logging
import warnings
import threading
import traceback
import pip as pip_mod
import shutil
try:
    import subprocess32 as subprocess
except Exception:
    import subprocess
import six
from localstack import constants, config

# set up logger
LOG = logging.getLogger(os.path.basename(__file__))

# maps plugin scope ("services", "commands") to flags which indicate whether plugins have been loaded
PLUGINS_LOADED = {}

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
    'dynamodbstreams': ['kinesis'],
    'lambda': ['logs'],
    'es': ['elasticsearch']
}
# composites define an abstract name like "serverless" that maps to a set of services
API_COMPOSITES = {
    'serverless': ['cloudformation', 'iam', 'sts', 'lambda', 'dynamodb', 'apigateway', 's3'],
    'cognito': ['cognito-idp', 'cognito-identity']
}

# name of main Docker container
MAIN_CONTAINER_NAME = 'localstack_main'

mutex_popen = threading.Semaphore(1)


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
    if hasattr(pip_mod, 'main'):
        pip_mod.main(args)
    else:
        import pip._internal
        pip._internal.main(args)


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
            if not re.match(r'.*cannot import name .*%s.*' % method_name, str(e)):
                LOG.debug('Unable to load plugins from module %s: %s' % (module, e))
            return
        try:
            return method_to_execute()
        except Exception as e:
            LOG.warning('Unable to load plugins from file %s: %s' % (file_path, e))


def load_plugins(scope=None):
    scope = scope or PLUGIN_SCOPE_SERVICES
    if PLUGINS_LOADED.get(scope):
        return PLUGINS_LOADED[scope]

    setup_logging()

    loaded_files = []
    result = []
    for module in pkgutil.iter_modules():
        file_path = None
        if six.PY3 and not isinstance(module, tuple):
            file_path = '%s/%s/plugins.py' % (module.module_finder.path, module.name)
        elif six.PY3 or isinstance(module[0], pkgutil.ImpImporter):
            if hasattr(module[0], 'path'):
                file_path = '%s/%s/plugins.py' % (module[0].path, module[1])
        if file_path and file_path not in loaded_files:
            plugin_config = load_plugin_from_path(file_path, scope=scope)
            if plugin_config:
                result.append(plugin_config)
            loaded_files.append(file_path)
    # set global flag
    PLUGINS_LOADED[scope] = result
    return result


def docker_container_running(container_name):
    output = to_str(run("docker ps --format '{{.Names}}'"))
    container_names = re.split(r'\s+', output.replace('\n', ' '))
    return container_name in container_names


def setup_logging():
    # determine and set log level
    log_level = logging.DEBUG if is_debug() else logging.INFO
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


def start_infra_in_docker():

    container_name = MAIN_CONTAINER_NAME

    if docker_container_running(container_name):
        raise Exception('LocalStack container named "%s" is already running' % container_name)

    # load plugins before starting the docker container
    plugin_configs = load_plugins()

    # prepare APIs
    canonicalize_api_names()

    services = os.environ.get('SERVICES', '')
    entrypoint = os.environ.get('ENTRYPOINT', '')
    cmd = os.environ.get('CMD', '')
    user_flags = config.DOCKER_FLAGS
    image_name = os.environ.get('IMAGE_NAME', constants.DOCKER_IMAGE_NAME)
    service_ports = config.SERVICE_PORTS
    force_noninteractive = os.environ.get('FORCE_NONINTERACTIVE', '')

    # get run params
    plugin_run_params = ' '.join([
        entry.get('docker', {}).get('run_flags', '') for entry in plugin_configs])

    # get port ranges defined via DOCKER_FLAGS (if any)
    regex = r'.*-p\s+([0-9]+)(\-([0-9]+))?:([0-9]+)(\-[0-9]+)?.*'
    match = re.match(regex, user_flags)
    start = end = 0
    if match:
        start = int(match.group(1))
        end = int(match.group(3) or match.group(1))

    def is_mapped(start_port, end_port=None):
        existing_range = range(start, end)
        return (int(start_port) in existing_range) or (start_port and int(start_port) in existing_range)

    # construct port mappings
    ports_list = sorted(service_ports.values())
    start_port = 0
    last_port = 0
    port_ranges = []
    for i in range(0, len(ports_list)):
        if not start_port:
            start_port = ports_list[i]
        if not last_port:
            last_port = ports_list[i]
        if ports_list[i] > last_port + 1:
            port_ranges.append([start_port, last_port])
            start_port = ports_list[i]
        elif i >= len(ports_list) - 1:
            port_ranges.append([start_port, ports_list[i]])
        last_port = ports_list[i]
    port_mappings = ' '.join([
        '-p {start}-{end}:{start}-{end}'.format(start=entry[0], end=entry[1])
        if entry[0] < entry[1] else '-p {port}:{port}'.format(port=entry[0])
        for entry in port_ranges if not is_mapped(entry[0], entry[1])])

    if services:
        port_mappings = ''
        for port in set(service_ports.values()):
            if not is_mapped(port):
                port_mappings += ' -p {port}:{port}'.format(port=port)

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
    web_ui_flags = ''
    if config.START_WEB:
        web_ui_flags = '-p {p}:{p} -p {p1}:{p1} '.format(p=config.PORT_WEB_UI, p1=config.PORT_WEB_UI_SSL)

    docker_cmd = ('%s run %s%s%s%s%s' +
        '--rm --privileged ' +
        '--name %s ' +
        '%s %s %s ' +
        '-v "%s:/tmp/localstack" -v "%s:%s" ' +
        '-e DOCKER_HOST="unix://%s" ' +
        '-e HOST_TMP_FOLDER="%s" "%s" %s') % (
            config.DOCKER_CMD, interactive, entrypoint, env_str, user_flags, plugin_run_params,
            container_name, web_ui_flags, port_mappings, data_dir_mount,
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

    def run(self):
        try:
            self.func(self.params)
        except Exception:
            if not self.quiet:
                LOG.warning('Thread run method %s(%s) failed: %s' %
                    (self.func, self.params, traceback.format_exc()))

    def stop(self, quiet=False):
        if not quiet and not self.quiet:
            LOG.warning('Not implemented: FuncThread.stop(..)')


def run(cmd, print_error=True, asynchronous=False, stdin=False,
        stderr=subprocess.STDOUT, outfile=None, env_vars=None, inherit_cwd=False,
        inherit_env=True, tty=False):
    # don't use subprocess module inn Python 2 as it is not thread-safe
    # http://stackoverflow.com/questions/21194380/is-subprocess-popen-not-thread-safe
    if six.PY2:
        import subprocess32 as subprocess
    else:
        import subprocess

    env_dict = os.environ.copy() if inherit_env else {}
    if env_vars:
        env_dict.update(env_vars)

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

        # subprocess.Popen is not thread-safe, hence use a mutex here.. (TODO: mutex still needed?)
        with mutex_popen:
            stdin_arg = subprocess.PIPE if stdin else None
            stdout_arg = open(outfile, 'wb') if isinstance(outfile, six.string_types) else outfile
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
    try:
        out = to_str(subprocess.check_output('uname -a', shell=True))
        return 'Darwin' in out
    except subprocess.CalledProcessError:
        return False


def is_linux():
    try:
        out = to_str(subprocess.check_output('uname -a', shell=True))
        return 'Linux' in out
    except subprocess.CalledProcessError:
        return False


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
