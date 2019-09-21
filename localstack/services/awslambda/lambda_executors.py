import os
import re
import json
import time
import logging
import threading
import subprocess
from multiprocessing import Process, Queue
try:
    from shlex import quote as cmd_quote
except ImportError:
    # for Python 2.7
    from pipes import quote as cmd_quote
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    CaptureOutput, FuncThread, TMP_FILES, short_uid, save_file,
    to_str, run, cp_r, json_safe, get_free_tcp_port)
from localstack.services.install import INSTALL_PATH_LOCALSTACK_FAT_JAR

# constants
LAMBDA_EXECUTOR_JAR = INSTALL_PATH_LOCALSTACK_FAT_JAR
LAMBDA_EXECUTOR_CLASS = 'cloud.localstack.LambdaExecutor'
EVENT_FILE_PATTERN = '%s/lambda.event.*.json' % config.TMP_FOLDER

LAMBDA_RUNTIME_PYTHON27 = 'python2.7'
LAMBDA_RUNTIME_PYTHON36 = 'python3.6'
LAMBDA_RUNTIME_NODEJS = 'nodejs'
LAMBDA_RUNTIME_NODEJS610 = 'nodejs6.10'
LAMBDA_RUNTIME_NODEJS810 = 'nodejs8.10'
LAMBDA_RUNTIME_NODEJS10X = 'nodejs10.x'
LAMBDA_RUNTIME_JAVA8 = 'java8'
LAMBDA_RUNTIME_DOTNETCORE2 = 'dotnetcore2.0'
LAMBDA_RUNTIME_DOTNETCORE21 = 'dotnetcore2.1'
LAMBDA_RUNTIME_GOLANG = 'go1.x'
LAMBDA_RUNTIME_RUBY = 'ruby'
LAMBDA_RUNTIME_RUBY25 = 'ruby2.5'
LAMBDA_RUNTIME_CUSTOM_RUNTIME = 'provided'

LAMBDA_EVENT_FILE = 'event_file.json'

LAMBDA_SERVER_UNIQUE_PORTS = 500
LAMBDA_SERVER_PORT_OFFSET = 5000

# logger
LOG = logging.getLogger(__name__)

# maximum time a pre-allocated container can sit idle before getting killed
MAX_CONTAINER_IDLE_TIME_MS = 600 * 1000


class LambdaExecutor(object):
    """ Base class for Lambda executors. Subclasses must overwrite the _execute method """

    def __init__(self):
        # keeps track of each function arn and the last time it was invoked
        self.function_invoke_times = {}

    def execute(self, func_arn, func_details, event, context=None, version=None, asynchronous=False):

        def do_execute(*args):
            # set the invocation time in milliseconds
            invocation_time = int(time.time() * 1000)
            # start the execution
            try:
                result, log_output = self._execute(func_arn, func_details, event, context, version)
            finally:
                self.function_invoke_times[func_arn] = invocation_time
            # forward log output to cloudwatch logs
            self._store_logs(func_details, log_output, invocation_time)
            # return final result
            return result, log_output

        # Inform users about asynchronous mode of the lambda execution.
        if asynchronous:
            LOG.debug('Lambda executed in Event (asynchronous) mode, no response from this '
                      'function will be returned to caller')
            FuncThread(do_execute).start()
            return None, 'Lambda executed asynchronously.'

        return do_execute()

    def _execute(self, func_arn, func_details, event, context=None, version=None):
        """ This method must be overwritten by subclasses. """
        raise Exception('Not implemented.')

    def startup(self):
        pass

    def cleanup(self, arn=None):
        pass

    def _store_logs(self, func_details, log_output, invocation_time):
        if not aws_stack.is_service_enabled('logs'):
            return
        logs_client = aws_stack.connect_to_service('logs')
        log_group_name = '/aws/lambda/%s' % func_details.name()
        time_str = time.strftime('%Y/%m/%d', time.gmtime(invocation_time))
        log_stream_name = '%s/[$LATEST]%s' % (time_str, short_uid())

        # make sure that the log group exists
        log_groups = logs_client.describe_log_groups()['logGroups']
        log_groups = [lg['logGroupName'] for lg in log_groups]
        if log_group_name not in log_groups:
            logs_client.create_log_group(logGroupName=log_group_name)

        # create a new log stream for this lambda invocation
        logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

        # store new log events under the log stream
        invocation_time = invocation_time
        finish_time = int(time.time() * 1000)
        log_lines = log_output.split('\n')
        time_diff_per_line = float(finish_time - invocation_time) / float(len(log_lines))
        log_events = []
        for i, line in enumerate(log_lines):
            if not line:
                continue
            # simple heuristic: assume log lines were emitted in regular intervals
            log_time = invocation_time + float(i) * time_diff_per_line
            event = {'timestamp': int(log_time), 'message': line}
            log_events.append(event)
        if not log_events:
            return
        logs_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=log_events
        )

    def run_lambda_executor(self, cmd, event=None, env_vars={}):
        process = run(cmd, asynchronous=True, stderr=subprocess.PIPE, outfile=subprocess.PIPE, env_vars=env_vars,
                      stdin=True)
        result, log_output = process.communicate(input=event)
        result = to_str(result).strip()
        log_output = to_str(log_output).strip()
        return_code = process.returncode
        # Note: The user's code may have been logging to stderr, in which case the logs
        # will be part of the "result" variable here. Hence, make sure that we extract
        # only the *last* line of "result" and consider anything above that as log output.
        if '\n' in result:
            additional_logs, _, result = result.rpartition('\n')
            log_output += '\n%s' % additional_logs

        if return_code != 0:
            raise Exception('Lambda process returned error status code: %s. Output:\n%s' %
                (return_code, log_output))

        return result, log_output


class ContainerInfo:
    """
    Contains basic information about a docker container.
    """
    def __init__(self, name, entry_point):
        self.name = name
        self.entry_point = entry_point


class LambdaExecutorContainers(LambdaExecutor):
    """ Abstract executor class for executing Lambda functions in Docker containers """

    def prepare_execution(self, func_arn, env_vars, runtime, command, handler, lambda_cwd):
        raise Exception('Not implemented')

    def _docker_cmd(self):
        """ Return the string to be used for running Docker commands. """
        return config.DOCKER_CMD

    def prepare_event(self, environment, event_body):
        """ Return the event as a stdin string. """
        # amend the environment variables for execution
        environment['AWS_LAMBDA_EVENT_BODY'] = event_body
        return None

    def _execute(self, func_arn, func_details, event, context=None, version=None):

        lambda_cwd = func_details.cwd
        runtime = func_details.runtime
        handler = func_details.handler
        environment = func_details.envvars.copy()

        # configure USE_SSL in environment
        if config.USE_SSL:
            environment['USE_SSL'] = '1'

        # prepare event body
        if not event:
            LOG.warning('Empty event body specified for invocation of Lambda "%s"' % func_arn)
            event = {}
        event_body = json.dumps(json_safe(event))
        stdin = self.prepare_event(environment, event_body)

        docker_host = config.DOCKER_HOST_FROM_CONTAINER

        environment['HOSTNAME'] = docker_host
        environment['LOCALSTACK_HOSTNAME'] = docker_host
        if context:
            environment['AWS_LAMBDA_FUNCTION_NAME'] = context.function_name
            environment['AWS_LAMBDA_FUNCTION_VERSION'] = context.function_version
            environment['AWS_LAMBDA_FUNCTION_INVOKED_ARN'] = context.invoked_function_arn

        # custom command to execute in the container
        command = ''

        # if running a Java Lambda, set up classpath arguments
        if runtime == LAMBDA_RUNTIME_JAVA8:
            java_opts = Util.get_java_opts()
            stdin = None
            # copy executor jar into temp directory
            target_file = os.path.join(lambda_cwd, os.path.basename(LAMBDA_EXECUTOR_JAR))
            if not os.path.exists(target_file):
                cp_r(LAMBDA_EXECUTOR_JAR, target_file)
            # TODO cleanup once we have custom Java Docker image
            taskdir = '/var/task'
            save_file(os.path.join(lambda_cwd, LAMBDA_EVENT_FILE), event_body)
            command = ("bash -c 'cd %s; java %s -cp \".:`ls *.jar | tr \"\\n\" \":\"`\" \"%s\" \"%s\" \"%s\"'" %
                (taskdir, java_opts, LAMBDA_EXECUTOR_CLASS, handler, LAMBDA_EVENT_FILE))

        # determine the command to be executed (implemented by subclasses)
        cmd = self.prepare_execution(func_arn, environment, runtime, command, handler, lambda_cwd)

        # lambci writes the Lambda result to stdout and logs to stderr, fetch it from there!
        LOG.debug('Running lambda cmd: %s' % cmd)
        result, log_output = self.run_lambda_executor(cmd, stdin, environment)
        log_formatted = log_output.strip().replace('\n', '\n> ')
        LOG.debug('Lambda %s result / log output:\n%s\n>%s' % (func_arn, result.strip(), log_formatted))
        return result, log_output


class LambdaExecutorReuseContainers(LambdaExecutorContainers):
    """ Executor class for executing Lambda functions in re-usable Docker containers """

    def __init__(self):
        super(LambdaExecutorReuseContainers, self).__init__()
        # locking thread for creation/destruction of docker containers.
        self.docker_container_lock = threading.RLock()

        # On each invocation we try to construct a port unlikely to conflict
        # with a previously invoked lambda function. This is a problem with at
        # least the lambci/lambda:go1.x container, which execs a go program that
        # attempts to bind to the same default port.
        self.next_port = 0
        self.max_port = LAMBDA_SERVER_UNIQUE_PORTS
        self.port_offset = LAMBDA_SERVER_PORT_OFFSET

    def prepare_execution(self, func_arn, env_vars, runtime, command, handler, lambda_cwd):

        # check whether the Lambda has been invoked before
        has_been_invoked_before = func_arn in self.function_invoke_times

        # Choose a port for this invocation
        with self.docker_container_lock:
            env_vars['_LAMBDA_SERVER_PORT'] = str(self.next_port + self.port_offset)
            self.next_port = (self.next_port + 1) % self.max_port

        # create/verify the docker container is running.
        LOG.debug('Priming docker container with runtime "%s" and arn "%s".', runtime, func_arn)
        container_info = self.prime_docker_container(runtime, func_arn, env_vars.items(), lambda_cwd)

        # Note: currently "docker exec" does not support --env-file, i.e., environment variables can only be
        # passed directly on the command line, using "-e" below. TODO: Update this code once --env-file is
        # available for docker exec, to better support very large Lambda events (very long environment values)
        exec_env_vars = ' '.join(['-e {}="${}"'.format(k, k) for (k, v) in env_vars.items()])

        if not command:
            command = '%s %s' % (container_info.entry_point, handler)

        # determine files to be copied into the container
        copy_command = ''
        docker_cmd = self._docker_cmd()
        event_file = os.path.join(lambda_cwd, LAMBDA_EVENT_FILE)
        if not has_been_invoked_before:
            # if this is the first invocation: copy the entire folder into the container
            copy_command = '%s cp "%s/." "%s:/var/task";' % (docker_cmd, lambda_cwd, container_info.name)
        elif os.path.exists(event_file):
            # otherwise, copy only the event file if it exists
            copy_command = '%s cp "%s" "%s:/var/task";' % (docker_cmd, event_file, container_info.name)

        cmd = (
            '%s'
            ' %s exec'
            ' %s'  # env variables
            ' %s'  # container name
            ' %s'  # run cmd
        ) % (copy_command, docker_cmd, exec_env_vars, container_info.name, command)
        LOG.debug('Command for docker-reuse Lambda executor: %s' % cmd)

        return cmd

    def startup(self):
        self.cleanup()
        # start a process to remove idle containers
        self.start_idle_container_destroyer_interval()

    def cleanup(self, arn=None):
        if arn:
            self.function_invoke_times.pop(arn, None)
            return self.destroy_docker_container(arn)
        self.function_invoke_times = {}
        return self.destroy_existing_docker_containers()

    def prime_docker_container(self, runtime, func_arn, env_vars, lambda_cwd):
        """
        Prepares a persistent docker container for a specific function.
        :param runtime: Lamda runtime environment. python2.7, nodejs6.10, etc.
        :param func_arn: The ARN of the lambda function.
        :param env_vars: The environment variables for the lambda.
        :param lambda_cwd: The local directory containing the code for the lambda function.
        :return: ContainerInfo class containing the container name and default entry point.
        """
        with self.docker_container_lock:
            # Get the container name and id.
            container_name = self.get_container_name(func_arn)
            docker_cmd = self._docker_cmd()

            status = self.get_docker_container_status(func_arn)
            LOG.debug('Priming docker container (status "%s"): %s' % (status, container_name))

            # Container is not running or doesn't exist.
            if status < 1:
                # Make sure the container does not exist in any form/state.
                self.destroy_docker_container(func_arn)

                env_vars_str = ' '.join(['-e {}={}'.format(k, cmd_quote(v)) for (k, v) in env_vars])

                network = config.LAMBDA_DOCKER_NETWORK
                network_str = '--network="%s"' % network if network else ''

                # Create and start the container
                LOG.debug('Creating container: %s' % container_name)
                cmd = (
                    '%s create'
                    ' --rm'
                    ' --name "%s"'
                    ' --entrypoint /bin/bash'  # Load bash when it starts.
                    ' --interactive'  # Keeps the container running bash.
                    ' -e AWS_LAMBDA_EVENT_BODY="$AWS_LAMBDA_EVENT_BODY"'
                    ' -e HOSTNAME="$HOSTNAME"'
                    ' -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME"'
                    '  %s'  # env_vars
                    '  %s'  # network
                    ' lambci/lambda:%s'
                ) % (docker_cmd, container_name, env_vars_str, network_str, runtime)
                LOG.debug(cmd)
                run(cmd)

                LOG.debug('Copying files to container "%s" from "%s".' % (container_name, lambda_cwd))
                cmd = (
                    '%s cp'
                    ' "%s/." "%s:/var/task"'
                ) % (docker_cmd, lambda_cwd, container_name)
                LOG.debug(cmd)
                run(cmd)

                LOG.debug('Starting container: %s' % container_name)
                cmd = '%s start %s' % (docker_cmd, container_name)
                LOG.debug(cmd)
                run(cmd)
                # give the container some time to start up
                time.sleep(1)

            # Get the entry point for the image.
            LOG.debug('Getting the entrypoint for image: lambci/lambda:%s' % runtime)
            cmd = (
                '%s image inspect'
                ' --format="{{ .ContainerConfig.Entrypoint }}"'
                ' lambci/lambda:%s'
            ) % (docker_cmd, runtime)

            LOG.debug(cmd)
            run_result = run(cmd)

            entry_point = run_result.strip('[]\n\r ')

            container_network = self.get_docker_container_network(func_arn)

            LOG.debug('Using entrypoint "%s" for container "%s" on network "%s".'
                % (entry_point, container_name, container_network))

            return ContainerInfo(container_name, entry_point)

    def destroy_docker_container(self, func_arn):
        """
        Stops and/or removes a docker container for a specific lambda function ARN.
        :param func_arn: The ARN of the lambda function.
        :return: None
        """
        with self.docker_container_lock:
            status = self.get_docker_container_status(func_arn)
            docker_cmd = self._docker_cmd()

            # Get the container name and id.
            container_name = self.get_container_name(func_arn)

            if status == 1:
                LOG.debug('Stopping container: %s' % container_name)
                cmd = (
                    '%s stop -t0 %s'
                ) % (docker_cmd, container_name)

                LOG.debug(cmd)
                run(cmd, asynchronous=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                status = self.get_docker_container_status(func_arn)

            if status == -1:
                LOG.debug('Removing container: %s' % container_name)
                cmd = (
                    '%s rm %s'
                ) % (docker_cmd, container_name)

                LOG.debug(cmd)
                run(cmd, asynchronous=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

    def get_all_container_names(self):
        """
        Returns a list of container names for lambda containers.
        :return: A String[] localstack docker container names for each function.
        """
        with self.docker_container_lock:
            LOG.debug('Getting all lambda containers names.')
            cmd = '%s ps -a --filter="name=localstack_lambda_*" --format "{{.Names}}"' % self._docker_cmd()
            LOG.debug(cmd)
            cmd_result = run(cmd, asynchronous=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE).strip()

            if len(cmd_result) > 0:
                container_names = cmd_result.split('\n')
            else:
                container_names = []

            return container_names

    def destroy_existing_docker_containers(self):
        """
        Stops and/or removes all lambda docker containers for localstack.
        :return: None
        """
        with self.docker_container_lock:
            container_names = self.get_all_container_names()

            LOG.debug('Removing %d containers.' % len(container_names))
            for container_name in container_names:
                cmd = '%s rm -f %s' % (self._docker_cmd(), container_name)
                LOG.debug(cmd)
                run(cmd, asynchronous=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

    def get_docker_container_status(self, func_arn):
        """
        Determine the status of a docker container.
        :param func_arn: The ARN of the lambda function.
        :return: 1 If the container is running,
        -1 if the container exists but is not running
        0 if the container does not exist.
        """
        with self.docker_container_lock:
            # Get the container name and id.
            container_name = self.get_container_name(func_arn)

            # Check if the container is already running
            # Note: filtering by *exact* name using regex filter '^...$' seems unstable on some
            # systems. Therefore, we use a combination of filter and grep to get the results.
            cmd = ("docker ps -a --filter name='%s' "
                   '--format "{{ .Status }} - {{ .Names }}" '
                   '| grep -w "%s" | cat') % (container_name, container_name)
            LOG.debug('Getting status for container "%s": %s' % (container_name, cmd))
            cmd_result = run(cmd)

            # If the container doesn't exist. Create and start it.
            container_status = cmd_result.strip()

            if len(container_status) == 0:
                return 0

            if container_status.lower().startswith('up '):
                return 1

            return -1

    def get_docker_container_network(self, func_arn):
        """
        Determine the network of a docker container.
        :param func_arn: The ARN of the lambda function.
        :return: name of the container network
        """

        with self.docker_container_lock:

            status = self.get_docker_container_status(func_arn)

            # container does not exist
            if status == 0:
                return ''

            # Get the container name.
            container_name = self.get_container_name(func_arn)
            docker_cmd = self._docker_cmd()

            # Get the container network
            LOG.debug('Getting container network: %s' % container_name)
            cmd = (
                '%s inspect %s'
                ' --format "{{ .HostConfig.NetworkMode }}"'
            ) % (docker_cmd, container_name)

            LOG.debug(cmd)
            cmd_result = run(cmd, asynchronous=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

            container_network = cmd_result.strip()

            return container_network

    def idle_container_destroyer(self):
        """
        Iterates though all the lambda containers and destroys any container that has
        been inactive for longer than MAX_CONTAINER_IDLE_TIME_MS.
        :return: None
        """
        LOG.info('Checking if there are idle containers.')
        current_time = int(time.time() * 1000)
        for func_arn, last_run_time in dict(self.function_invoke_times).items():
            duration = current_time - last_run_time

            # not enough idle time has passed
            if duration < MAX_CONTAINER_IDLE_TIME_MS:
                continue

            # container has been idle, destroy it.
            self.destroy_docker_container(func_arn)

    def start_idle_container_destroyer_interval(self):
        """
        Starts a repeating timer that triggers start_idle_container_destroyer_interval every 60 seconds.
        Thus checking for idle containers and destroying them.
        :return: None
        """
        self.idle_container_destroyer()
        threading.Timer(60.0, self.start_idle_container_destroyer_interval).start()

    def get_container_name(self, func_arn):
        """
        Given a function ARN, returns a valid docker container name.
        :param func_arn: The ARN of the lambda function.
        :return: A docker compatible name for the arn.
        """
        return 'localstack_lambda_' + re.sub(r'[^a-zA-Z0-9_.-]', '_', func_arn)


class LambdaExecutorSeparateContainers(LambdaExecutorContainers):

    def prepare_event(self, environment, event_body):

        # Tell Lambci to use STDIN for the event
        environment['DOCKER_LAMBDA_USE_STDIN'] = '1'
        return event_body.encode()

    def prepare_execution(self, func_arn, env_vars, runtime, command, handler, lambda_cwd):
        entrypoint = ''
        if command:
            entrypoint = ' --entrypoint ""'
        else:
            command = '"%s"' % handler

        env_vars_string = ' '.join(['-e {}="${}"'.format(k, k) for (k, v) in env_vars.items()])
        debug_docker_java_port = '-p {p}:{p}'.format(p=Util.debug_java_port) if Util.debug_java_port else ''
        network = config.LAMBDA_DOCKER_NETWORK
        network_str = '--network="%s"' % network if network else ''
        docker_cmd = self._docker_cmd()

        if config.LAMBDA_REMOTE_DOCKER:
            cmd = (
                'CONTAINER_ID="$(%s create -i'
                ' %s'
                ' %s'
                ' %s'
                ' %s'  # network
                ' --rm'
                ' "lambci/lambda:%s" %s'
                ')";'
                '%s cp "%s/." "$CONTAINER_ID:/var/task"; '
                '%s start -ai "$CONTAINER_ID";'
            ) % (docker_cmd, entrypoint, debug_docker_java_port, env_vars_string, network_str, runtime, command,
                 docker_cmd, lambda_cwd,
                 docker_cmd)
        else:
            lambda_cwd_on_host = self.get_host_path_for_path_in_docker(lambda_cwd)
            cmd = (
                '%s run -i'
                ' %s -v "%s":/var/task'
                ' %s'
                ' %s'  # network
                ' --rm'
                ' "lambci/lambda:%s" %s'
            ) % (docker_cmd, entrypoint, lambda_cwd_on_host, env_vars_string, network_str, runtime, command)
        return cmd

    def get_host_path_for_path_in_docker(self, path):
        return re.sub(r'^%s/(.*)$' % config.TMP_FOLDER,
                    r'%s/\1' % config.HOST_TMP_FOLDER, path)


class LambdaExecutorLocal(LambdaExecutor):

    def _execute(self, func_arn, func_details, event, context=None, version=None):
        lambda_cwd = func_details.cwd
        environment = func_details.envvars.copy()

        # execute the Lambda function in a forked sub-process, sync result via queue
        queue = Queue()

        lambda_function = func_details.function(version)

        def do_execute():
            # now we're executing in the child process, safe to change CWD and ENV
            if lambda_cwd:
                os.chdir(lambda_cwd)
            if environment:
                os.environ.update(environment)
            result = lambda_function(event, context)
            queue.put(result)

        process = Process(target=do_execute)
        with CaptureOutput() as c:
            process.run()
        result = queue.get()
        # TODO: Interweaving stdout/stderr currently not supported
        log_output = ''
        for stream in (c.stdout(), c.stderr()):
            if stream:
                log_output += ('\n' if log_output else '') + stream
        return result, log_output

    def execute_java_lambda(self, event, context, handler, main_file):
        event_file = EVENT_FILE_PATTERN.replace('*', short_uid())
        save_file(event_file, json.dumps(event))
        TMP_FILES.append(event_file)
        class_name = handler.split('::')[0]
        classpath = '%s:%s' % (LAMBDA_EXECUTOR_JAR, main_file)
        cmd = 'java -cp %s %s %s %s' % (classpath, LAMBDA_EXECUTOR_CLASS, class_name, event_file)
        result, log_output = self.run_lambda_executor(cmd)
        LOG.debug('Lambda result / log output:\n%s\n> %s' % (
            result.strip(), log_output.strip().replace('\n', '\n> ')))
        return result, log_output


class Util:
    debug_java_port = False

    @classmethod
    def get_java_opts(cls):
        opts = config.LAMBDA_JAVA_OPTS or ''
        if '_debug_port_' in opts:
            if not cls.debug_java_port:
                cls.debug_java_port = get_free_tcp_port()
            opts = opts.replace('_debug_port_', ('%s' % cls.debug_java_port))
        return opts


# --------------
# GLOBAL STATE
# --------------

EXECUTOR_LOCAL = LambdaExecutorLocal()
EXECUTOR_CONTAINERS_SEPARATE = LambdaExecutorSeparateContainers()
EXECUTOR_CONTAINERS_REUSE = LambdaExecutorReuseContainers()
DEFAULT_EXECUTOR = EXECUTOR_LOCAL
# the keys of AVAILABLE_EXECUTORS map to the LAMBDA_EXECUTOR config variable
AVAILABLE_EXECUTORS = {
    'local': EXECUTOR_LOCAL,
    'docker': EXECUTOR_CONTAINERS_SEPARATE,
    'docker-reuse': EXECUTOR_CONTAINERS_REUSE
}
