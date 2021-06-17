import os
import re
import sys
import glob
import json
import time
import logging
import threading
import traceback
import subprocess
import six
import base64
from multiprocessing import Process, Queue
try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote  # for Python 2.7
from localstack import config
from localstack.utils import bootstrap
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    CaptureOutput, FuncThread, TMP_FILES, short_uid, save_file, rm_rf, in_docker, last_index_of,
    long_uid, now, to_str, to_bytes, run, cp_r, json_safe, get_free_tcp_port, rm_docker_container)
from localstack.services.install import INSTALL_PATH_LOCALSTACK_FAT_JAR
from localstack.utils.aws.dead_letter_queue import lambda_error_to_dead_letter_queue
from localstack.utils.aws.dead_letter_queue import sqs_error_to_dead_letter_queue
from localstack.utils.aws.lambda_destinations import lambda_result_to_destination
from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs, cloudwatched
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_JAVA8, LAMBDA_RUNTIME_JAVA11, LAMBDA_RUNTIME_PROVIDED)

# constants
LAMBDA_EXECUTOR_JAR = INSTALL_PATH_LOCALSTACK_FAT_JAR
LAMBDA_EXECUTOR_CLASS = 'cloud.localstack.LambdaExecutor'
EVENT_FILE_PATTERN = '%s/lambda.event.*.json' % config.TMP_FOLDER

LAMBDA_SERVER_UNIQUE_PORTS = 500
LAMBDA_SERVER_PORT_OFFSET = 5000

LAMBDA_API_UNIQUE_PORTS = 500
LAMBDA_API_PORT_OFFSET = 9000

MAX_ENV_ARGS_LENGTH = 20000

INTERNAL_LOG_PREFIX = 'ls-daemon: '

# logger
LOG = logging.getLogger(__name__)

# maximum time a pre-allocated container can sit idle before getting killed
MAX_CONTAINER_IDLE_TIME_MS = 600 * 1000

# SQS event source name
EVENT_SOURCE_SQS = 'aws:sqs'

# IP address of main Docker container (lazily initialized)
DOCKER_MAIN_CONTAINER_IP = None

# maps lambda arns to concurrency locks
LAMBDA_CONCURRENCY_LOCK = {}

# CWD folder of handler code in Lambda containers
DOCKER_TASK_FOLDER = '/var/task'


class InvocationException(Exception):
    def __init__(self, message, log_output, result=None):
        super(InvocationException, self).__init__(message)
        self.log_output = log_output
        self.result = result


def get_from_event(event, key):
    try:
        return event['Records'][0][key]
    except KeyError:
        return None


def is_java_lambda(lambda_details):
    runtime = getattr(lambda_details, 'runtime', lambda_details)
    return runtime in [LAMBDA_RUNTIME_JAVA8, LAMBDA_RUNTIME_JAVA11]


def is_nodejs_runtime(lambda_details):
    runtime = getattr(lambda_details, 'runtime', lambda_details) or ''
    return runtime.startswith('nodejs')


def _store_logs(func_details, log_output, invocation_time=None, container_id=None):
    log_group_name = '/aws/lambda/%s' % func_details.name()
    container_id = container_id or short_uid()
    invocation_time = invocation_time or int(time.time() * 1000)
    invocation_time_secs = int(invocation_time / 1000)
    time_str = time.strftime('%Y/%m/%d', time.gmtime(invocation_time_secs))
    log_stream_name = '%s/[LATEST]%s' % (time_str, container_id)
    return store_cloudwatch_logs(log_group_name, log_stream_name, log_output, invocation_time)


def get_main_endpoint_from_container():
    global DOCKER_MAIN_CONTAINER_IP
    if not config.HOSTNAME_FROM_LAMBDA and DOCKER_MAIN_CONTAINER_IP is None:
        DOCKER_MAIN_CONTAINER_IP = False
        try:
            if in_docker():
                DOCKER_MAIN_CONTAINER_IP = bootstrap.get_main_container_ip()
                LOG.info('Determined main container target IP: %s' % DOCKER_MAIN_CONTAINER_IP)
        except Exception as e:
            container_name = bootstrap.get_main_container_name()
            LOG.info('Unable to get IP address of main Docker container "%s": %s' %
                (container_name, e))
    # return (1) predefined endpoint host, or (2) main container IP, or (3) Docker host (e.g., bridge IP)
    return config.HOSTNAME_FROM_LAMBDA or DOCKER_MAIN_CONTAINER_IP or config.DOCKER_HOST_FROM_CONTAINER


class InvocationResult(object):
    def __init__(self, result, log_output=''):
        if isinstance(result, InvocationResult):
            raise Exception('Unexpected invocation result type: %s' % result)
        self.result = result
        self.log_output = log_output or ''


class LambdaExecutor(object):
    """ Base class for Lambda executors. Subclasses must overwrite the _execute method """
    def __init__(self):
        # keeps track of each function arn and the last time it was invoked
        self.function_invoke_times = {}

    def _prepare_environment(self, func_details):
        # setup environment pre-defined variables for docker environment
        result = func_details.envvars.copy()

        # injecting aws credentials into docker environment if not provided
        aws_stack.inject_test_credentials_into_env(result)
        # injecting the region into the docker environment
        aws_stack.inject_region_into_env(result, func_details.region())

        return result

    def execute(self, func_arn, func_details, event, context=None, version=None,
            asynchronous=False, callback=None):
        def do_execute(*args):

            @cloudwatched('lambda')
            def _run(func_arn=None):
                # set the invocation time in milliseconds
                invocation_time = int(time.time() * 1000)
                # start the execution
                raised_error = None
                result = None
                dlq_sent = None
                try:
                    result = self._execute(func_arn, func_details, event, context, version)
                except Exception as e:
                    raised_error = e
                    if asynchronous:
                        if get_from_event(event, 'eventSource') == EVENT_SOURCE_SQS:
                            sqs_queue_arn = get_from_event(event, 'eventSourceARN')
                            if sqs_queue_arn:
                                # event source is SQS, send event back to dead letter queue
                                dlq_sent = sqs_error_to_dead_letter_queue(sqs_queue_arn, event, e)
                        else:
                            # event source is not SQS, send back to lambda dead letter queue
                            lambda_error_to_dead_letter_queue(func_details, event, e)
                    raise e
                finally:
                    self.function_invoke_times[func_arn] = invocation_time
                    callback and callback(result, func_arn, event, error=raised_error, dlq_sent=dlq_sent)
                    lambda_result_to_destination(func_details, event, result, asynchronous, raised_error)

                # return final result
                return result

            return _run(func_arn=func_arn)

        # Inform users about asynchronous mode of the lambda execution.
        if asynchronous:
            LOG.debug('Lambda executed in Event (asynchronous) mode, no response will be returned to caller')
            FuncThread(do_execute).start()
            return InvocationResult(None, log_output='Lambda executed asynchronously.')

        return do_execute()

    def _execute(self, func_arn, func_details, event, context=None, version=None):
        """ This method must be overwritten by subclasses. """
        raise Exception('Not implemented.')

    def startup(self):
        pass

    def cleanup(self, arn=None):
        pass

    def run_lambda_executor(self, cmd, event=None, func_details=None, env_vars=None):
        env_vars = dict(env_vars or {})
        runtime = func_details.runtime or ''

        stdin_str = None
        event_body = event if event is not None else env_vars.get('AWS_LAMBDA_EVENT_BODY')
        event_body = json.dumps(event_body) if isinstance(event_body, dict) else event_body
        event_body = event_body or ''
        is_large_event = len(event_body) > MAX_ENV_ARGS_LENGTH

        is_provided = runtime.startswith(LAMBDA_RUNTIME_PROVIDED)
        if not is_large_event and func_details and is_provided and env_vars.get('DOCKER_LAMBDA_USE_STDIN') == '1':
            # Note: certain "provided" runtimes (e.g., Rust programs) can block if we pass in
            # the event payload via stdin, hence we rewrite the command to "echo ... | ..." below
            env_updates = {
                'PATH': env_vars.get('PATH') or os.environ.get('PATH', ''),
                'AWS_LAMBDA_EVENT_BODY': to_str(event_body),  # Note: seems to be needed for provided runtimes!
                'DOCKER_LAMBDA_USE_STDIN': '1'
            }
            env_vars.update(env_updates)
            # Note: $AWS_LAMBDA_COGNITO_IDENTITY='{}' causes Rust Lambdas to hang
            env_vars.pop('AWS_LAMBDA_COGNITO_IDENTITY', None)
            cmd = re.sub(r'(.*)(%s\s+(run|start|exec))' % self._docker_cmd(),
                r'\1echo $AWS_LAMBDA_EVENT_BODY | \2', cmd)

        if is_large_event:
            # in case of very large event payloads, we need to pass them via stdin
            LOG.debug('Received large Lambda event payload (length %s) - passing via stdin' % len(event_body))
            env_vars['DOCKER_LAMBDA_USE_STDIN'] = '1'

        def add_env_var(cmd, name, value=None):
            value = value or '$%s' % name
            return re.sub(r'(%s)\s+(run|exec)\s+' % config.DOCKER_CMD,
                r'\1 \2 -e %s="%s" ' % (name, value), cmd)

        def rm_env_var(cmd, name):
            return re.sub(r'-e\s+%s="?[^"\s]+"?' % name, '', cmd)

        if env_vars.get('DOCKER_LAMBDA_USE_STDIN') == '1':
            stdin_str = event_body
            if not is_provided:
                env_vars.pop('AWS_LAMBDA_EVENT_BODY', None)
            if 'DOCKER_LAMBDA_USE_STDIN' not in cmd:
                cmd = add_env_var(cmd, 'DOCKER_LAMBDA_USE_STDIN', '1')
                cmd = rm_env_var(cmd, 'AWS_LAMBDA_EVENT_BODY')
        else:
            if 'AWS_LAMBDA_EVENT_BODY' not in env_vars:
                env_vars['AWS_LAMBDA_EVENT_BODY'] = to_str(event_body)
            cmd = add_env_var(cmd, 'AWS_LAMBDA_EVENT_BODY')
            cmd = rm_env_var(cmd, 'DOCKER_LAMBDA_USE_STDIN')

        kwargs = {'stdin': True, 'inherit_env': True, 'asynchronous': True}
        process = run(cmd, env_vars=env_vars, stderr=subprocess.PIPE, outfile=subprocess.PIPE, **kwargs)
        event_stdin_bytes = stdin_str and to_bytes(stdin_str)
        result, log_output = process.communicate(input=event_stdin_bytes)
        try:
            result = to_str(result).strip()
        except Exception:
            pass
        log_output = to_str(log_output).strip()
        return_code = process.returncode
        # Note: The user's code may have been logging to stderr, in which case the logs
        # will be part of the "result" variable here. Hence, make sure that we extract
        # only the *last* line of "result" and consider anything above that as log output.
        if isinstance(result, six.string_types) and '\n' in result:
            lines = result.split('\n')
            idx = last_index_of(lines, lambda line: line and not line.startswith(INTERNAL_LOG_PREFIX))
            if idx >= 0:
                result = lines[idx]
                additional_logs = '\n'.join(lines[:idx] + lines[idx + 1:])
                log_output += '\n%s' % additional_logs

        log_formatted = log_output.strip().replace('\n', '\n> ')
        func_arn = func_details and func_details.arn()
        LOG.debug('Lambda %s result / log output:\n%s\n> %s' % (func_arn, result.strip(), log_formatted))

        # store log output - TODO get live logs from `process` above?
        _store_logs(func_details, log_output)

        if return_code != 0:
            raise InvocationException('Lambda process returned error status code: %s. Result: %s. Output:\n%s' %
                (return_code, result, log_output), log_output, result)

        invocation_result = InvocationResult(result, log_output=log_output)
        return invocation_result


class ContainerInfo:
    """ Contains basic information about a docker container. """
    def __init__(self, name, entry_point):
        self.name = name
        self.entry_point = entry_point


class LambdaExecutorContainers(LambdaExecutor):
    """ Abstract executor class for executing Lambda functions in Docker containers """

    def prepare_execution(self, func_details, env_vars, command):
        raise Exception('Not implemented')

    def _docker_cmd(self):
        """ Return the string to be used for running Docker commands. """
        return config.DOCKER_CMD

    def prepare_event(self, environment, event_body):
        """ Return the event as a stdin string. """
        # amend the environment variables for execution
        environment['AWS_LAMBDA_EVENT_BODY'] = event_body
        return event_body.encode()

    def _execute(self, func_arn, func_details, event, context=None, version=None):
        lambda_cwd = func_details.cwd
        runtime = func_details.runtime
        handler = func_details.handler
        environment = self._prepare_environment(func_details)

        # configure USE_SSL in environment
        if config.USE_SSL:
            environment['USE_SSL'] = '1'

        # prepare event body
        if not event:
            LOG.info('Empty event body specified for invocation of Lambda "%s"' % func_arn)
            event = {}
        event_body = json.dumps(json_safe(event))
        stdin = self.prepare_event(environment, event_body)

        main_endpoint = get_main_endpoint_from_container()

        environment['LOCALSTACK_HOSTNAME'] = main_endpoint
        environment['EDGE_PORT'] = str(config.EDGE_PORT)
        environment['_HANDLER'] = handler
        if os.environ.get('HTTP_PROXY'):
            environment['HTTP_PROXY'] = os.environ['HTTP_PROXY']
        if func_details.timeout:
            environment['AWS_LAMBDA_FUNCTION_TIMEOUT'] = str(func_details.timeout)
        if context:
            environment['AWS_LAMBDA_FUNCTION_NAME'] = context.function_name
            environment['AWS_LAMBDA_FUNCTION_VERSION'] = context.function_version
            environment['AWS_LAMBDA_FUNCTION_INVOKED_ARN'] = context.invoked_function_arn
            environment['AWS_LAMBDA_COGNITO_IDENTITY'] = json.dumps(context.cognito_identity or {})
            if context.client_context is not None:
                environment['AWS_LAMBDA_CLIENT_CONTEXT'] = json.dumps(to_str(
                    base64.b64decode(to_bytes(context.client_context))))

        # custom command to execute in the container
        command = ''
        events_file_path = ''

        if config.LAMBDA_JAVA_OPTS and is_java_lambda(runtime):
            # if running a Java Lambda with our custom executor, set up classpath arguments
            java_opts = Util.get_java_opts()
            stdin = None
            # copy executor jar into temp directory
            target_file = os.path.join(lambda_cwd, os.path.basename(LAMBDA_EXECUTOR_JAR))
            if not os.path.exists(target_file):
                cp_r(LAMBDA_EXECUTOR_JAR, target_file)
            # TODO cleanup once we have custom Java Docker image
            events_file = '_lambda.events.%s.json' % short_uid()
            events_file_path = os.path.join(lambda_cwd, events_file)
            save_file(events_file_path, event_body)
            # construct Java command
            classpath = Util.get_java_classpath(target_file)
            command = ("bash -c 'cd %s; java %s -cp \"%s\" \"%s\" \"%s\" \"%s\"'" %
                (DOCKER_TASK_FOLDER, java_opts, classpath, LAMBDA_EXECUTOR_CLASS, handler, events_file))

        # accept any self-signed certificates for outgoing calls from the Lambda
        if is_nodejs_runtime(runtime):
            environment['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'

        # determine the command to be executed (implemented by subclasses)
        cmd = self.prepare_execution(func_details, environment, command)

        # copy events file into container, if necessary
        if events_file_path:
            container_name = self.get_container_name(func_details.arn())
            self.copy_into_container(events_file_path, container_name, DOCKER_TASK_FOLDER)

        # run Lambda executor and fetch invocation result
        LOG.info('Running lambda cmd: %s' % cmd)
        result = self.run_lambda_executor(cmd, event=stdin, env_vars=environment, func_details=func_details)

        # clean up events file
        events_file_path and os.path.exists(events_file_path) and rm_rf(events_file_path)
        # TODO: delete events file from container!

        return result


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

    def prepare_execution(self, func_details, env_vars, command):
        func_arn = func_details.arn()
        lambda_cwd = func_details.cwd
        runtime = func_details.runtime
        handler = func_details.handler

        # check whether the Lambda has been invoked before
        has_been_invoked_before = func_arn in self.function_invoke_times

        # Choose a port for this invocation
        with self.docker_container_lock:
            env_vars['_LAMBDA_SERVER_PORT'] = str(self.next_port + self.port_offset)
            self.next_port = (self.next_port + 1) % self.max_port

        # create/verify the docker container is running.
        LOG.debug('Priming docker container with runtime "%s" and arn "%s".', runtime, func_arn)
        container_info = self.prime_docker_container(func_details, env_vars, lambda_cwd)

        if not command:
            command = '%s %s' % (container_info.entry_point, handler)

        # create file with environment variables
        env_vars_flag = Util.create_env_vars_file_flag(env_vars)

        # determine files to be copied into the container
        copy_command = ''
        docker_cmd = self._docker_cmd()
        if not has_been_invoked_before and config.LAMBDA_REMOTE_DOCKER:
            # if this is the first invocation: copy the entire folder into the container
            copy_command = '%s cp "%s/." "%s:%s";' % (docker_cmd,
                lambda_cwd, container_info.name, DOCKER_TASK_FOLDER)

        cmd = (
            '%s'
            ' %s exec -i'
            ' %s'  # env variables file
            ' %s'  # container name
            ' %s'  # run cmd
        ) % (copy_command, docker_cmd, env_vars_flag, container_info.name, command)
        LOG.debug('Command for docker-reuse Lambda executor: %s' % cmd)

        return cmd

    def _execute(self, func_arn, *args, **kwargs):
        if not LAMBDA_CONCURRENCY_LOCK.get(func_arn):
            concurrency_lock = threading.RLock()
            LAMBDA_CONCURRENCY_LOCK[func_arn] = concurrency_lock
        with LAMBDA_CONCURRENCY_LOCK[func_arn]:
            return super(LambdaExecutorReuseContainers, self)._execute(func_arn, *args, **kwargs)

    def startup(self):
        self.cleanup()
        # start a process to remove idle containers
        if config.LAMBDA_REMOVE_CONTAINERS:
            self.start_idle_container_destroyer_interval()

    def cleanup(self, arn=None):
        if arn:
            self.function_invoke_times.pop(arn, None)
            return self.destroy_docker_container(arn)
        self.function_invoke_times = {}
        return self.destroy_existing_docker_containers()

    def prime_docker_container(self, func_details, env_vars, lambda_cwd):
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
            func_arn = func_details.arn()
            container_name = self.get_container_name(func_arn)
            docker_cmd = self._docker_cmd()

            status = self.get_docker_container_status(func_arn)
            LOG.debug('Priming Docker container (status "%s"): %s' % (status, container_name))

            docker_image = Util.docker_image_for_lambda(func_details)

            # Container is not running or doesn't exist.
            if status < 1:
                # Make sure the container does not exist in any form/state.
                self.destroy_docker_container(func_arn)

                # get container startup command and run it
                LOG.debug('Creating container: %s' % container_name)
                cmd = self.get_container_startup_command(func_details, env_vars, lambda_cwd)
                LOG.debug(cmd)
                run(cmd)

                if config.LAMBDA_REMOTE_DOCKER:
                    LOG.debug('Copying files to container "%s" from "%s".' % (container_name, lambda_cwd))
                    self.copy_into_container('%s/.' % lambda_cwd, container_name, DOCKER_TASK_FOLDER)

                LOG.debug('Starting container: %s' % container_name)
                cmd = '%s start %s' % (docker_cmd, container_name)
                LOG.debug(cmd)
                run(cmd)
                # give the container some time to start up
                time.sleep(1)

            container_network = self.get_docker_container_network(func_arn)
            entry_point = self.get_container_entrypoint(docker_image)

            LOG.debug('Using entrypoint "%s" for container "%s" on network "%s".'
                % (entry_point, container_name, container_network))

            return ContainerInfo(container_name, entry_point)

    def get_container_startup_command(self, func_details, env_vars, lambda_cwd):
        docker_image = Util.docker_image_for_lambda(func_details)
        rm_flag = Util.get_docker_remove_flag()
        docker_cmd = self._docker_cmd()
        container_name = self.get_container_name(func_details.arn())

        # make sure AWS_LAMBDA_EVENT_BODY is not set (otherwise causes issues with "docker exec ..." above)
        env_vars.pop('AWS_LAMBDA_EVENT_BODY', None)

        # create environment variables flag (either passed directly, or as env var file)
        env_vars_flags = Util.create_env_vars_file_flag(env_vars)

        network = config.LAMBDA_DOCKER_NETWORK
        network_str = '--network="%s"' % network if network else ''

        additional_flags = config.LAMBDA_DOCKER_FLAGS or ''

        dns = config.LAMBDA_DOCKER_DNS
        dns_str = '--dns="%s"' % dns if dns else ''

        mount_volume = not config.LAMBDA_REMOTE_DOCKER
        lambda_cwd_on_host = Util.get_host_path_for_path_in_docker(lambda_cwd)
        if (':' in lambda_cwd and '\\' in lambda_cwd):
            lambda_cwd_on_host = Util.format_windows_path(lambda_cwd_on_host)
        mount_volume_str = '-v "%s":%s' % (lambda_cwd_on_host, DOCKER_TASK_FOLDER) if mount_volume else ''

        # Create and start the container
        cmd = (
            '%s create'
            ' %s'  # --rm flag
            ' --name "%s"'
            ' --entrypoint /bin/bash'  # Load bash when it starts.
            ' %s'
            ' --interactive'  # Keeps the container running bash.
            ' -e HOSTNAME="$HOSTNAME"'
            ' -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME"'
            ' -e EDGE_PORT="$EDGE_PORT"'
            ' %s'  # env_vars
            ' %s'  # network
            ' %s'  # dns
            ' %s'  # additional flags
            ' %s'
        ) % (docker_cmd, rm_flag, container_name, mount_volume_str,
            env_vars_flags, network_str, dns_str, additional_flags, docker_image)
        return cmd

    def get_container_entrypoint(self, docker_image):
        """ Get the entry point for the given image """
        docker_cmd = self._docker_cmd()
        LOG.debug('Getting the entrypoint for image: %s' % (docker_image))
        cmd = (
            '%s image inspect'
            ' --format="{{ .Config.Entrypoint }}"'
            ' %s'
        ) % (docker_cmd, docker_image)

        LOG.debug(cmd)
        run_result = run(cmd)

        entry_point = run_result.strip('[]\n\r ')
        return entry_point

    def copy_into_container(self, local_path, container_name, container_path):
        cmd = ('%s cp %s "%s:%s"') % (self._docker_cmd(), local_path, container_name, container_path)
        LOG.debug(cmd)
        run(cmd)

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
                cmd = '%s stop -t0 %s' % (docker_cmd, container_name)

                LOG.debug(cmd)
                run(cmd, asynchronous=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                status = self.get_docker_container_status(func_arn)

            if status == -1:
                LOG.debug('Removing container: %s' % container_name)
                rm_docker_container(container_name, safe=True)

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
        LOG.debug('Checking if there are idle containers ...')
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
    def __init__(self):
        super(LambdaExecutorSeparateContainers, self).__init__()
        self.max_port = LAMBDA_API_UNIQUE_PORTS
        self.port_offset = LAMBDA_API_PORT_OFFSET

    def prepare_event(self, environment, event_body):
        # Tell Lambci to use STDIN for the event
        environment['DOCKER_LAMBDA_USE_STDIN'] = '1'
        return event_body.encode()

    def prepare_execution(self, func_details, env_vars, command):
        lambda_cwd = func_details.cwd
        handler = func_details.handler

        entrypoint = ''
        if command:
            entrypoint = ' --entrypoint ""'
        elif handler:
            command = '"%s"' % handler
        else:
            command = ''

        # add Docker Lambda env vars
        network = config.LAMBDA_DOCKER_NETWORK
        network_str = '--network="%s"' % network if network else ''
        if network == 'host':
            port = get_free_tcp_port()
            env_vars['DOCKER_LAMBDA_API_PORT'] = port
            env_vars['DOCKER_LAMBDA_RUNTIME_PORT'] = port

        additional_flags = config.LAMBDA_DOCKER_FLAGS or ''

        dns = config.LAMBDA_DOCKER_DNS
        dns_str = '--dns="%s"' % dns if dns else ''

        env_vars_flag = Util.create_env_vars_file_flag(env_vars)
        debug_docker_java_port = '-p {p}:{p}'.format(p=Util.debug_java_port) if Util.debug_java_port else ''
        docker_cmd = self._docker_cmd()
        docker_image = Util.docker_image_for_lambda(func_details)
        rm_flag = Util.get_docker_remove_flag()

        # construct common flags for commands below
        common_flags = ' '.join([env_vars_flag, network_str, dns_str, additional_flags, rm_flag])

        if config.LAMBDA_REMOTE_DOCKER:
            cp_cmd = ('%s cp "%s/." "$CONTAINER_ID:%s";' % (
                docker_cmd, lambda_cwd, DOCKER_TASK_FOLDER)) if lambda_cwd else ''
            cmd = (
                'CONTAINER_ID="$(%s create -i'
                ' %s'  # entrypoint
                ' %s'  # debug_docker_java_port
                ' %s'  # common flags
                ' %s %s'  # image and command
                ')";'
                '%s '
                '%s start -ai "$CONTAINER_ID";'
            ) % (docker_cmd, entrypoint, debug_docker_java_port,
                 common_flags, docker_image, command,
                 cp_cmd, docker_cmd)
        else:
            mount_flag = ''
            if lambda_cwd:
                mount_flag = '-v "%s":%s' % (Util.get_host_path_for_path_in_docker(lambda_cwd), DOCKER_TASK_FOLDER)
            cmd = (
                '%s run -i'
                ' %s'
                ' %s'  # code mount
                ' %s'  # common flags
                ' %s %s'
            ) % (docker_cmd, entrypoint, mount_flag, common_flags, docker_image, command)
        return cmd


class LambdaExecutorLocal(LambdaExecutor):
    def _execute(self, func_arn, func_details, event, context=None, version=None):
        lambda_cwd = func_details.cwd
        environment = self._prepare_environment(func_details)

        # execute the Lambda function in a forked sub-process, sync result via queue
        queue = Queue()

        lambda_function = func_details.function(version)

        def do_execute():
            # now we're executing in the child process, safe to change CWD and ENV
            result = None
            try:
                if lambda_cwd:
                    os.chdir(lambda_cwd)
                    sys.path.insert(0, '')
                if environment:
                    os.environ.update(environment)
                result = lambda_function(event, context)
            except Exception as e:
                result = str(e)
                sys.stderr.write('%s %s' % (e, traceback.format_exc()))
                raise
            finally:
                queue.put(result)

        process = Process(target=do_execute)
        start_time = now(millis=True)
        error = None
        with CaptureOutput() as c:
            try:
                process.run()
            except Exception as e:
                error = e
        result = queue.get()
        end_time = now(millis=True)

        # Make sure to keep the log line below, to ensure the log stream gets created
        request_id = long_uid()
        log_output = 'START %s: Lambda %s started via "local" executor ...' % (request_id, func_arn)
        # TODO: Interweaving stdout/stderr currently not supported
        for stream in (c.stdout(), c.stderr()):
            if stream:
                log_output += ('\n' if log_output else '') + stream
        log_output += '\nEND RequestId: %s' % request_id
        log_output += '\nREPORT RequestId: %s Duration: %s ms' % (request_id, int((end_time - start_time) * 1000))

        # store logs to CloudWatch
        _store_logs(func_details, log_output)

        result = result.result if isinstance(result, InvocationResult) else result

        if error:
            LOG.info('Error executing Lambda "%s": %s %s' % (func_arn, error,
                ''.join(traceback.format_tb(error.__traceback__))))
            raise InvocationException(result, log_output)

        invocation_result = InvocationResult(result, log_output=log_output)
        return invocation_result

    def execute_java_lambda(self, event, context, main_file, func_details=None):
        handler = func_details.handler
        opts = config.LAMBDA_JAVA_OPTS if config.LAMBDA_JAVA_OPTS else ''
        event_file = EVENT_FILE_PATTERN.replace('*', short_uid())
        save_file(event_file, json.dumps(json_safe(event)))
        TMP_FILES.append(event_file)
        class_name = handler.split('::')[0]
        classpath = '%s:%s:%s' % (main_file, Util.get_java_classpath(main_file), LAMBDA_EXECUTOR_JAR)
        cmd = 'java %s -cp %s %s %s %s' % (opts, classpath, LAMBDA_EXECUTOR_CLASS, class_name, event_file)
        LOG.warning(cmd)
        result = self.run_lambda_executor(cmd, func_details=func_details)
        return result


class Util:
    debug_java_port = False

    @classmethod
    def get_java_opts(cls):
        opts = config.LAMBDA_JAVA_OPTS or ''
        # Replace _debug_port_ with a random free port
        if '_debug_port_' in opts:
            if not cls.debug_java_port:
                cls.debug_java_port = get_free_tcp_port()
            opts = opts.replace('_debug_port_', ('%s' % cls.debug_java_port))
        else:
            # Parse the debug port from opts
            m = re.match('.*address=(.+:)?(\\d+).*', opts)
            if m is not None:
                cls.debug_java_port = m.groups()[1]

        return opts

    @classmethod
    def get_host_path_for_path_in_docker(cls, path):
        return re.sub(r'^%s/(.*)$' % config.TMP_FOLDER,
                      r'%s/\1' % config.HOST_TMP_FOLDER, path)

    @classmethod
    def format_windows_path(cls, path):
        temp = path.replace(':', '').replace('\\', '/')
        if len(temp) >= 1 and temp[:1] != '/':
            temp = '/' + temp
        temp = '%s%s' % (config.WINDOWS_DOCKER_MOUNT_PREFIX, temp)
        return temp

    @classmethod
    def docker_image_for_lambda(cls, func_details):
        runtime = func_details.runtime or ''
        docker_tag = runtime
        docker_image = config.LAMBDA_CONTAINER_REGISTRY
        # TODO: remove prefix once execution issues are fixed with dotnetcore/python lambdas
        # See https://github.com/lambci/docker-lambda/pull/218
        lambdas_to_add_prefix = ['dotnetcore2.0', 'dotnetcore2.1', 'python2.7', 'python3.6', 'python3.7']
        if docker_image == 'lambci/lambda' and any(img in docker_tag for img in lambdas_to_add_prefix):
            docker_tag = '20191117-%s' % docker_tag
        if runtime == 'nodejs14.x':
            # TODO temporary fix until lambci image for nodejs14.x becomes available
            docker_image = 'localstack/lambda-js'
        return '"%s:%s"' % (docker_image, docker_tag)

    @staticmethod
    def get_docker_remove_flag():
        return '--rm' if config.LAMBDA_REMOVE_CONTAINERS else ''

    @classmethod
    def get_java_classpath(cls, archive):
        """
        Return the Java classpath, using the parent folder of the
        given archive as the base folder.

        The result contains any *.jar files in the base folder, as
        well as any JAR files in the "lib/*" subfolder living
        alongside the supplied java archive (.jar or .zip).

        :param archive: an absolute path to a .jar or .zip Java archive
        :return: the Java classpath, relative to the base dir of "archive"
        """
        entries = ['.']
        base_dir = os.path.dirname(archive)
        for pattern in ['%s/*.jar', '%s/lib/*.jar', '%s/java/lib/*.jar', '%s/*.zip']:
            for entry in glob.glob(pattern % base_dir):
                if os.path.realpath(archive) != os.path.realpath(entry):
                    entries.append(os.path.relpath(entry, base_dir))
        # make sure to append the localstack-utils.jar at the end of the classpath
        # https://github.com/localstack/localstack/issues/1160
        entries.append(os.path.relpath(archive, base_dir))
        entries.append('*.jar')
        entries.append('java/lib/*.jar')
        result = ':'.join(entries)
        return result

    @classmethod
    def create_env_vars_file_flag(cls, env_vars, use_env_variable_names=True):
        if not env_vars:
            return ''
        result = ''
        env_vars = dict(env_vars)
        if len(str(env_vars)) > MAX_ENV_ARGS_LENGTH:
            # default ARG_MAX=131072 in Docker - let's create an env var file if the string becomes too long...
            env_file = cls.mountable_tmp_file()
            env_content = ''
            for name, value in dict(env_vars).items():
                if len(value) > MAX_ENV_ARGS_LENGTH:
                    # each line in the env file has a max size as well (error "bufio.Scanner: token too long")
                    continue
                env_vars.pop(name)
                value = value.replace('\n', '\\')
                env_content += '%s=%s\n' % (name, value)
            save_file(env_file, env_content)
            result += '--env-file %s ' % env_file

        if use_env_variable_names:
            env_vars_str = ' '.join(['-e {k}="${k}"'.format(k=k) for k in env_vars.keys()])
        else:
            # TODO: we should remove this mid-term - shouldn't be using cmd_quote directly
            env_vars_str = ' '.join(['-e {}={}'.format(k, cmd_quote(v)) for k, v in env_vars.items()])
        result += env_vars_str
        return result

    @staticmethod
    def rm_env_vars_file(env_vars_file_flag):
        if not env_vars_file_flag or '--env-file' not in env_vars_file_flag:
            return
        env_vars_file = env_vars_file_flag.replace('--env-file', '').strip()
        return rm_rf(env_vars_file)

    @staticmethod
    def mountable_tmp_file():
        f = os.path.join(config.TMP_FOLDER, short_uid())
        TMP_FILES.append(f)
        return f


# --------------
# GLOBAL STATE
# --------------

EXECUTOR_LOCAL = LambdaExecutorLocal()
EXECUTOR_CONTAINERS_SEPARATE = LambdaExecutorSeparateContainers()
EXECUTOR_CONTAINERS_REUSE = LambdaExecutorReuseContainers()
DEFAULT_EXECUTOR = EXECUTOR_CONTAINERS_SEPARATE
# the keys of AVAILABLE_EXECUTORS map to the LAMBDA_EXECUTOR config variable
AVAILABLE_EXECUTORS = {
    'local': EXECUTOR_LOCAL,
    'docker': EXECUTOR_CONTAINERS_SEPARATE,
    'docker-reuse': EXECUTOR_CONTAINERS_REUSE
}
