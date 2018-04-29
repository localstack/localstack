import os
import re
import json
import time
import logging
import threading
import subprocess
# from datetime import datetime
from multiprocessing import Process, Queue
try:
    from shlex import quote as cmd_quote
except ImportError:
    # for Python 2.7
    from pipes import quote as cmd_quote
from localstack import config
from localstack.utils.common import run, TMP_FILES, short_uid, save_file, to_str, cp_r
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
LAMBDA_RUNTIME_JAVA8 = 'java8'
LAMBDA_RUNTIME_DOTNETCORE2 = 'dotnetcore2.0'
LAMBDA_RUNTIME_GOLANG = 'go1.x'

LAMBDA_EVENT_FILE = 'event_file.json'

# logger
LOG = logging.getLogger(__name__)

# maximum time a pre-allocated container can sit idle before getting killed
MAX_CONTAINER_IDLE_TIME = 600


class LambdaExecutor(object):
    """ Base class for Lambda executors. Subclasses must overwrite the execute method """

    def __init__(self):
        pass

    def execute(self, func_arn, func_details, event, context=None, version=None, async=False):
        raise Exception('Not implemented.')

    def startup(self):
        pass

    def cleanup(self, arn=None):
        pass

    def run_lambda_executor(self, cmd, env_vars={}, async=False):
        process = run(cmd, async=True, stderr=subprocess.PIPE, outfile=subprocess.PIPE, env_vars=env_vars)
        if async:
            result = '{"async": "%s"}' % async
            log_output = 'Lambda executed asynchronously'
        else:
            return_code = process.wait()
            result = to_str(process.stdout.read())
            log_output = to_str(process.stderr.read())

            if return_code != 0:
                raise Exception('Lambda process returned error status code: %s. Output:\n%s' %
                    (return_code, log_output))
        return result, log_output


# holds information about an existing container.
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

    def execute(self, func_arn, func_details, event, context=None, version=None, async=False):

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
        event_body = json.dumps(event)
        event_body_escaped = event_body.replace("'", "\\'")

        docker_host = config.DOCKER_HOST_FROM_CONTAINER

        # amend the environment variables for execution
        environment['AWS_LAMBDA_EVENT_BODY'] = event_body_escaped
        environment['HOSTNAME'] = docker_host
        environment['LOCALSTACK_HOSTNAME'] = docker_host

        # custom command to execute in the container
        command = ''

        # if running a Java Lambda, set up classpath arguments
        if runtime == LAMBDA_RUNTIME_JAVA8:
            # copy executor jar into temp directory
            cp_r(LAMBDA_EXECUTOR_JAR, lambda_cwd)
            # TODO cleanup once we have custom Java Docker image
            taskdir = '/var/task'
            save_file(os.path.join(lambda_cwd, LAMBDA_EVENT_FILE), event_body)
            command = ("bash -c 'cd %s; java -cp .:`ls *.jar | tr \"\\n\" \":\"` \"%s\" \"%s\" \"%s\"'" %
                (taskdir, LAMBDA_EXECUTOR_CLASS, handler, LAMBDA_EVENT_FILE))

        # determine the command to be executed (implemented by subclasses)
        cmd = self.prepare_execution(func_arn, environment, runtime, command, handler, lambda_cwd)

        # lambci writes the Lambda result to stdout and logs to stderr, fetch it from there!
        LOG.debug('Running lambda cmd: %s' % cmd)
        result, log_output = self.run_lambda_executor(cmd, environment, async)
        LOG.debug('Lambda result / log output:\n%s\n>%s' % (result.strip(), log_output.strip().replace('\n', '\n> ')))
        return result, log_output


class LambdaExecutorReuseContainers(LambdaExecutorContainers):
    """ Executor class for executing Lambda functions in re-usable Docker containers """

    def __init__(self):
        super(LambdaExecutorReuseContainers, self).__init__()
        # keeps track of each function arn and the last time it was invoked
        self.function_invoke_times = {}
        # locking thread for creation/destruction of docker containers.
        self.docker_container_lock = threading.RLock()

    def prepare_execution(self, func_arn, env_vars, runtime, command, handler, lambda_cwd):

        # check whether the Lambda has been invoked before
        has_been_invoked_before = func_arn in self.function_invoke_times

        # set the invocation time
        self.function_invoke_times[func_arn] = time.time()

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
        event_file = os.path.join(lambda_cwd, LAMBDA_EVENT_FILE)
        if not has_been_invoked_before:
            # if this is the first invocation: copy the entire folder into the container
            copy_command = 'docker cp "%s/." "%s:/var/task"; ' % (lambda_cwd, container_info.name)
        elif os.path.exists(event_file):
            # otherwise, copy only the event file if it exists
            copy_command = 'docker cp "%s" "%s:/var/task"; ' % (event_file, container_info.name)

        cmd = (
            '%s'  # copy files command
            'docker exec'
            ' %s'  # env variables
            ' %s'  # container name
            ' %s'  # run cmd
        ) % (copy_command, exec_env_vars, container_info.name, command)

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

            LOG.debug('Priming docker container: %s' % container_name)

            status = self.get_docker_container_status(func_arn)
            # Container is not running or doesn't exist.
            if status < 1:
                # Make sure the container does not exist in any form/state.
                self.destroy_docker_container(func_arn)

                env_vars_str = ' '.join(['-e {}={}'.format(k, cmd_quote(v)) for (k, v) in env_vars])

                # Create and start the container
                LOG.debug('Creating container: %s' % container_name)
                cmd = (
                    'docker create'
                    ' --name "%s"'
                    ' --entrypoint /bin/bash'  # Load bash when it starts.
                    ' --interactive'  # Keeps the container running bash.
                    ' -e AWS_LAMBDA_EVENT_BODY="$AWS_LAMBDA_EVENT_BODY"'
                    ' -e HOSTNAME="$HOSTNAME"'
                    ' -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME"'
                    '  %s'  # env_vars
                    ' lambci/lambda:%s'
                ) % (container_name, env_vars_str, runtime)
                LOG.debug(cmd)
                run(cmd, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                LOG.debug('Copying files to container "%s" from "%s".' % (container_name, lambda_cwd))
                cmd = (
                    'docker cp'
                    ' "%s/." "%s:/var/task"'
                ) % (lambda_cwd, container_name)
                LOG.debug(cmd)
                run(cmd, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                LOG.debug('Starting container: %s' % container_name)
                cmd = 'docker start %s' % (container_name)
                LOG.debug(cmd)
                run(cmd, stderr=subprocess.PIPE, outfile=subprocess.PIPE)
                # give the container some time to start up
                time.sleep(1)

            # Get the entry point for the image.
            LOG.debug('Getting the entrypoint for image: lambci/lambda:%s' % runtime)
            cmd = (
                'docker image inspect'
                ' --format="{{ .ContainerConfig.Entrypoint }}"'
                ' lambci/lambda:%s'
            ) % (runtime)

            LOG.debug(cmd)
            run_result = run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

            entry_point = run_result.strip('[]\n\r ')

            LOG.debug('Using entrypoint "%s" for container "%s".' % (entry_point, container_name))
            return ContainerInfo(container_name, entry_point)

    def destroy_docker_container(self, func_arn):
        """
        Stops and/or removes a docker container for a specific lambda function ARN.
        :param func_arn: The ARN of the lambda function.
        :return: None
        """
        with self.docker_container_lock:
            status = self.get_docker_container_status(func_arn)

            # Get the container name and id.
            container_name = self.get_container_name(func_arn)

            if status == 1:
                LOG.debug('Stopping container: %s' % container_name)
                cmd = (
                    'docker stop -t0 %s'
                ) % (container_name)

                LOG.debug(cmd)
                run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                status = self.get_docker_container_status(func_arn)

            if status == -1:
                LOG.debug('Removing container: %s' % container_name)
                cmd = (
                    'docker rm %s'
                ) % (container_name)

                LOG.debug(cmd)
                run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

    def get_all_container_names(self):
        """
        Returns a list of container names for lambda containers.
        :return: A String[] localstack docker container names for each function.
        """
        with self.docker_container_lock:
            LOG.debug('Getting all lambda containers names.')
            cmd = 'docker ps -a --filter="name=localstack_lambda_*" --format "{{.Names}}"'
            LOG.debug(cmd)
            cmd_result = run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE).strip()

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
                cmd = 'docker rm -f %s' % container_name
                LOG.debug(cmd)
                run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

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

            # Check if the container is already running.
            LOG.debug('Getting container status: %s' % container_name)
            cmd = (
                'docker ps'
                ' -a'
                ' --filter name="%s"'
                ' --format "{{ .Status }}"'
            ) % (container_name)

            LOG.debug(cmd)
            cmd_result = run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

            # If the container doesn't exist. Create and start it.
            container_status = cmd_result.strip()

            if len(container_status) == 0:
                return 0

            if container_status.lower().startswith('up '):
                return 1

            return -1

    def idle_container_destroyer(self):
        """
        Iterates though all the lambda containers and destroys any container that has
        been inactive for longer than MAX_CONTAINER_IDLE_TIME.
        :return: None
        """
        LOG.info('Checking if there are idle containers.')
        current_time = time.time()
        for func_arn, last_run_time in self.function_invoke_times.items():
            duration = current_time - last_run_time

            # not enough idle time has passed
            if duration < MAX_CONTAINER_IDLE_TIME:
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

    def prepare_execution(self, func_arn, env_vars, runtime, command, handler, lambda_cwd):
        entrypoint = ''
        if command:
            entrypoint = ' --entrypoint ""'
        else:
            command = '"%s"' % handler

        env_vars_string = ' '.join(['-e {}="${}"'.format(k, k) for (k, v) in env_vars.items()])

        if config.LAMBDA_REMOTE_DOCKER:
            cmd = (
                'CONTAINER_ID="$(docker create'
                ' %s'
                ' %s'
                ' "lambci/lambda:%s" %s'
                ')";'
                'docker cp "%s/." "$CONTAINER_ID:/var/task";'
                'docker start -a "$CONTAINER_ID";'
            ) % (entrypoint, env_vars_string, runtime, command, lambda_cwd)
        else:
            lambda_cwd_on_host = self.get_host_path_for_path_in_docker(lambda_cwd)
            cmd = (
                'docker run'
                '%s -v "%s":/var/task'
                ' %s'
                ' --rm'
                ' "lambci/lambda:%s" %s'
            ) % (entrypoint, lambda_cwd_on_host, env_vars_string, runtime, command)
        return cmd

    def get_host_path_for_path_in_docker(self, path):
        return re.sub(r'^%s/(.*)$' % config.TMP_FOLDER,
                    r'%s/\1' % config.HOST_TMP_FOLDER, path)


class LambdaExecutorLocal(LambdaExecutor):

    def execute(self, func_arn, func_details, event, context=None, version=None, async=False):
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
        process.run()
        result = queue.get()
        # TODO capture log output during local execution?
        log_output = ''
        return result, log_output

    def execute_java_lambda(self, event, context, handler, main_file):
        event_file = EVENT_FILE_PATTERN.replace('*', short_uid())
        save_file(event_file, json.dumps(event))
        TMP_FILES.append(event_file)
        class_name = handler.split('::')[0]
        classpath = '%s:%s' % (LAMBDA_EXECUTOR_JAR, main_file)
        cmd = 'java -cp %s %s %s %s' % (classpath, LAMBDA_EXECUTOR_CLASS, class_name, event_file)
        async = False
        # flip async flag depending on origin
        if 'Records' in event:
            # TODO: add more event supporting async lambda execution
            if 'Sns' in event['Records'][0]:
                async = True
            if 'dynamodb' in event['Records'][0]:
                async = True
        result, log_output = self.run_lambda_executor(cmd, async=async)
        LOG.debug('Lambda result / log output:\n%s\n> %s' % (result.strip(), log_output.strip().replace('\n', '\n> ')))
        return result, log_output


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
