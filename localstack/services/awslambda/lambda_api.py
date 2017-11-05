from __future__ import print_function

import os
import re
import sys
import json
import uuid
import time
import traceback
import logging
import base64
import threading
import imp
import glob
import subprocess
from io import BytesIO
from datetime import datetime
from multiprocessing import Process, Queue
try:
    from shlex import quote as cmd_quote
except ImportError:
    # for Python 2.7
    from pipes import quote as cmd_quote
from six import iteritems
from six.moves import cStringIO as StringIO
from flask import Flask, Response, jsonify, request, make_response
from localstack import config
from localstack.services import generic_proxy
from localstack.services.install import INSTALL_PATH_LOCALSTACK_FAT_JAR
from localstack.utils.common import (to_str, load_file, save_file, TMP_FILES,
    unzip, is_zip_file, run, short_uid, is_jar_archive, timestamp, TIMESTAMP_FORMAT_MILLIS)
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.analytics import event_publisher
from localstack.utils.cloudwatch.cloudwatch_util import cloudwatched
from localstack.utils.aws.aws_models import LambdaFunction


APP_NAME = 'lambda_api'
PATH_ROOT = '/2015-03-31'
ARCHIVE_FILE_PATTERN = '%s/lambda.handler.*.jar' % config.TMP_FOLDER
EVENT_FILE_PATTERN = '%s/lambda.event.*.json' % config.TMP_FOLDER
LAMBDA_SCRIPT_PATTERN = '%s/lambda_script_*.py' % config.TMP_FOLDER
LAMBDA_EXECUTOR_JAR = INSTALL_PATH_LOCALSTACK_FAT_JAR
LAMBDA_EXECUTOR_CLASS = 'cloud.localstack.LambdaExecutor'

LAMBDA_RUNTIME_PYTHON27 = 'python2.7'
LAMBDA_RUNTIME_PYTHON36 = 'python3.6'
LAMBDA_RUNTIME_NODEJS = 'nodejs'
LAMBDA_RUNTIME_NODEJS610 = 'nodejs6.10'
LAMBDA_RUNTIME_JAVA8 = 'java8'

LAMBDA_DEFAULT_HANDLER = 'handler.handler'
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON27
LAMBDA_DEFAULT_STARTING_POSITION = 'LATEST'
LAMBDA_DEFAULT_TIMEOUT = 60
LAMBDA_ZIP_FILE_NAME = 'original_lambda_archive.zip'

app = Flask(APP_NAME)

# map ARN strings to lambda function objects
arn_to_lambda = {}

# list of event source mappings for the API
event_source_mappings = []

# logger
LOG = logging.getLogger(__name__)

# mutex for access to CWD and ENV
exec_mutex = threading.Semaphore(1)

# whether to use Docker for execution
DO_USE_DOCKER = None

# locking thread for creation/destruction of docker containers.
docker_container_lock = threading.RLock()

# keeps track of each function arn and the last time it was invoked
function_invoke_times = {}


# holds information about an existing container.
class ContainerInfo:
    """
    Contains basic information about a docker container.
    """
    def __init__(self, name, entry_point):
        self.name = name
        self.entry_point = entry_point


def cleanup():
    global event_source_mappings, arn_to_lambda
    arn_to_lambda = {}
    event_source_mappings = []


def func_arn(function_name):
    return aws_stack.lambda_function_arn(function_name)


def add_function_mapping(lambda_name, lambda_handler, lambda_cwd=None):
    arn = func_arn(lambda_name)
    arn_to_lambda[arn].versions.get('$LATEST')['Function'] = lambda_handler
    arn_to_lambda[arn].cwd = lambda_cwd


def add_event_source(function_name, source_arn):
    mapping = {
        'UUID': str(uuid.uuid4()),
        'StateTransitionReason': 'User action',
        'LastModified': float(time.mktime(datetime.utcnow().timetuple())),
        'BatchSize': 100,
        'State': 'Enabled',
        'FunctionArn': func_arn(function_name),
        'EventSourceArn': source_arn,
        'LastProcessingResult': 'OK',
        'StartingPosition': LAMBDA_DEFAULT_STARTING_POSITION
    }
    event_source_mappings.append(mapping)
    return mapping


def update_event_source(uuid_value, function_name, enabled, batch_size):
    for m in event_source_mappings:
        if uuid_value == m['UUID']:
            if function_name:
                m['FunctionArn'] = func_arn(function_name)
            m['BatchSize'] = batch_size
            m['State'] = enabled and 'Enabled' or 'Disabled'
            m['LastModified'] = float(time.mktime(datetime.utcnow().timetuple()))
            return m
    return {}


def delete_event_source(uuid_value):
    for i, m in enumerate(event_source_mappings):
        if uuid_value == m['UUID']:
            return event_source_mappings.pop(i)
    return {}


def use_docker():
    global DO_USE_DOCKER
    if DO_USE_DOCKER is None:
        DO_USE_DOCKER = False
        if config.LAMBDA_EXECUTOR == 'docker':
            try:
                run('docker images', print_error=False)
                # run('ping -c 1 -t 1 %s' % DOCKER_BRIDGE_IP, print_error=False)
                DO_USE_DOCKER = True
            except Exception:
                pass
    return DO_USE_DOCKER


def process_apigateway_invocation(func_arn, path, payload, headers={},
        resource_path=None, method=None, path_params={}):
    try:
        lambda_function = arn_to_lambda[func_arn].function()
        resource_path = resource_path or path
        event = {
            'path': path,
            'headers': dict(headers),
            'pathParameters': dict(path_params),
            'body': payload,
            'isBase64Encoded': False,
            'resource': resource_path,
            'httpMethod': method,
            'queryStringParameters': {},  # TODO
            'stageVariables': {}  # TODO
        }
        return run_lambda(lambda_function, event=event, context={}, func_arn=func_arn)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on API Gateway message: %s %s' % (e, traceback.format_exc()))


def process_sns_notification(func_arn, topic_arn, message, subject=''):
    try:
        lambda_function = arn_to_lambda[func_arn].function()
        event = {
            'Records': [{
                'Sns': {
                    'Type': 'Notification',
                    'TopicArn': topic_arn,
                    'Subject': subject,
                    'Message': message,
                    'Timestamp': timestamp(format=TIMESTAMP_FORMAT_MILLIS)
                }
            }]
        }
        return run_lambda(lambda_function, event=event, context={}, func_arn=func_arn, async=True)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on SNS message: %s %s' % (e, traceback.format_exc()))


def process_kinesis_records(records, stream_name):
    # feed records into listening lambdas
    try:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        sources = get_event_sources(source_arn=stream_arn)
        for source in sources:
            arn = source['FunctionArn']
            lambda_function = arn_to_lambda[arn].function()
            event = {
                'Records': []
            }
            for rec in records:
                event['Records'].append({
                    'kinesis': rec
                })
            run_lambda(lambda_function, event=event, context={}, func_arn=arn)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on Kinesis records: %s %s' % (e, traceback.format_exc()))


def get_event_sources(func_name=None, source_arn=None):
    result = []
    for m in event_source_mappings:
        if not func_name or m['FunctionArn'] in [func_name, func_arn(func_name)]:
            if not source_arn or m['EventSourceArn'].startswith(source_arn):
                result.append(m)
    return result


def get_function_version(arn, version):
    func_name = arn.split(':function:')[-1]
    return \
        {
            'Version': version,
            'CodeSize': arn_to_lambda.get(arn).get_version(version).get('CodeSize'),
            'FunctionName': func_name,
            'FunctionArn': arn + ':' + str(version),
            'Handler': arn_to_lambda.get(arn).handler,
            'Runtime': arn_to_lambda.get(arn).runtime,
            'Timeout': LAMBDA_DEFAULT_TIMEOUT,
        }


def publish_new_function_version(arn):
    versions = arn_to_lambda.get(arn).versions
    if len(versions) == 1:
        last_version = 0
    else:
        last_version = max([int(key) for key in versions.keys() if key != '$LATEST'])
    versions[str(last_version + 1)] = {'CodeSize': versions.get('$LATEST').get('CodeSize'),
                                  'Function': versions.get('$LATEST').get('Function')}
    return get_function_version(arn, str(last_version + 1))


def do_list_versions(arn):
    return sorted([get_function_version(arn, version) for version in
                   arn_to_lambda.get(arn).versions.keys()], key=lambda k: str(k.get('Version')))


def do_update_alias(arn, alias, version, description=None):
    new_alias = {
        'AliasArn': arn + ':' + alias,
        'FunctionVersion': version,
        'Name': alias,
        'Description': description or ''
    }
    arn_to_lambda.get(arn).aliases[alias] = new_alias
    return new_alias


def get_host_path_for_path_in_docker(path):
    return re.sub(r'^%s/(.*)$' % config.TMP_FOLDER,
                r'%s/\1' % config.HOST_TMP_FOLDER, path)


@cloudwatched('lambda')
def run_lambda(func, event, context, func_arn, suppress_output=False, async=False):
    if suppress_output:
        stdout_ = sys.stdout
        stderr_ = sys.stderr
        stream = StringIO()
        sys.stdout = stream
        sys.stderr = stream
    lambda_cwd = arn_to_lambda.get(func_arn).cwd
    try:
        runtime = arn_to_lambda.get(func_arn).runtime
        handler = arn_to_lambda.get(func_arn).handler
        environment = arn_to_lambda.get(func_arn).envvars.copy()
        if use_docker():
            handler_args = '"%s"' % handler

            # prepare event body
            if not event:
                LOG.warning('Empty event body specified for invocation of Lambda "%s"' % func_arn)
                event = {}
            event_body = json.dumps(event)
            event_body_escaped = event_body.replace("'", "\\'")

            docker_host = config.DOCKER_HOST_FROM_CONTAINER

            # create/verify the docker container is running.
            LOG.debug('Priming docker container with runtime "%s" and arn "%s".', runtime, func_arn)
            container_info = prime_docker_container(runtime, func_arn, environment.items(), lambda_cwd)

            # amend the environment variables for execution
            environment['AWS_LAMBDA_EVENT_BODY'] = event_body_escaped
            environment['HOSTNAME'] = docker_host
            environment['LOCALSTACK_HOSTNAME'] = docker_host
            exec_env_vars = ' '.join(['export {}={} &&'.format(k, cmd_quote(v)) for (k, v) in environment.items()])

            run_cmd = ''

            # if running a Java Lambda, override the executor and run our own.
            if runtime == LAMBDA_RUNTIME_JAVA8:
                taskdir = '/var/task'
                event_file = 'event_file-%s.json' % datetime.now().isoformat()

                # create a local temp file of event data and copy it to the container.
                local_event_file = os.path.join(lambda_cwd, event_file)
                save_file(local_event_file, event_body)
                cmd = (
                    'docker cp "%s" "%s:%s"'
                ) % (local_event_file, container_info.name, taskdir)
                run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                # copy the localstack java executor to the container.
                cmd = (
                    'docker cp "%s" "%s:%s"'
                ) % (LAMBDA_EXECUTOR_JAR, container_info.name, taskdir)
                run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

                # determine the classpath on the container.
                cmd = (
                    'docker exec %s /bin/bash -c \'cd %s; ls *.jar\''
                ) % (container_info.name, taskdir)
                run_result = run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)
                class_path = run_result.strip().replace('\n', ':')

                # create the command
                run_cmd = '%s cd %s && java -cp .:%s "%s" "%s" "%s"' % (
                    exec_env_vars,
                    taskdir,
                    class_path,
                    LAMBDA_EXECUTOR_CLASS,
                    handler,
                    event_file
                )
            else:
                run_cmd = '%s %s %s' % (exec_env_vars, container_info.entry_point, handler_args)

            cmd = (
                'docker exec'
                ' %s'  # container name
                ' /bin/bash -c'
                ' \''
                ' %s'  # run cmd
                '\''
            ) % (container_info.name, run_cmd)

            env_vars = {}
            print(cmd)

            function_invoke_times[func_arn] = time.time()

            # lambci writes the Lambda result to stdout and logs to stderr, fetch it from there!
            LOG.debug('Running lambda cmd: %s', cmd)
            result, log_output = run_lambda_executor(cmd, env_vars, async)
            LOG.debug('Lambda log output:\n%s' % log_output)
        else:
            # execute the Lambda function in a forked sub-process, sync result via queue
            queue = Queue()

            def do_execute():
                # now we're executing in the child process, safe to change CWD and ENV
                if lambda_cwd:
                    os.chdir(lambda_cwd)
                if environment:
                    os.environ.update(environment)
                result = func(event, context)
                queue.put(result)

            process = Process(target=do_execute)
            process.run()
            result = queue.get()

    except Exception as e:
        return error_response('Error executing Lambda function: %s %s' % (e, traceback.format_exc()))
    finally:
        if suppress_output:
            sys.stdout = stdout_
            sys.stderr = stderr_
    return result


def exec_lambda_code(script, handler_function='handler', lambda_cwd=None, lambda_env=None):
    if lambda_cwd or lambda_env:
        exec_mutex.acquire()
        if lambda_cwd:
            previous_cwd = os.getcwd()
            os.chdir(lambda_cwd)
            sys.path = [lambda_cwd] + sys.path
        if lambda_env:
            previous_env = dict(os.environ)
            os.environ.update(lambda_env)
    # generate lambda file name
    lambda_id = 'l_%s' % short_uid()
    lambda_file = LAMBDA_SCRIPT_PATTERN.replace('*', lambda_id)
    save_file(lambda_file, script)
    # delete temporary .py and .pyc files on exit
    TMP_FILES.append(lambda_file)
    TMP_FILES.append('%sc' % lambda_file)
    try:
        handler_module = imp.load_source(lambda_id, lambda_file)
        module_vars = handler_module.__dict__
    except Exception as e:
        LOG.error('Unable to exec: %s %s' % (script, traceback.format_exc()))
        raise e
    finally:
        if lambda_cwd or lambda_env:
            if lambda_cwd:
                os.chdir(previous_cwd)
                sys.path.pop(0)
            if lambda_env:
                os.environ = previous_env
            exec_mutex.release()
    return module_vars[handler_function]


def get_handler_file_from_name(handler_name, runtime=LAMBDA_RUNTIME_PYTHON27):
    # TODO: support Java Lambdas in the future
    file_ext = '.js' if runtime.startswith(LAMBDA_RUNTIME_NODEJS) else '.py'
    return '%s%s' % (handler_name.split('.')[0], file_ext)


def get_handler_function_from_name(handler_name, runtime=LAMBDA_RUNTIME_PYTHON27):
    # TODO: support Java Lambdas in the future
    return handler_name.split('.')[-1]


def error_response(msg, code=500, error_type='InternalFailure'):
    LOG.warning(msg)
    return aws_responses.flask_error_response(msg, code=code, error_type=error_type)


def prime_docker_container(runtime, func_arn, env_vars, lambda_cwd):
    """
    Prepares a persistent docker container for a specific function.
    :param runtime: Lamda runtime environment. python2.7, nodejs6.10, etc.
    :param func_arn: The ARN of the lambda function.
    :param env_vars: The environment variables for the lambda.
    :param lambda_cwd: The local directory containing the code for the lambda function.
    :return: ContainerInfo class containing the container name and default entry point.
    """
    with docker_container_lock:
        # Get the container name and id.
        container_name = get_container_name(func_arn)

        LOG.debug('Priming docker container: %s', container_name)

        # Container is not running or doesn't exist.
        status = get_docker_container_status(func_arn)
        if status < 1:
            # Make sure the container does not exist in any form/state.
            destroy_docker_container(func_arn)

            env_vars_str = ' '.join(['-e {}={}'.format(k, cmd_quote(v)) for (k, v) in env_vars])

            # Create and start the container
            LOG.debug('Creating container: %s', container_name)
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
            run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

            LOG.debug('Copying files to container "%s" from "%s".', container_name, lambda_cwd)
            cmd = (
                'docker cp'
                ' "%s/." "%s:/var/task"'
            ) % (lambda_cwd, container_name)
            LOG.debug(cmd)
            run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

            LOG.debug('Starting container: %s', container_name)
            cmd = (
                'docker start'
                ' %s'
            ) % (container_name)
            LOG.debug(cmd)
            run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

        # Get the entry point for the image.
        LOG.debug('Getting the entrypoint for image: lambci/lambda:%s', runtime)
        cmd = (
            'docker image inspect'
            ' --format="{{ .ContainerConfig.Entrypoint }}"'
            ' lambci/lambda:%s'
        ) % (runtime)

        LOG.debug(cmd)
        run_result = run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

        entry_point = run_result.strip('[]\n\r ')

        LOG.debug('Using entrypoint "%s" for container "%s".', entry_point, container_name)
        return ContainerInfo(container_name, entry_point)


def destroy_docker_container(func_arn):
    """
    Stops and/or removes a docker container for a specific lambda function ARN.
    :param func_arn: The ARN of the lambda function.
    :return: None
    """
    with docker_container_lock:
        status = get_docker_container_status(func_arn)

        # Get the container name and id.
        container_name = get_container_name(func_arn)

        if status == 1:
            LOG.debug('Stopping container: %s', container_name)
            cmd = (
                'docker stop -t0 %s'
            ) % (container_name)

            LOG.debug(cmd)
            run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)

            status = get_docker_container_status(func_arn)

        if status == -1:
            LOG.debug('Removing container: %s', container_name)
            cmd = (
                'docker rm %s'
            ) % (container_name)

            LOG.debug(cmd)
            run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)


def get_all_container_names():
    """
    Returns a list of container names for lambda containers.
    :return: A String[] localstack docker container names for each function.
    """
    with docker_container_lock:
        LOG.debug('Getting all lambda containers names.')
        cmd = 'docker ps -a --filter="name=localstack_lambda_*" --format "{{.Names}}"'
        LOG.debug(cmd)
        cmd_result = run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE).strip()

        if len(cmd_result) > 0:
            container_names = cmd_result.split('\n')
        else:
            container_names = []

        return container_names


def destroy_existing_docker_containers():
    """
    Stops and/or removes all lambda docker containers for localstack.
    :return: None
    """
    with docker_container_lock:
        container_names = get_all_container_names()

        LOG.debug('Removing %d containers.' % len(container_names))
        for container_name in container_names:
            cmd = 'docker rm -f %s' % container_name
            LOG.debug(cmd)
            run(cmd, async=False, stderr=subprocess.PIPE, outfile=subprocess.PIPE)


def get_docker_container_status(func_arn):
    """
    Determine the status of a docker container.
    :param func_arn: The ARN of the lambda function.
    :return: 1 If the container is running,
    -1 if the container exists but is not running
    0 if the container does not exist.
    """
    with docker_container_lock:
        # Get the container name and id.
        container_name = get_container_name(func_arn)

        # Check if the container is already running.
        LOG.debug('Getting container status: %s', container_name)
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


def idle_container_destroyer():
    """
    Iterates though all the lambda containers and destroys any container that has been inactive for longer than 10min.
    :return: None
    """
    LOG.info('Checking if there are idle containers.')
    current_time = time.time()
    for func_arn, last_run_time in function_invoke_times.items():
        duration = current_time - last_run_time

        # not enough idle time has passed
        if duration < 600:
            continue

        # container has been idle, destroy it.
        destroy_docker_container(func_arn)


def start_idle_container_destroyer_interval():
    """
    Starts a repeating timer that triggers start_idle_container_destroyer_interval every 60 seconds.
    Thus checking for idle containers and destroying them.
    :return: None
    """
    idle_container_destroyer()
    threading.Timer(60.0, start_idle_container_destroyer_interval).start()


def get_container_name(func_arn):
    """
    Given a function ARN, returns a valid docker container name.
    :param func_arn: The ARN of the lambda function.
    :return: A docker compatible name for the arn.
    """
    return 'localstack_lambda_' + re.sub(r'[^a-zA-Z0-9_.-]', '_', func_arn)


def run_lambda_executor(cmd, env_vars={}, async=False):
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


def set_function_code(code, lambda_name):

    def generic_handler(event, context):
        raise Exception(('Unable to find executor for Lambda function "%s". ' +
            'Note that Node.js Lambdas currently require LAMBDA_EXECUTOR=docker') % lambda_name)

    lambda_handler = generic_handler
    lambda_cwd = None
    arn = func_arn(lambda_name)
    runtime = arn_to_lambda[arn].runtime
    handler_name = arn_to_lambda.get(arn).handler
    lambda_environment = arn_to_lambda.get(arn).envvars
    if not handler_name:
        handler_name = LAMBDA_DEFAULT_HANDLER
    handler_file = get_handler_file_from_name(handler_name, runtime=runtime)
    handler_function = get_handler_function_from_name(handler_name, runtime=runtime)

    # Stop/remove any containers that this arn uses.
    destroy_docker_container(arn)

    if 'S3Bucket' in code:
        s3_client = aws_stack.connect_to_service('s3')
        bytes_io = BytesIO()
        try:
            s3_client.download_fileobj(code['S3Bucket'], code['S3Key'], bytes_io)
            zip_file_content = bytes_io.getvalue()
        except Exception as e:
            return error_response('Unable to fetch Lambda archive from S3: %s' % e, 404)
    elif 'ZipFile' in code:
        zip_file_content = code['ZipFile']
        zip_file_content = base64.b64decode(zip_file_content)
    else:
        return error_response('No valid Lambda archive specified.', 400)

    # save tmp file
    tmp_dir = '%s/zipfile.%s' % (config.TMP_FOLDER, short_uid())
    run('mkdir -p %s' % tmp_dir)
    tmp_file = '%s/%s' % (tmp_dir, LAMBDA_ZIP_FILE_NAME)
    save_file(tmp_file, zip_file_content)
    TMP_FILES.append(tmp_dir)
    lambda_cwd = tmp_dir

    # check if this is a ZIP file
    is_zip = is_zip_file(zip_file_content)
    if is_zip:
        unzip(tmp_file, tmp_dir)
        main_file = '%s/%s' % (tmp_dir, handler_file)
        if not os.path.isfile(main_file):
            # check if this is a zip file that contains a single JAR file
            jar_files = glob.glob('%s/*.jar' % tmp_dir)
            if len(jar_files) == 1:
                main_file = jar_files[0]
        if os.path.isfile(main_file):
            with open(main_file, 'rb') as file_obj:
                zip_file_content = file_obj.read()
        else:
            file_list = run('ls -la %s' % tmp_dir)
            LOG.debug('Lambda archive content:\n%s' % file_list)
            return error_response('Unable to find handler script in Lambda archive.', 400, error_type='ValidationError')

    # it could be a JAR file (regardless of whether wrapped in a ZIP file or not)
    is_jar = is_jar_archive(zip_file_content)
    if is_jar:

        def execute(event, context):
            event_file = EVENT_FILE_PATTERN.replace('*', short_uid())
            save_file(event_file, json.dumps(event))
            TMP_FILES.append(event_file)
            class_name = arn_to_lambda[arn].handler.split('::')[0]
            classpath = '%s:%s' % (LAMBDA_EXECUTOR_JAR, main_file)
            cmd = 'java -cp %s %s %s %s' % (classpath, LAMBDA_EXECUTOR_CLASS, class_name, event_file)
            async = False
            # flip async flag depending on origin
            if 'Records' in event:
                # TODO: add more event supporting async lambda execution
                if 'Sns' in event['Records'][0]:
                    async = True
            result, log_output = run_lambda_executor(cmd, async=async)
            LOG.info('Lambda output: %s' % log_output.replace('\n', '\n> '))
            return result

        lambda_handler = execute

    elif runtime.startswith('python') and not use_docker():
        try:
            lambda_handler = exec_lambda_code(zip_file_content,
                handler_function=handler_function, lambda_cwd=lambda_cwd,
                lambda_env=lambda_environment)
        except Exception as e:
            raise Exception('Unable to get handler function from lambda code.', e)

    if not is_zip and not is_jar:
        raise Exception('Uploaded Lambda code is neither a ZIP nor JAR file.')

    add_function_mapping(lambda_name, lambda_handler, lambda_cwd)

    return {'FunctionName': lambda_name}


def do_list_functions():
    funcs = []
    for f_arn, func in iteritems(arn_to_lambda):
        func_name = f_arn.split(':function:')[-1]
        arn = func_arn(func_name)
        funcs.append({
            'Version': '$LATEST',
            'CodeSize': arn_to_lambda.get(arn).get_version('$LATEST').get('CodeSize'),
            'FunctionName': func_name,
            'FunctionArn': f_arn,
            'Handler': arn_to_lambda.get(arn).handler,
            'Runtime': arn_to_lambda.get(arn).runtime,
            'Timeout': LAMBDA_DEFAULT_TIMEOUT,
            # 'Description': ''
            # 'MemorySize': 192,
        })
    return funcs


@app.route('%s/functions' % PATH_ROOT, methods=['POST'])
def create_function():
    """ Create new function
        ---
        operationId: 'createFunction'
        parameters:
            - name: 'request'
              in: body
    """
    arn = 'n/a'
    try:
        data = json.loads(to_str(request.data))
        lambda_name = data['FunctionName']
        event_publisher.fire_event(event_publisher.EVENT_LAMBDA_CREATE_FUNC,
            payload={'n': event_publisher.get_hash(lambda_name)})
        arn = func_arn(lambda_name)
        if arn in arn_to_lambda:
            return error_response('Function already exist: %s' %
                lambda_name, 409, error_type='ResourceConflictException')
        arn_to_lambda[arn] = LambdaFunction(arn)
        arn_to_lambda[arn].versions = {'$LATEST': {'CodeSize': 50}}
        arn_to_lambda[arn].handler = data['Handler']
        arn_to_lambda[arn].runtime = data['Runtime']
        arn_to_lambda[arn].envvars = data.get('Environment', {}).get('Variables', {})
        result = set_function_code(data['Code'], lambda_name)
        if isinstance(result, Response):
            del arn_to_lambda[arn]
            return result
        result.update({
            'DeadLetterConfig': data.get('DeadLetterConfig'),
            'Description': data.get('Description'),
            'Environment': {'Error': {}, 'Variables': arn_to_lambda[arn].envvars},
            'FunctionArn': arn,
            'FunctionName': lambda_name,
            'Handler': arn_to_lambda[arn].handler,
            'MemorySize': data.get('MemorySize'),
            'Role': data.get('Role'),
            'Runtime': arn_to_lambda[arn].runtime,
            'Timeout': data.get('Timeout'),
            'TracingConfig': {},
            'VpcConfig': {'SecurityGroupIds': [None], 'SubnetIds': [None], 'VpcId': None}
        })
        return jsonify(result or {})
    except Exception as e:
        del arn_to_lambda[arn]
        return error_response('Unknown error: %s' % e)


@app.route('%s/functions/<function>' % PATH_ROOT, methods=['GET'])
def get_function(function):
    """ Get details for a single function
        ---
        operationId: 'getFunction'
        parameters:
            - name: 'request'
              in: body
            - name: 'function'
              in: path
    """
    funcs = do_list_functions()
    for func in funcs:
        if func['FunctionName'] == function:
            result = {
                'Configuration': func,
                'Code': {
                    'Location': '%s/code' % request.url
                }
            }
            return jsonify(result)
    result = {
        'ResponseMetadata': {
            'HTTPStatusCode': 404
        }
    }
    return make_response((jsonify(result), 404, {}))


@app.route('%s/functions/' % PATH_ROOT, methods=['GET'])
def list_functions():
    """ List functions
        ---
        operationId: 'listFunctions'
        parameters:
            - name: 'request'
              in: body
    """
    funcs = do_list_functions()
    result = {}
    result['Functions'] = funcs
    return jsonify(result)


@app.route('%s/functions/<function>' % PATH_ROOT, methods=['DELETE'])
def delete_function(function):
    """ Delete an existing function
        ---
        operationId: 'deleteFunction'
        parameters:
            - name: 'request'
              in: body
    """
    arn = func_arn(function)

    # Stop/remove any containers that this arn uses.
    destroy_docker_container(arn)

    try:
        arn_to_lambda.pop(arn)
    except KeyError:
        return error_response('Function does not exist: %s' % function, 404, error_type='ResourceNotFoundException')

    event_publisher.fire_event(event_publisher.EVENT_LAMBDA_DELETE_FUNC,
        payload={'n': event_publisher.get_hash(function)})
    i = 0
    while i < len(event_source_mappings):
        mapping = event_source_mappings[i]
        if mapping['FunctionArn'] == arn:
            del event_source_mappings[i]
            i -= 1
        i += 1
    result = {}
    return jsonify(result)


@app.route('%s/functions/<function>/code' % PATH_ROOT, methods=['PUT'])
def update_function_code(function):
    """ Update the code of an existing function
        ---
        operationId: 'updateFunctionCode'
        parameters:
            - name: 'request'
              in: body
    """
    data = json.loads(to_str(request.data))
    result = set_function_code(data, function)
    return jsonify(result or {})


@app.route('%s/functions/<function>/code' % PATH_ROOT, methods=['GET'])
def get_function_code(function):
    """ Get the code of an existing function
        ---
        operationId: 'getFunctionCode'
        parameters:
    """
    arn = func_arn(function)
    lambda_cwd = arn_to_lambda[arn].cwd
    tmp_file = '%s/%s' % (lambda_cwd, LAMBDA_ZIP_FILE_NAME)
    return Response(load_file(tmp_file, mode='rb'),
            mimetype='application/zip',
            headers={'Content-Disposition': 'attachment; filename=lambda_archive.zip'})


@app.route('%s/functions/<function>/configuration' % PATH_ROOT, methods=['GET'])
def get_function_configuration(function):
    """ Get the configuration of an existing function
        ---
        operationId: 'getFunctionConfiguration'
        parameters:
    """
    arn = func_arn(function)
    lambda_details = arn_to_lambda.get(arn)
    if not lambda_details:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    result = {
        'Version': '$LATEST',
        'FunctionName': function,
        'FunctionArn': arn,
        'Handler': lambda_details.handler,
        'Runtime': lambda_details.runtime,
        'Timeout': LAMBDA_DEFAULT_TIMEOUT,
        'Environment': lambda_details.envvars
    }
    return jsonify(result)


@app.route('%s/functions/<function>/configuration' % PATH_ROOT, methods=['PUT'])
def update_function_configuration(function):
    """ Update the configuration of an existing function
        ---
        operationId: 'updateFunctionConfiguration'
        parameters:
            - name: 'request'
              in: body
    """
    data = json.loads(to_str(request.data))
    arn = func_arn(function)

    # Stop/remove any containers that this arn uses.
    destroy_docker_container(arn)

    if data.get('Handler'):
        arn_to_lambda[arn].handler = data['Handler']
    if data.get('Runtime'):
        arn_to_lambda[arn].runtime = data['Runtime']
    if data.get('Environment'):
        arn_to_lambda[arn].envvars = data.get('Environment', {}).get('Variables', {})
    result = {}
    return jsonify(result)


@app.route('%s/functions/<function>/invocations' % PATH_ROOT, methods=['POST'])
def invoke_function(function):
    """ Invoke an existing function
        ---
        operationId: 'invokeFunction'
        parameters:
            - name: 'request'
              in: body
    """
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function does not exist: %s' % arn, 404, error_type='ResourceNotFoundException')
    qualifier = request.args['Qualifier'] if 'Qualifier' in request.args else '$LATEST'
    if not arn_to_lambda.get(arn).qualifier_exists(qualifier):
        return error_response('Function does not exist: {0}:{1}'.format(arn, qualifier), 404,
                              error_type='ResourceNotFoundException')
    lambda_function = arn_to_lambda.get(arn).function(qualifier)
    data = None
    if request.data:
        try:
            data = json.loads(to_str(request.data))
        except Exception:
            return error_response('The payload is not JSON', 415, error_type='UnsupportedMediaTypeException')
    async = False
    if 'HTTP_X_AMZ_INVOCATION_TYPE' in request.environ:
        async = request.environ['HTTP_X_AMZ_INVOCATION_TYPE'] == 'Event'
    result = run_lambda(lambda_function, async=async, func_arn=arn, event=data, context={})
    if isinstance(result, dict):
        return jsonify(result)
    if result:
        return result
    return make_response('', 200)


@app.route('%s/event-source-mappings/' % PATH_ROOT, methods=['GET'])
def list_event_source_mappings():
    """ List event source mappings
        ---
        operationId: 'listEventSourceMappings'
    """
    event_source_arn = request.args.get('EventSourceArn')
    function_name = request.args.get('FunctionName')

    mappings = event_source_mappings
    if event_source_arn:
        mappings = [m for m in mappings if event_source_arn == m.get('EventSourceArn')]
    if function_name:
        function_arn = func_arn(function_name)
        mappings = [m for m in mappings if function_arn == m.get('FunctionArn')]

    response = {
        'EventSourceMappings': mappings
    }
    return jsonify(response)


@app.route('%s/event-source-mappings/' % PATH_ROOT, methods=['POST'])
def create_event_source_mapping():
    """ Create new event source mapping
        ---
        operationId: 'createEventSourceMapping'
        parameters:
            - name: 'request'
              in: body
    """
    data = json.loads(to_str(request.data))
    mapping = add_event_source(data['FunctionName'], data['EventSourceArn'])
    return jsonify(mapping)


@app.route('%s/event-source-mappings/<mapping_uuid>' % PATH_ROOT, methods=['PUT'])
def update_event_source_mapping(mapping_uuid):
    """ Update an existing event source mapping
        ---
        operationId: 'updateEventSourceMapping'
        parameters:
            - name: 'request'
              in: body
    """
    data = json.loads(request.data)
    if not mapping_uuid:
        return jsonify({})
    function_name = data.get('FunctionName') or ''
    enabled = data.get('Enabled') or True
    batch_size = data.get('BatchSize') or 100
    mapping = update_event_source(mapping_uuid, function_name, enabled, batch_size)
    return jsonify(mapping)


@app.route('%s/event-source-mappings/<mapping_uuid>' % PATH_ROOT, methods=['DELETE'])
def delete_event_source_mapping(mapping_uuid):
    """ Delete an event source mapping
        ---
        operationId: 'deleteEventSourceMapping'
    """
    if not mapping_uuid:
        return jsonify({})

    mapping = delete_event_source(mapping_uuid)
    return jsonify(mapping)


@app.route('%s/functions/<function>/versions' % PATH_ROOT, methods=['POST'])
def publish_version(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    return jsonify(publish_new_function_version(arn))


@app.route('%s/functions/<function>/versions' % PATH_ROOT, methods=['GET'])
def list_versions(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    return jsonify({'Versions': do_list_versions(arn)})


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['POST'])
def create_alias(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    data = json.loads(request.data)
    alias = data.get('Name')
    if alias in arn_to_lambda.get(arn).aliases:
        return error_response('Alias already exists: %s' % arn + ':' + alias, 404,
                              error_type='ResourceConflictException')
    version = data.get('FunctionVersion')
    description = data.get('Description')
    return jsonify(do_update_alias(arn, alias, version, description))


@app.route('%s/functions/<function>/aliases/<name>' % PATH_ROOT, methods=['PUT'])
def update_alias(function, name):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    if name not in arn_to_lambda.get(arn).aliases:
        return error_response('Alias not found: %s' % arn + ':' + name, 404,
                              error_type='ResourceNotFoundException')
    current_alias = arn_to_lambda.get(arn).aliases.get(name)
    data = json.loads(request.data)
    version = data.get('FunctionVersion') or current_alias.get('FunctionVersion')
    description = data.get('Description') or current_alias.get('Description')
    return jsonify(do_update_alias(arn, name, version, description))


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['GET'])
def list_aliases(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    return jsonify({'Aliases': sorted(arn_to_lambda.get(arn).aliases.values(),
                                      key=lambda x: x['Name'])})


def serve(port, quiet=True):
    # destroy existing containers.
    destroy_existing_docker_containers()

    # start a process to remove idle containers
    start_idle_container_destroyer_interval()

    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
