#!/usr/bin/env python
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
from six import iteritems
from six.moves import cStringIO as StringIO
from flask import Flask, Response, jsonify, request, make_response
from localstack import config
from localstack.constants import *
from localstack.services.generic_proxy import GenericProxy
from localstack.utils.common import *
from localstack.utils.aws import aws_stack
from localstack.utils.cloudwatch.cloudwatch_util import cloudwatched


APP_NAME = 'lambda_api'
PATH_ROOT = '/2015-03-31'
ARCHIVE_FILE_PATTERN = '%s/lambda.handler.*.jar' % config.TMP_FOLDER
EVENT_FILE_PATTERN = '%s/lambda.event.*.json' % config.TMP_FOLDER
LAMBDA_SCRIPT_PATTERN = '%s/lambda_script_*.py' % config.TMP_FOLDER
LAMBDA_EXECUTOR_JAR = os.path.join(LOCALSTACK_ROOT_FOLDER, 'localstack',
    'infra', 'localstack-utils.jar')
LAMBDA_EXECUTOR_CLASS = 'com.atlassian.localstack.LambdaExecutor'

LAMBDA_RUNTIME_PYTHON27 = 'python2.7'
LAMBDA_RUNTIME_NODEJS = 'nodejs'
LAMBDA_RUNTIME_NODEJS610 = 'nodejs6.10'
LAMBDA_RUNTIME_JAVA8 = 'java8'

LAMBDA_DEFAULT_HANDLER = 'handler.handler'
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON27
LAMBDA_DEFAULT_STARTING_POSITION = 'LATEST'
LAMBDA_DEFAULT_TIMEOUT = 60
LAMBDA_ZIP_FILE_NAME = 'original_lambda_archive.zip'

# local maven repository path
M2_HOME = '$HOME/.m2'
# hack required for Docker because our base image uses $HOME/.m2 as a volume (see Dockerfile)
if '/root/.m2_persistent' in os.environ.get('MAVEN_OPTS', ''):
    M2_HOME = '/root/.m2_persistent'
# TODO: temporary hack! Remove all hardcoded paths (and move to lamb-ci Docker for Java once it's available)
JAR_DEPENDENCIES = [
    'com/amazonaws/aws-lambda-java-core/1.1.0/aws-lambda-java-core-1.1.0.jar',
    'com/amazonaws/aws-lambda-java-events/1.3.0/aws-lambda-java-events-1.3.0.jar',
    'com/amazonaws/aws-java-sdk-kinesis/1.11.86/aws-java-sdk-kinesis-1.11.86.jar',
    'com/fasterxml/jackson/core/jackson-databind/2.6.6/jackson-databind-2.6.6.jar',
    'com/fasterxml/jackson/core/jackson-core/2.6.6/jackson-core-2.6.6.jar',
    'com/fasterxml/jackson/core/jackson-annotations/2.6.0/jackson-annotations-2.6.0.jar',
    'commons-codec/commons-codec/1.9/commons-codec-1.9.jar',
    'commons-io/commons-io/2.5/commons-io-2.5.jar',
    'org/apache/commons/commons-lang3/3.5/commons-lang3-3.5.jar'
]

# IP address of Docker bridge
DOCKER_BRIDGE_IP = '172.17.0.1'

app = Flask(APP_NAME)

# map ARN strings to lambda function objects
# TODO: create a single map for function details
lambda_arn_to_function = {}
lambda_arn_to_cwd = {}
lambda_arn_to_handler = {}
lambda_arn_to_runtime = {}

# list of event source mappings for the API
event_source_mappings = []

# logger
LOG = logging.getLogger(__name__)

# mutex for access to CWD
cwd_mutex = threading.Semaphore(1)

# whether to use Docker for execution
DO_USE_DOCKER = None


def cleanup():
    global lambda_arn_to_function, event_source_mappings, lambda_arn_to_cwd, lambda_arn_to_handler
    # reset the state
    lambda_arn_to_function = {}
    lambda_arn_to_cwd = {}
    lambda_arn_to_handler = {}
    lambda_arn_to_runtime = {}
    event_source_mappings = []


def func_arn(function_name):
    return aws_stack.lambda_function_arn(function_name)


def add_function_mapping(lambda_name, lambda_handler, lambda_cwd=None):
    arn = func_arn(lambda_name)
    lambda_arn_to_function[arn] = lambda_handler
    lambda_arn_to_cwd[arn] = lambda_cwd


def add_event_source(function_name, source_arn):
    mapping = {
        "UUID": str(uuid.uuid4()),
        "StateTransitionReason": "User action",
        "LastModified": float(time.mktime(datetime.utcnow().timetuple())),
        "BatchSize": 100,
        "State": "Enabled",
        "FunctionArn": func_arn(function_name),
        "EventSourceArn": source_arn,
        "LastProcessingResult": "OK",
        "StartingPosition": LAMBDA_DEFAULT_STARTING_POSITION
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
        if uuid_value == m['uuid']:
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
            except Exception as e:
                pass
    return DO_USE_DOCKER


def in_docker():
    """ Returns: True if running in a docker container, else False """
    if not os.path.exists('/proc/1/cgroup'):
        return False
    with open('/proc/1/cgroup', 'rt') as ifh:
        return 'docker' in ifh.read()


def process_apigateway_invocation(func_arn, path, payload, headers={}, path_params={}):
    try:
        lambda_function = lambda_arn_to_function[func_arn]
        event = {
            'path': path,
            'headers': dict(headers),
            'pathParameters': dict(path_params),
            'body': payload,
            'isBase64Encoded': False,
            'resource': 'TODO',
            'httpMethod': 'TODO',
            'queryStringParameters': {},  # TODO
            'stageVariables': {}  # TODO
        }
        return run_lambda(lambda_function, event=event, context={}, func_arn=func_arn)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on API Gateway message: %s %s' % (e, traceback.format_exc()))


def process_sns_notification(func_arn, topic_arn, message, subject=''):
    try:
        lambda_function = lambda_arn_to_function[func_arn]
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
        run_lambda(lambda_function, event=event, context={}, func_arn=func_arn)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on SNS message: %s %s' % (e, traceback.format_exc()))


def process_kinesis_records(records, stream_name):
    # feed records into listening lambdas
    try:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        sources = get_event_sources(source_arn=stream_arn)
        for source in sources:
            arn = source['FunctionArn']
            lambda_function = lambda_arn_to_function[arn]
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


def get_host_path_for_path_in_docker(path):
    return re.sub(r'^%s/(.*)$' % config.TMP_FOLDER,
                r'%s/\1' % config.HOST_TMP_FOLDER, path)


@cloudwatched('lambda')
def run_lambda(func, event, context, func_arn, suppress_output=False):
    if suppress_output:
        stdout_ = sys.stdout
        stderr_ = sys.stderr
        stream = StringIO()
        sys.stdout = stream
        sys.stderr = stream
    lambda_cwd = lambda_arn_to_cwd.get(func_arn)
    result = None
    try:
        runtime = lambda_arn_to_runtime.get(func_arn)
        handler = lambda_arn_to_handler.get(func_arn)
        if use_docker():
            handler_args = '"%s"' % handler
            entrypoint = ''

            # if running a Java Lambda, set up classpath arguments
            if runtime == LAMBDA_RUNTIME_JAVA8:
                # TODO cleanup once we have custom Java Docker image
                event_file = 'event_file.json'  # TODO
                handler_args = ("java -cp .:`ls *.jar | tr '\\n' ':'` '%s' '%s' '%s'" %
                    (LAMBDA_EXECUTOR_CLASS, handler, event_file))
                entrypoint = ' --entrypoint ""'

            if config.LAMBDA_REMOTE_DOCKER:
                cmd = (
                    'CONTAINER_ID="$(docker create'
                    '%s -e AWS_LAMBDA_EVENT_BODY="$AWS_LAMBDA_EVENT_BODY"'
                    ' -e HOSTNAME="$HOSTNAME"'
                    ' "lambci/lambda:%s" %s'
                    ')";'
                    'docker cp "%s/." "$CONTAINER_ID:/var/task";'
                    'docker start -a "$CONTAINER_ID";'
                ) % (entrypoint, runtime, handler_args, lambda_cwd)
            else:
                lambda_cwd_on_host = get_host_path_for_path_in_docker(lambda_cwd)
                cmd = (
                    'docker run'
                    '%s -v "%s":/var/task'
                    ' -e AWS_LAMBDA_EVENT_BODY="$AWS_LAMBDA_EVENT_BODY"'
                    ' -e HOSTNAME="$HOSTNAME"'
                    ' "lambci/lambda:%s" %s'
                ) % (entrypoint, lambda_cwd_on_host, runtime, handler_args)

            print(cmd)
            # prepare event body
            if event is None or str(event).strip() == '':
                LOG.warning('Empty event body specified for invocation of Lambda "%s"' % func_arn)
                event_body = '{}'
            else:
                event_body = json.dumps(event).replace("'", "\\'")
            # lambci writes the Lambda result to stdout and logs to stderr, fetch it from there!
            process = run(cmd, env_vars={
                'AWS_LAMBDA_EVENT_BODY': event_body,
                'HOSTNAME': DOCKER_BRIDGE_IP,
            }, async=True, stderr=subprocess.PIPE, outfile=subprocess.PIPE)
            return_code = process.wait()
            result = process.stdout.read()
            log_output = process.stderr.read()
            LOG.debug('Lambda log output:\n%s' % log_output)
            if return_code != 0:
                raise Exception('Lambda process returned error status code: %s. Output:\n%s' %
                    (return_code, log_output))
        else:
            # execute the Lambda function in a forked sub-process, sync result via queue
            queue = Queue()

            def do_execute():
                # now we're executing in the child process, safe to change CWD
                if lambda_cwd:
                    os.chdir(lambda_cwd)
                result = func(event, context)
                queue.put(result)

            process = Process(target=do_execute)
            process.run()
            result = queue.get()

    except Exception as e:
        return error_response("Error executing Lambda function: %s %s" % (e, traceback.format_exc()))
    finally:
        if suppress_output:
            sys.stdout = stdout_
            sys.stderr = stderr_
    return result


def exec_lambda_code(script, handler_function='handler', lambda_cwd=None):
    if lambda_cwd:
        cwd_mutex.acquire()
        previous_cwd = os.getcwd()
        os.chdir(lambda_cwd)
        sys.path = [lambda_cwd] + sys.path
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
        if lambda_cwd:
            os.chdir(previous_cwd)
            sys.path.pop(0)
            cwd_mutex.release()
    return module_vars[handler_function]


def get_handler_file_from_name(handler_name, runtime=LAMBDA_RUNTIME_PYTHON27):
    # TODO: support Java Lambdas in the future
    file_ext = '.js' if runtime.startswith(LAMBDA_RUNTIME_NODEJS) else '.py'
    return '%s%s' % (handler_name.split('.')[0], file_ext)


def get_handler_function_from_name(handler_name, runtime=LAMBDA_RUNTIME_PYTHON27):
    # TODO: support Java Lambdas in the future
    return handler_name.split('.')[-1]


def error_response(msg, code=400, error_type='Exception'):
    LOG.warning(msg)
    result = {'Type': 'User', 'message': msg}
    headers = {'x-amzn-errortype': error_type}
    return make_response((jsonify(result), code, headers))


def set_function_code(code, lambda_name):

    def generic_handler(event, context):
        raise Exception(('Unable to find executor for Lambda function "%s". ' +
            'Note that non-Python Lambdas require LAMBDA_EXECUTOR=docker') % lambda_name)

    lambda_handler = generic_handler
    lambda_cwd = None
    arn = func_arn(lambda_name)
    runtime = lambda_arn_to_runtime[arn]
    handler_name = lambda_arn_to_handler.get(arn)
    if not handler_name:
        handler_name = LAMBDA_DEFAULT_HANDLER
    handler_file = get_handler_file_from_name(handler_name, runtime=runtime)
    handler_function = get_handler_function_from_name(handler_name, runtime=runtime)

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
        return error_response('No valid Lambda archive specified.')

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

        run('cd %s && unzip %s' % (tmp_dir, LAMBDA_ZIP_FILE_NAME))
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
            return error_response('Unable to find handler script in Lambda archive.')

    # it could be a JAR file (regardless of whether wrapped in a ZIP file or not)
    is_jar = is_jar_archive(zip_file_content)
    if is_jar:

        def execute(event, context):
            event_file = EVENT_FILE_PATTERN.replace('*', short_uid())
            save_file(event_file, json.dumps(event))
            TMP_FILES.append(event_file)
            class_name = lambda_arn_to_handler[arn].split('::')[0]
            classpath = '%s:%s' % (LAMBDA_EXECUTOR_JAR, main_file)
            for jar in JAR_DEPENDENCIES:
                jar_path = '%s/repository/%s' % (M2_HOME, jar)
                classpath += ':%s' % (jar_path)
            cmd = 'java -cp %s %s %s %s' % (classpath, LAMBDA_EXECUTOR_CLASS, class_name, event_file)
            output = run(cmd)
            LOG.info('Lambda output: %s' % output.replace('\n', '\n> '))
            return output

        lambda_handler = execute

    elif runtime.startswith('python') and not use_docker():
        try:
            lambda_handler = exec_lambda_code(zip_file_content,
                handler_function=handler_function, lambda_cwd=lambda_cwd)
        except Exception as e:
            raise Exception('Unable to get handler function from lambda code.', e)

    if not is_zip and not is_jar:
        raise Exception('Uploaded Lambda code is neither a ZIP nor JAR file.')

    add_function_mapping(lambda_name, lambda_handler, lambda_cwd)


def do_list_functions():
    funcs = []
    for f_arn, func in iteritems(lambda_arn_to_handler):
        func_name = f_arn.split(':function:')[-1]
        arn = func_arn(func_name)
        funcs.append({
            'Version': '$LATEST',
            'FunctionName': func_name,
            'FunctionArn': f_arn,
            'Handler': lambda_arn_to_handler.get(arn),
            'Runtime': lambda_arn_to_runtime.get(arn),
            'Timeout': LAMBDA_DEFAULT_TIMEOUT,
            # 'Description': ''
            # 'MemorySize': 192,
            # 'CodeSize': 2526917
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
    try:
        data = json.loads(to_str(request.data))
        lambda_name = data['FunctionName']
        arn = func_arn(lambda_name)
        if arn in lambda_arn_to_handler:
            return error_response('Function already exist: %s' %
                lambda_name, 409, error_type='ResourceConflictException')
        lambda_arn_to_handler[arn] = data['Handler']
        lambda_arn_to_runtime[arn] = data['Runtime']
        result = set_function_code(data['Code'], lambda_name)
        return result or jsonify({})
    except Exception as e:
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
    try:
        lambda_arn_to_handler.pop(arn)
    except KeyError:
        return error_response('Function does not exist: %s' % function, 404, error_type='ResourceNotFoundException')
    lambda_arn_to_cwd.pop(arn, None)
    lambda_arn_to_function.pop(arn, None)
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
    return result or jsonify({})


@app.route('%s/functions/<function>/code' % PATH_ROOT, methods=['GET'])
def get_function_code(function):
    """ Get the code of an existing function
        ---
        operationId: 'getFunctionCode'
        parameters:
    """
    arn = func_arn(function)
    lambda_cwd = lambda_arn_to_cwd[arn]
    tmp_file = '%s/%s' % (lambda_cwd, LAMBDA_ZIP_FILE_NAME)
    return Response(load_file(tmp_file, mode="rb"),
            mimetype='application/zip',
            headers={'Content-Disposition': 'attachment; filename=lambda_archive.zip'})


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
    if data.get('Handler'):
        lambda_arn_to_handler[arn] = data['Handler']
    if data.get('Runtime'):
        lambda_arn_to_runtime[arn] = data['Runtime']
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
    lambda_function = lambda_arn_to_function.get(arn)
    if not lambda_function:
        return error_response('Function does not exist: %s' % function, 404, error_type='ResourceNotFoundException')
    data = None
    if request.data:
        try:
            data = json.loads(to_str(request.data))
        except Exception as e:
            return error_response('The payload is not JSON', 415, error_type='UnsupportedMediaTypeException')
    result = run_lambda(lambda_function, func_arn=arn, event=data, context={})
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


def serve(port, quiet=True):
    if quiet:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
    ssl_context = GenericProxy.get_flask_ssl_context()
    app.run(port=int(port), threaded=True, host='0.0.0.0', ssl_context=ssl_context)


if __name__ == '__main__':
    port = DEFAULT_PORT_LAMBDA
    print("Starting server on port %s" % port)
    serve(port)
