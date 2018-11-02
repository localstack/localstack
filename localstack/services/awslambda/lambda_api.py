from __future__ import print_function

import re
import os
import imp
import sys
import json
import uuid
import time
import base64
import logging
import zipfile
import threading
import traceback
from io import BytesIO
from datetime import datetime
from six import iteritems
from six.moves import cStringIO as StringIO
from flask import Flask, Response, jsonify, request, make_response
from localstack import config
from localstack.services import generic_proxy
from localstack.services.awslambda import lambda_executors
from localstack.services.awslambda.lambda_executors import (
    LAMBDA_RUNTIME_PYTHON27,
    LAMBDA_RUNTIME_PYTHON36,
    LAMBDA_RUNTIME_NODEJS,
    LAMBDA_RUNTIME_NODEJS610,
    LAMBDA_RUNTIME_NODEJS810,
    LAMBDA_RUNTIME_JAVA8,
    LAMBDA_RUNTIME_DOTNETCORE2,
    LAMBDA_RUNTIME_GOLANG)
from localstack.utils.common import (to_str, load_file, save_file, TMP_FILES, ensure_readable,
    mkdir, unzip, is_zip_file, run, short_uid, is_jar_archive, timestamp, TIMESTAMP_FORMAT_MILLIS,
    md5, new_tmp_file)
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.analytics import event_publisher
from localstack.utils.cloudwatch.cloudwatch_util import cloudwatched
from localstack.utils.aws.aws_models import LambdaFunction

APP_NAME = 'lambda_api'
PATH_ROOT = '/2015-03-31'
ARCHIVE_FILE_PATTERN = '%s/lambda.handler.*.jar' % config.TMP_FOLDER
LAMBDA_SCRIPT_PATTERN = '%s/lambda_script_*.py' % config.TMP_FOLDER

# List of Lambda runtime names. Keep them in this list, mainly to silence the linter
LAMBDA_RUNTIMES = [LAMBDA_RUNTIME_PYTHON27, LAMBDA_RUNTIME_PYTHON36, LAMBDA_RUNTIME_DOTNETCORE2,
    LAMBDA_RUNTIME_NODEJS, LAMBDA_RUNTIME_NODEJS610, LAMBDA_RUNTIME_NODEJS810, LAMBDA_RUNTIME_JAVA8]

LAMBDA_DEFAULT_HANDLER = 'handler.handler'
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON27
LAMBDA_DEFAULT_STARTING_POSITION = 'LATEST'
LAMBDA_DEFAULT_TIMEOUT = 60
LAMBDA_ZIP_FILE_NAME = 'original_lambda_archive.zip'
LAMBDA_JAR_FILE_NAME = 'original_lambda_archive.jar'

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

# lambda executor instance
LAMBDA_EXECUTOR = lambda_executors.AVAILABLE_EXECUTORS.get(config.LAMBDA_EXECUTOR, lambda_executors.DEFAULT_EXECUTOR)


class LambdaContext(object):

    def __init__(self, func_details, qualifier=None):
        self.function_name = func_details.name()
        self.function_version = func_details.get_qualifier_version(qualifier)

        self.invoked_function_arn = func_details.arn()
        if qualifier:
            self.invoked_function_arn += ':' + qualifier

    def get_remaining_time_in_millis(self):
        # TODO implement!
        return 1000 * 60


def cleanup():
    global event_source_mappings, arn_to_lambda
    arn_to_lambda = {}
    event_source_mappings = []
    LAMBDA_EXECUTOR.cleanup()


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
        if 'docker' in config.LAMBDA_EXECUTOR:
            try:
                run('docker images', print_error=False)
                # run('ping -c 1 -t 1 %s' % DOCKER_BRIDGE_IP, print_error=False)
                DO_USE_DOCKER = True
            except Exception:
                pass
    return DO_USE_DOCKER


def process_apigateway_invocation(func_arn, path, payload, headers={},
        resource_path=None, method=None, path_params={},
        query_string_params={}, request_context={}):
    try:
        resource_path = resource_path or path
        event = {
            'path': path,
            'headers': dict(headers),
            'pathParameters': dict(path_params),
            'body': payload,
            'isBase64Encoded': False,
            'resource': resource_path,
            'httpMethod': method,
            'queryStringParameters': query_string_params,
            'requestContext': request_context,
            'stageVariables': {}  # TODO
        }
        return run_lambda(event=event, context={}, func_arn=func_arn)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on API Gateway message: %s %s' % (e, traceback.format_exc()))


def process_sns_notification(func_arn, topic_arn, message, subject=''):
    try:
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
        return run_lambda(event=event, context={}, func_arn=func_arn, asynchronous=True)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on SNS message: %s %s' % (e, traceback.format_exc()))


def process_kinesis_records(records, stream_name):
    # feed records into listening lambdas
    try:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        sources = get_event_sources(source_arn=stream_arn)
        for source in sources:
            arn = source['FunctionArn']
            event = {
                'Records': []
            }
            for rec in records:
                event['Records'].append({
                    'eventID': 'shardId-000000000000:{0}'.format(rec['sequenceNumber']),
                    'eventSourceARN': stream_arn,
                    'kinesis': rec
                })
            run_lambda(event=event, context={}, func_arn=arn)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on Kinesis records: %s %s' % (e, traceback.format_exc()))


def process_sqs_message(message_body, queue_name):
    # feed message into the first listening lambda
    try:
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        source = next(iter(get_event_sources(source_arn=queue_arn)), None)
        if source:
            arn = source['FunctionArn']
            event = {'Records': [{
                'body': message_body,
                'receiptHandle': 'MessageReceiptHandle',
                'md5OfBody': md5(message_body),
                'eventSourceARN': queue_arn,
                'eventSource': 'aws:sqs',
                'awsRegion': aws_stack.get_local_region(),
                'messageId': str(uuid.uuid4()),
                'attributes': {
                    'ApproximateFirstReceiveTimestamp': '{}000'.format(int(time.time())),
                    'SenderId': '123456789012',
                    'ApproximateReceiveCount': '1',
                    'SentTimestamp': '{}000'.format(int(time.time()))
                },
                'messageAttributes': {},
                'sqs': True,
            }]}
            run_lambda(event=event, context={}, func_arn=arn)
            return True
    except Exception as e:
        LOG.warning('Unable to run Lambda function on SQS messages: %s %s' % (e, traceback.format_exc()))


def get_event_sources(func_name=None, source_arn=None):
    result = []
    for m in event_source_mappings:
        if not func_name or m['FunctionArn'] in [func_name, func_arn(func_name)]:
            if not source_arn or m['EventSourceArn'].startswith(source_arn):
                result.append(m)
    return result


def get_function_version(arn, version):
    func = arn_to_lambda.get(arn)
    return format_func_details(func, version=version, always_add_version=True)


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


@cloudwatched('lambda')
def run_lambda(event, context, func_arn, version=None, suppress_output=False, asynchronous=False):
    if suppress_output:
        stdout_ = sys.stdout
        stderr_ = sys.stderr
        stream = StringIO()
        sys.stdout = stream
        sys.stderr = stream
    try:
        func_details = arn_to_lambda.get(func_arn)
        if not context:
            context = LambdaContext(func_details, version)
        result, log_output = LAMBDA_EXECUTOR.execute(func_arn, func_details,
            event, context=context, version=version, asynchronous=asynchronous)
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


def get_handler_file_from_name(handler_name, runtime=LAMBDA_DEFAULT_RUNTIME):
    # TODO: support Java Lambdas in the future
    delimiter = '.'
    if runtime.startswith(LAMBDA_RUNTIME_NODEJS):
        file_ext = '.js'
    elif runtime.startswith(LAMBDA_RUNTIME_GOLANG):
        file_ext = ''
    elif runtime.startswith(LAMBDA_RUNTIME_DOTNETCORE2):
        file_ext = '.dll'
        delimiter = ':'
    else:
        file_ext = '.py'
    return '%s%s' % (handler_name.split(delimiter)[0], file_ext)


def get_handler_function_from_name(handler_name, runtime=LAMBDA_DEFAULT_RUNTIME):
    # TODO: support Java Lambdas in the future
    if runtime.startswith(LAMBDA_RUNTIME_DOTNETCORE2):
        return handler_name.split(':')[-1]
    else:
        return handler_name.split('.')[-1]


def error_response(msg, code=500, error_type='InternalFailure'):
    LOG.warning(msg)
    return aws_responses.flask_error_response(msg, code=code, error_type=error_type)


def get_zip_bytes(function_code):
    """Returns the ZIP file contents from a FunctionCode dict.

    :type function_code: dict
    :param function_code: https://docs.aws.amazon.com/lambda/latest/dg/API_FunctionCode.html
    :returns: bytes of the Zip file.
    """
    if 'S3Bucket' in function_code:
        s3_client = aws_stack.connect_to_service('s3')
        bytes_io = BytesIO()
        try:
            s3_client.download_fileobj(function_code['S3Bucket'], function_code['S3Key'], bytes_io)
            zip_file_content = bytes_io.getvalue()
        except Exception as e:
            return error_response('Unable to fetch Lambda archive from S3: %s' % e, 404)
    elif 'ZipFile' in function_code:
        zip_file_content = function_code['ZipFile']
        zip_file_content = base64.b64decode(zip_file_content)
    else:
        return error_response('No valid Lambda archive specified.', 400)
    return zip_file_content


def get_java_handler(zip_file_content, handler, main_file):
    """Creates a Java handler from an uploaded ZIP or JAR.

    :type zip_file_content: bytes
    :param zip_file_content: ZIP file bytes.
    :type handler: str
    :param handler: The lambda handler path.
    :type main_file: str
    :param main_file: Filepath to the uploaded ZIP or JAR file.

    :returns: function or flask.Response
    """
    if not is_jar_archive(zip_file_content):
        with zipfile.ZipFile(BytesIO(zip_file_content)) as zip_ref:
            jar_entries = [e for e in zip_ref.infolist() if e.filename.endswith('.jar')]
            if len(jar_entries) != 1:
                raise Exception('Expected exactly one *.jar entry in zip file, found %s' % len(jar_entries))
            zip_file_content = zip_ref.read(jar_entries[0].filename)
            LOG.info('Found jar file %s with %s bytes in Lambda zip archive' %
                     (jar_entries[0].filename, len(zip_file_content)))
            main_file = new_tmp_file()
            save_file(main_file, zip_file_content)
    if is_jar_archive(zip_file_content):
        def execute(event, context):
            result, log_output = lambda_executors.EXECUTOR_LOCAL.execute_java_lambda(
                event, context, handler=handler, main_file=main_file)
            return result
        return execute
    return error_response(
        'Unable to extract Java Lambda handler - file is not a valid zip/jar files', 400, error_type='ValidationError')


def set_function_code(code, lambda_name):

    def generic_handler(event, context):
        raise Exception(('Unable to find executor for Lambda function "%s". ' +
            'Note that Node.js and .NET Core Lambdas currently require LAMBDA_EXECUTOR=docker') % lambda_name)

    lambda_cwd = None
    arn = func_arn(lambda_name)
    runtime = arn_to_lambda[arn].runtime
    handler_name = arn_to_lambda.get(arn).handler
    lambda_environment = arn_to_lambda.get(arn).envvars
    if not handler_name:
        handler_name = LAMBDA_DEFAULT_HANDLER

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(arn)

    # Save the zip file to a temporary file that the lambda executors can reference.
    zip_file_content = get_zip_bytes(code)
    if isinstance(zip_file_content, Response):
        return zip_file_content
    tmp_dir = '%s/zipfile.%s' % (config.TMP_FOLDER, short_uid())
    mkdir(tmp_dir)
    tmp_file = '%s/%s' % (tmp_dir, LAMBDA_ZIP_FILE_NAME)
    save_file(tmp_file, zip_file_content)
    TMP_FILES.append(tmp_dir)
    lambda_cwd = tmp_dir

    # Set the appropriate lambda handler.
    lambda_handler = generic_handler
    if runtime == LAMBDA_RUNTIME_JAVA8:
        # The Lambda executors for Docker subclass LambdaExecutorContainers,
        # which runs Lambda in Docker by passing all *.jar files in the function
        # working directory as part of the classpath. Because of this, we need to
        # save the zip_file_content as a .jar here.
        if is_jar_archive(zip_file_content):
            jar_tmp_file = '{working_dir}/{file_name}'.format(
                working_dir=tmp_dir, file_name=LAMBDA_JAR_FILE_NAME)
            save_file(jar_tmp_file, zip_file_content)

        lambda_handler = get_java_handler(zip_file_content, handler_name, tmp_file)
        if isinstance(lambda_handler, Response):
            return lambda_handler
    else:
        handler_file = get_handler_file_from_name(handler_name, runtime=runtime)
        handler_function = get_handler_function_from_name(handler_name, runtime=runtime)

        # Lambda code must be uploaded in the Zip format.
        if not is_zip_file(zip_file_content):
            raise Exception(
                'Uploaded Lambda code for runtime ({}) is not in Zip format'.format(runtime))

        unzip(tmp_file, tmp_dir)
        main_file = '%s/%s' % (tmp_dir, handler_file)
        if os.path.isfile(main_file):
            # make sure the file is actually readable, then read contents
            ensure_readable(main_file)
            with open(main_file, 'rb') as file_obj:
                zip_file_content = file_obj.read()
        else:
            file_list = run('ls -la %s' % tmp_dir)
            LOG.debug('Lambda archive content:\n%s' % file_list)
            return error_response(
                'Unable to find handler script in Lambda archive.', 400,
                error_type='ValidationError')

        if runtime.startswith('python') and not use_docker():
            try:
                lambda_handler = exec_lambda_code(
                    zip_file_content,
                    handler_function=handler_function,
                    lambda_cwd=lambda_cwd,
                    lambda_env=lambda_environment)
            except Exception as e:
                raise Exception('Unable to get handler function from lambda code.', e)

    add_function_mapping(lambda_name, lambda_handler, lambda_cwd)

    return {'FunctionName': lambda_name}


def do_list_functions():
    funcs = []
    for f_arn, func in iteritems(arn_to_lambda):
        func_name = f_arn.split(':function:')[-1]
        arn = func_arn(func_name)
        func_details = arn_to_lambda.get(arn)
        funcs.append(format_func_details(func_details))
    return funcs


def format_func_details(func_details, version=None, always_add_version=False):
    version = version or '$LATEST'
    result = {
        'Version': version,
        'FunctionArn': func_details.arn(),
        'FunctionName': func_details.name(),
        'CodeSize': func_details.get_version(version).get('CodeSize'),
        'Handler': func_details.handler,
        'Runtime': func_details.runtime,
        'Timeout': func_details.timeout,
        'Environment': func_details.envvars,
        # 'Description': ''
        # 'MemorySize': 192,
    }
    if (always_add_version or version != '$LATEST') and len(result['FunctionArn'].split(':')) <= 7:
        result['FunctionArn'] += ':%s' % (version)
    return result


# ------------
# API METHODS
# ------------


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
        arn_to_lambda[arn] = func_details = LambdaFunction(arn)
        func_details.versions = {'$LATEST': {'CodeSize': 50}}
        func_details.handler = data['Handler']
        func_details.runtime = data['Runtime']
        func_details.envvars = data.get('Environment', {}).get('Variables', {})
        func_details.timeout = data.get('Timeout')
        result = set_function_code(data['Code'], lambda_name)
        if isinstance(result, Response):
            del arn_to_lambda[arn]
            return result
        result.update({
            'DeadLetterConfig': data.get('DeadLetterConfig'),
            'Description': data.get('Description'),
            'Environment': {'Error': {}, 'Variables': func_details.envvars},
            'FunctionArn': arn,
            'FunctionName': lambda_name,
            'Handler': func_details.handler,
            'MemorySize': data.get('MemorySize'),
            'Role': data.get('Role'),
            'Runtime': func_details.runtime,
            'Timeout': data.get('Timeout'),
            'TracingConfig': {},
            'VpcConfig': {'SecurityGroupIds': [None], 'SubnetIds': [None], 'VpcId': None}
        })
        if data.get('Publish', False):
            result['Version'] = publish_new_function_version(arn)['Version']
        return jsonify(result or {})
    except Exception as e:
        del arn_to_lambda[arn]
        return error_response('Unknown error: %s %s' % (e, traceback.format_exc()))


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
            lambda_details = arn_to_lambda.get(func['FunctionArn'])
            if lambda_details.concurrency is not None:
                result['Concurrency'] = lambda_details.concurrency
            return jsonify(result)
    return error_response(
        'Function not found: %s' % func_arn(function), 404, error_type='ResourceNotFoundException')


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
    LAMBDA_EXECUTOR.cleanup(arn)

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
    result = format_func_details(lambda_details)
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
    LAMBDA_EXECUTOR.cleanup(arn)

    lambda_details = arn_to_lambda[arn]
    if data.get('Handler'):
        lambda_details.handler = data['Handler']
    if data.get('Runtime'):
        lambda_details.runtime = data['Runtime']
    if data.get('Environment'):
        lambda_details.envvars = data.get('Environment', {}).get('Variables', {})
    if data.get('Timeout'):
        lambda_details.timeout = data['Timeout']
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
    # function here can either be an arn or a function name
    arn = func_arn(function)

    # arn can also contain a qualifier, extract it from there if so
    m = re.match('(arn:aws:lambda:.*:.*:function:[a-zA-Z0-9-_]+)(:.*)?', arn)
    if m and m.group(2):
        qualifier = m.group(2)[1:]
        arn = m.group(1)
    else:
        qualifier = request.args.get('Qualifier')

    if arn not in arn_to_lambda:
        return error_response('Function does not exist: %s' % arn, 404, error_type='ResourceNotFoundException')
    if qualifier and not arn_to_lambda.get(arn).qualifier_exists(qualifier):
        return error_response('Function does not exist: {0}:{1}'.format(arn, qualifier), 404,
                              error_type='ResourceNotFoundException')
    data = None
    if request.data:
        try:
            data = json.loads(to_str(request.data))
        except Exception:
            return error_response('The payload is not JSON', 415, error_type='UnsupportedMediaTypeException')

    # Default invocation type is RequestResponse
    invocation_type = request.environ.get('HTTP_X_AMZ_INVOCATION_TYPE', 'RequestResponse')

    if invocation_type == 'RequestResponse':
        result = run_lambda(asynchronous=False, func_arn=arn, event=data, context={}, version=qualifier)
        if isinstance(result, dict):
            return jsonify(result)
        if result:
            return result
        return make_response('', 200)
    elif invocation_type == 'Event':
        run_lambda(asynchronous=True, func_arn=arn, event=data, context={}, version=qualifier)
        return make_response('', 202)
    elif invocation_type == 'DryRun':
        # Assume the dry run always passes.
        return make_response('', 204)
    else:
        return error_response('Invocation type not one of: RequestResponse, Event or DryRun',
                              code=400,
                              error_type='InvalidParameterValueException')


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


@app.route('%s/event-source-mappings/<mapping_uuid>' % PATH_ROOT, methods=['GET'])
def get_event_source_mapping(mapping_uuid):
    """ Get an existing event source mapping
        ---
        operationId: 'getEventSourceMapping'
        parameters:
            - name: 'request'
              in: body
    """
    mappings = event_source_mappings
    mappings = [m for m in mappings if mapping_uuid == m.get('UUID')]

    if len(mappings) == 0:
        return error_response('The resource you requested does not exist.', 404, error_type='ResourceNotFoundException')
    return jsonify(mappings[0])


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


@app.route('%s/functions/<function>/aliases/<name>' % PATH_ROOT, methods=['GET'])
def get_alias(function, name):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    if name not in arn_to_lambda.get(arn).aliases:
        return error_response('Alias not found: %s' % arn + ':' + name, 404,
                              error_type='ResourceNotFoundException')
    return jsonify(arn_to_lambda.get(arn).aliases.get(name))


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['GET'])
def list_aliases(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    return jsonify({'Aliases': sorted(arn_to_lambda.get(arn).aliases.values(),
                                      key=lambda x: x['Name'])})


@app.route('/<version>/functions/<function>/concurrency', methods=['PUT'])
def put_concurrency(version, function):
    # the version for put_concurrency != PATH_ROOT, at the time of this
    # writing it's: /2017-10-31 for this endpoint
    # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
    arn = func_arn(function)
    data = json.loads(request.data)
    lambda_details = arn_to_lambda.get(arn)
    if not lambda_details:
        return error_response('Function not found: %s' % arn, 404, error_type='ResourceNotFoundException')
    lambda_details.concurrency = data
    return jsonify(data)


def serve(port, quiet=True):
    # initialize the Lambda executor
    LAMBDA_EXECUTOR.startup()

    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
