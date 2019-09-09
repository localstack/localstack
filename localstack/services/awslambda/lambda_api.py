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
import hashlib
from io import BytesIO
from datetime import datetime
from six.moves import cStringIO as StringIO
from six.moves.urllib.parse import urlparse
from flask import Flask, Response, jsonify, request
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
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
    LAMBDA_RUNTIME_DOTNETCORE21,
    LAMBDA_RUNTIME_GOLANG,
    LAMBDA_RUNTIME_RUBY,
    LAMBDA_RUNTIME_RUBY25,
    LAMBDA_RUNTIME_CUSTOM_RUNTIME)
from localstack.utils.common import (to_str, load_file, save_file, TMP_FILES, ensure_readable,
    mkdir, unzip, is_zip_file, run, short_uid, is_jar_archive, timestamp, TIMESTAMP_FORMAT_MILLIS,
    md5, new_tmp_file, parse_chunked_data, is_number, now_utc, safe_requests, isoformat_milliseconds)
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.analytics import event_publisher
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.cloudwatch.cloudwatch_util import cloudwatched

APP_NAME = 'lambda_api'
PATH_ROOT = '/2015-03-31'
ARCHIVE_FILE_PATTERN = '%s/lambda.handler.*.jar' % config.TMP_FOLDER
LAMBDA_SCRIPT_PATTERN = '%s/lambda_script_*.py' % config.TMP_FOLDER

# List of Lambda runtime names. Keep them in this list, mainly to silence the linter
LAMBDA_RUNTIMES = [LAMBDA_RUNTIME_PYTHON27, LAMBDA_RUNTIME_PYTHON36,
    LAMBDA_RUNTIME_DOTNETCORE2, LAMBDA_RUNTIME_DOTNETCORE21, LAMBDA_RUNTIME_NODEJS,
    LAMBDA_RUNTIME_NODEJS610, LAMBDA_RUNTIME_NODEJS810, LAMBDA_RUNTIME_JAVA8, LAMBDA_RUNTIME_RUBY,
    LAMBDA_RUNTIME_RUBY25]

# default timeout in seconds
LAMBDA_DEFAULT_TIMEOUT = 3
# default handler and runtime
LAMBDA_DEFAULT_HANDLER = 'handler.handler'
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON27
LAMBDA_DEFAULT_STARTING_POSITION = 'LATEST'
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

# Marker name to indicate that a bucket represents the local file system. This is used for testing
# Serverless applications where we mount the Lambda code directly into the container from the host OS.
BUCKET_MARKER_LOCAL = '__local__'


class ClientError(Exception):
    def __init__(self, msg, code=400):
        super(ClientError, self).__init__(msg)
        self.code = code
        self.msg = msg

    def get_response(self):
        if isinstance(self.msg, Response):
            return self.msg
        return error_response(self.msg, self.code)


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


def add_event_source(function_name, source_arn, enabled):
    mapping = {
        'UUID': str(uuid.uuid4()),
        'StateTransitionReason': 'User action',
        'LastModified': float(time.mktime(datetime.utcnow().timetuple())),
        'BatchSize': 100,
        'State': 'Enabled' if enabled is True or enabled is None else 'Disabled',
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
            m['State'] = 'Enabled' if enabled is True else 'Disabled'
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


def process_sns_notification(func_arn, topic_arn, subscriptionArn, message, message_attributes, subject='',):
    try:
        event = {
            'Records': [{
                'EventSource': 'localstack:sns',
                'EventVersion': '1.0',
                'EventSubscriptionArn': subscriptionArn,
                'Sns': {
                    'Type': 'Notification',
                    'TopicArn': topic_arn,
                    'Subject': subject,
                    'Message': message,
                    'Timestamp': timestamp(format=TIMESTAMP_FORMAT_MILLIS),
                    'MessageAttributes': message_attributes
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


def process_sqs_message(message_body, message_attributes, queue_name, region_name=None):
    # feed message into the first listening lambda (message should only get processed once)
    try:
        queue_arn = aws_stack.sqs_queue_arn(queue_name, region_name=region_name)
        sources = get_event_sources(source_arn=queue_arn)
        LOG.debug('Found %s source mappings for event from SQS queue %s' % (len(sources), queue_arn))
        source = next(iter(sources), None)
        if source:
            arn = source['FunctionArn']
            event = {'Records': [{
                'body': message_body,
                'receiptHandle': 'MessageReceiptHandle',
                'md5OfBody': md5(message_body),
                'eventSourceARN': queue_arn,
                'eventSource': 'aws:sqs',
                'awsRegion': region_name,
                'messageId': str(uuid.uuid4()),
                'attributes': {
                    'ApproximateFirstReceiveTimestamp': '{}000'.format(int(time.time())),
                    'SenderId': TEST_AWS_ACCOUNT_ID,
                    'ApproximateReceiveCount': '1',
                    'SentTimestamp': '{}000'.format(int(time.time()))
                },
                'messageAttributes': message_attributes,
                'sqs': True,
            }]}
            run_lambda(event=event, context={}, func_arn=arn)
            return True
    except Exception as e:
        LOG.warning('Unable to run Lambda function on SQS messages: %s %s' % (e, traceback.format_exc()))


def get_event_sources(func_name=None, source_arn=None):
    result = []
    for m in event_source_mappings:
        if not func_name or (m['FunctionArn'] in [func_name, func_arn(func_name)]):
            if not source_arn or (m['EventSourceArn'].startswith(source_arn)):
                result.append(m)
    return result


def get_function_version(arn, version):
    func = arn_to_lambda.get(arn)
    return format_func_details(func, version=version, always_add_version=True)


def publish_new_function_version(arn):
    func_details = arn_to_lambda.get(arn)
    versions = func_details.versions
    last_version = func_details.max_version()
    versions[str(last_version + 1)] = {
        'CodeSize': versions.get('$LATEST').get('CodeSize'),
        'CodeSha256': versions.get('$LATEST').get('CodeSha256'),
        'Function': versions.get('$LATEST').get('Function'),
        'RevisionId': str(uuid.uuid4())
    }
    return get_function_version(arn, str(last_version + 1))


def do_list_versions(arn):
    return sorted([get_function_version(arn, version) for version in
                   arn_to_lambda.get(arn).versions.keys()], key=lambda k: str(k.get('Version')))


def do_update_alias(arn, alias, version, description=None):
    new_alias = {
        'AliasArn': arn + ':' + alias,
        'FunctionVersion': version,
        'Name': alias,
        'Description': description or '',
        'RevisionId': str(uuid.uuid4())
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
        func_arn = aws_stack.fix_arn(func_arn)
        func_details = arn_to_lambda.get(func_arn)
        if not func_details:
            return not_found_error(msg='The resource specified in the request does not exist.')
        if not context:
            context = LambdaContext(func_details, version)
        result, log_output = LAMBDA_EXECUTOR.execute(func_arn, func_details,
            event, context=context, version=version, asynchronous=asynchronous)
    except Exception as e:
        return error_response('Error executing Lambda function %s: %s %s' % (func_arn, e, traceback.format_exc()))
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
    elif runtime.startswith(LAMBDA_RUNTIME_DOTNETCORE2) or runtime.startswith(LAMBDA_RUNTIME_DOTNETCORE21):
        file_ext = '.dll'
        delimiter = ':'
    elif runtime.startswith(LAMBDA_RUNTIME_RUBY):
        file_ext = '.rb'
    elif runtime.startswith(LAMBDA_RUNTIME_CUSTOM_RUNTIME):
        file_ext = '.sh'
    else:
        file_ext = '.py'
    return '%s%s' % (handler_name.split(delimiter)[0], file_ext)


def get_handler_function_from_name(handler_name, runtime=LAMBDA_DEFAULT_RUNTIME):
    # TODO: support Java Lambdas in the future
    if runtime.startswith(LAMBDA_RUNTIME_DOTNETCORE2) or runtime.startswith(LAMBDA_RUNTIME_DOTNETCORE21):
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
            raise ClientError('Unable to fetch Lambda archive from S3: %s' % e, 404)
    elif 'ZipFile' in function_code:
        zip_file_content = function_code['ZipFile']
        zip_file_content = base64.b64decode(zip_file_content)
    else:
        raise ClientError('No valid Lambda archive specified.')
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
                raise ClientError('Expected exactly one *.jar entry in zip file, found %s' % len(jar_entries))
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
        return execute, zip_file_content
    raise ClientError(error_response(
        'Unable to extract Java Lambda handler - file is not a valid zip/jar files', 400, error_type='ValidationError'))


def set_archive_code(code, lambda_name, zip_file_content=None):

    # get metadata
    lambda_arn = func_arn(lambda_name)
    lambda_details = arn_to_lambda[lambda_arn]
    is_local_mount = code.get('S3Bucket') == BUCKET_MARKER_LOCAL

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(lambda_arn)

    if is_local_mount:
        # Mount or use a local folder lambda executors can reference
        # WARNING: this means we're pointing lambda_cwd to a local path in the user's
        # file system! We must ensure that there is no data loss (i.e., we must *not* add
        # this folder to TMP_FILES or similar).
        return code['S3Key']

    # get file content
    zip_file_content = zip_file_content or get_zip_bytes(code)

    # Save the zip file to a temporary file that the lambda executors can reference
    code_sha_256 = base64.standard_b64encode(hashlib.sha256(zip_file_content).digest())
    lambda_details.get_version('$LATEST')['CodeSize'] = len(zip_file_content)
    lambda_details.get_version('$LATEST')['CodeSha256'] = code_sha_256.decode('utf-8')
    tmp_dir = '%s/zipfile.%s' % (config.TMP_FOLDER, short_uid())
    mkdir(tmp_dir)
    tmp_file = '%s/%s' % (tmp_dir, LAMBDA_ZIP_FILE_NAME)
    save_file(tmp_file, zip_file_content)
    TMP_FILES.append(tmp_dir)
    lambda_details.cwd = tmp_dir
    return tmp_dir


def set_function_code(code, lambda_name, lambda_cwd=None):

    def generic_handler(event, context):
        raise ClientError(('Unable to find executor for Lambda function "%s". Note that ' +
            'Node.js, Golang, and .Net Core Lambdas currently require LAMBDA_EXECUTOR=docker') % lambda_name)

    arn = func_arn(lambda_name)
    lambda_details = arn_to_lambda[arn]
    runtime = lambda_details.runtime
    lambda_environment = lambda_details.envvars
    handler_name = lambda_details.handler or LAMBDA_DEFAULT_HANDLER
    code_passed = code
    code = code or lambda_details.code
    is_local_mount = code.get('S3Bucket') == BUCKET_MARKER_LOCAL
    zip_file_content = None

    if code_passed:
        lambda_cwd = lambda_cwd or set_archive_code(code_passed, lambda_name)
        if not is_local_mount:
            # Save the zip file to a temporary file that the lambda executors can reference
            zip_file_content = get_zip_bytes(code_passed)
    else:
        lambda_cwd = lambda_cwd or lambda_details.cwd

    # get local lambda working directory
    tmp_file = '%s/%s' % (lambda_cwd, LAMBDA_ZIP_FILE_NAME)

    if not zip_file_content:
        zip_file_content = load_file(tmp_file, mode='rb')

    # Set the appropriate lambda handler.
    lambda_handler = generic_handler
    if runtime == LAMBDA_RUNTIME_JAVA8:
        # The Lambda executors for Docker subclass LambdaExecutorContainers,
        # which runs Lambda in Docker by passing all *.jar files in the function
        # working directory as part of the classpath. Because of this, we need to
        # save the zip_file_content as a .jar here.
        lambda_handler, zip_file_content = get_java_handler(zip_file_content, handler_name, tmp_file)
        if is_jar_archive(zip_file_content):
            jar_tmp_file = '{working_dir}/{file_name}'.format(
                working_dir=lambda_cwd, file_name=LAMBDA_JAR_FILE_NAME)
            save_file(jar_tmp_file, zip_file_content)

    else:
        handler_file = get_handler_file_from_name(handler_name, runtime=runtime)
        handler_function = get_handler_function_from_name(handler_name, runtime=runtime)

        if not is_local_mount:
            # Lambda code must be uploaded in Zip format
            if not is_zip_file(zip_file_content):
                raise ClientError(
                    'Uploaded Lambda code for runtime ({}) is not in Zip format'.format(runtime))
            unzip(tmp_file, lambda_cwd)

        main_file = '%s/%s' % (lambda_cwd, handler_file)
        if not os.path.exists(main_file):
            # Raise an error if (1) this is not a local mount lambda, or (2) we're
            # running Lambdas locally (not in Docker), or (3) we're using remote Docker.
            # -> We do *not* want to raise an error if we're using local mount in non-remote Docker
            if not is_local_mount or not use_docker() or config.LAMBDA_REMOTE_DOCKER:
                file_list = run('cd %s; du -d 3 .' % lambda_cwd)
                config_debug = ('Config for local mount, docker, remote: "%s", "%s", "%s"' %
                    (is_local_mount, use_docker(), config.LAMBDA_REMOTE_DOCKER))
                LOG.debug('Lambda archive content:\n%s' % file_list)
                raise ClientError(error_response(
                    'Unable to find handler script in Lambda archive. %s' % config_debug,
                    400, error_type='ValidationError'))

        if runtime.startswith('python') and not use_docker():
            try:
                # make sure the file is actually readable, then read contents
                ensure_readable(main_file)
                zip_file_content = load_file(main_file, mode='rb')
                # extract handler
                lambda_handler = exec_lambda_code(
                    zip_file_content,
                    handler_function=handler_function,
                    lambda_cwd=lambda_cwd,
                    lambda_env=lambda_environment)
            except Exception as e:
                raise ClientError('Unable to get handler function from lambda code.', e)

    add_function_mapping(lambda_name, lambda_handler, lambda_cwd)

    return {'FunctionName': lambda_name}


def do_list_functions():
    funcs = []
    for f_arn, func in arn_to_lambda.items():
        if type(func) != LambdaFunction:
            continue
        func_name = f_arn.split(':function:')[-1]
        arn = func_arn(func_name)
        func_details = arn_to_lambda.get(arn)
        funcs.append(format_func_details(func_details))
    return funcs


def format_func_details(func_details, version=None, always_add_version=False):
    version = version or '$LATEST'
    result = {
        'CodeSha256': func_details.get_version(version).get('CodeSha256'),
        'Role': func_details.role,
        'Version': version,
        'FunctionArn': func_details.arn(),
        'FunctionName': func_details.name(),
        'CodeSize': func_details.get_version(version).get('CodeSize'),
        'Handler': func_details.handler,
        'Runtime': func_details.runtime,
        'Timeout': func_details.timeout,
        'Description': func_details.description,
        'MemorySize': func_details.memory_size,
        'LastModified': func_details.last_modified,
        'TracingConfig': {'Mode': 'PassThrough'},
        'RevisionId': func_details.get_version(version).get('RevisionId')
    }
    if func_details.envvars:
        result['Environment'] = {
            'Variables': func_details.envvars
        }
    if (always_add_version or version != '$LATEST') and len(result['FunctionArn'].split(':')) <= 7:
        result['FunctionArn'] += ':%s' % (version)
    return result


def forward_to_fallback_url(func_arn, data):
    """ If LAMBDA_FALLBACK_URL is configured, forward the invocation of this non-existing
        Lambda to the configured URL. """
    if not config.LAMBDA_FALLBACK_URL:
        return None
    if config.LAMBDA_FALLBACK_URL.startswith('dynamodb://'):
        table_name = urlparse(config.LAMBDA_FALLBACK_URL.replace('dynamodb://', 'http://')).netloc
        dynamodb = aws_stack.connect_to_service('dynamodb')
        item = {
            'id': {'S': short_uid()},
            'timestamp': {'N': str(now_utc())},
            'payload': {'S': str(data)}
        }
        aws_stack.create_dynamodb_table(table_name, partition_key='id')
        dynamodb.put_item(TableName=table_name, Item=item)
        return ''
    if re.match(r'^https?://.+', config.LAMBDA_FALLBACK_URL):
        response = safe_requests.post(config.LAMBDA_FALLBACK_URL, data)
        return response.content
    raise ClientError('Unexpected value for LAMBDA_FALLBACK_URL: %s' % config.LAMBDA_FALLBACK_URL)


def not_found_error(ref=None, msg=None):
    if not msg:
        msg = 'The resource you requested does not exist.'
        if ref:
            msg = '%s not found: %s' % ('Function' if ':function:' in ref else 'Resource', ref)
    return error_response(msg, 404, error_type='ResourceNotFoundException')


# ------------
# API METHODS
# ------------


@app.before_request
def before_request():
    # fix to enable chunked encoding, as this is used by some Lambda clients
    transfer_encoding = request.headers.get('Transfer-Encoding', '').lower()
    if transfer_encoding == 'chunked':
        request.environ['wsgi.input_terminated'] = True


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
        func_details.versions = {'$LATEST': {'RevisionId': str(uuid.uuid4())}}
        func_details.last_modified = isoformat_milliseconds(datetime.utcnow()) + '+0000'
        func_details.description = data.get('Description', '')
        func_details.handler = data['Handler']
        func_details.runtime = data['Runtime']
        func_details.envvars = data.get('Environment', {}).get('Variables', {})
        func_details.tags = data.get('Tags', {})
        func_details.timeout = data.get('Timeout', LAMBDA_DEFAULT_TIMEOUT)
        func_details.role = data['Role']
        func_details.memory_size = data.get('MemorySize')
        func_details.code = data['Code']
        result = set_function_code(func_details.code, lambda_name)
        if isinstance(result, Response):
            del arn_to_lambda[arn]
            return result
        # remove content from code attribute, if present
        func_details.code.pop('ZipFile', None)
        # prepare result
        result.update(format_func_details(func_details))
        if data.get('Publish', False):
            result['Version'] = publish_new_function_version(arn)['Version']
        return jsonify(result or {})
    except Exception as e:
        arn_to_lambda.pop(arn, None)
        if isinstance(e, ClientError):
            return e.get_response()
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
    return not_found_error(func_arn(function))


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
        return not_found_error(func_arn(function))

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
    arn = func_arn(function)
    func_details = arn_to_lambda.get(arn)
    result.update(format_func_details(func_details))
    if isinstance(result, Response):
        return result
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
        return not_found_error(arn)
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
    env_vars = data.get('Environment', {}).get('Variables')
    if env_vars is not None:
        lambda_details.envvars = env_vars
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

    data = request.get_data()
    if data:
        data = to_str(data)
        try:
            data = json.loads(data)
        except Exception:
            try:
                # try to read chunked content
                data = json.loads(parse_chunked_data(data))
            except Exception:
                return error_response('The payload is not JSON: %s' % data, 415,
                                      error_type='UnsupportedMediaTypeException')

    # Default invocation type is RequestResponse
    invocation_type = request.environ.get('HTTP_X_AMZ_INVOCATION_TYPE', 'RequestResponse')

    def _create_response(result, status_code=200):
        """ Create the final response for the given invocation result """
        if isinstance(result, Response):
            return result
        details = {
            'StatusCode': status_code,
            'Payload': result,
            'Headers': {}
        }
        if isinstance(result, dict):
            for key in ('StatusCode', 'Payload', 'FunctionError'):
                if result.get(key):
                    details[key] = result[key]
        # Try to parse parse payload as JSON
        payload = details['Payload']
        if payload and isinstance(payload, (str, bytes)) and payload[0] in ('[', '{', '"'):
            try:
                details['Payload'] = json.loads(details['Payload'])
            except Exception:
                pass
        # Set error headers
        if details.get('FunctionError'):
            details['Headers']['X-Amz-Function-Error'] = str(details['FunctionError'])
        # Construct response object
        response_obj = details['Payload']
        if isinstance(response_obj, (dict, list, bool)) or is_number(response_obj):
            # Assume this is a JSON response
            response_obj = jsonify(response_obj)
        else:
            response_obj = str(response_obj)
            details['Headers']['Content-Type'] = 'text/plain'
        return response_obj, details['StatusCode'], details['Headers']

    # check if this lambda function exists
    not_found = None
    if arn not in arn_to_lambda:
        not_found = not_found_error(arn)
    if qualifier and not arn_to_lambda.get(arn).qualifier_exists(qualifier):
        not_found = not_found_error('{0}:{1}'.format(arn, qualifier))
    if not_found:
        forward_result = forward_to_fallback_url(func_arn, data)
        if forward_result is not None:
            return _create_response(forward_result)
        return not_found

    if invocation_type == 'RequestResponse':
        result = run_lambda(asynchronous=False, func_arn=arn, event=data, context={}, version=qualifier)
        return _create_response(result)
    elif invocation_type == 'Event':
        run_lambda(asynchronous=True, func_arn=arn, event=data, context={}, version=qualifier)
        return _create_response('', status_code=202)
    elif invocation_type == 'DryRun':
        # Assume the dry run always passes.
        return _create_response('', status_code=204)
    return error_response('Invocation type not one of: RequestResponse, Event or DryRun',
                          code=400, error_type='InvalidParameterValueException')


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
        return not_found_error()
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
    mapping = add_event_source(data['FunctionName'], data['EventSourceArn'], data.get('Enabled'))
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
    enabled = data.get('Enabled', True)
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
        return not_found_error(arn)
    return jsonify(publish_new_function_version(arn))


@app.route('%s/functions/<function>/versions' % PATH_ROOT, methods=['GET'])
def list_versions(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return not_found_error(arn)
    return jsonify({'Versions': do_list_versions(arn)})


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['POST'])
def create_alias(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return not_found_error(arn)
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
        return not_found_error(arn)
    if name not in arn_to_lambda.get(arn).aliases:
        return not_found_error(msg='Alias not found: %s:%s' % (arn, name))
    current_alias = arn_to_lambda.get(arn).aliases.get(name)
    data = json.loads(request.data)
    version = data.get('FunctionVersion') or current_alias.get('FunctionVersion')
    description = data.get('Description') or current_alias.get('Description')
    return jsonify(do_update_alias(arn, name, version, description))


@app.route('%s/functions/<function>/aliases/<name>' % PATH_ROOT, methods=['GET'])
def get_alias(function, name):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return not_found_error(arn)
    if name not in arn_to_lambda.get(arn).aliases:
        return not_found_error(msg='Alias not found: %s:%s' % (arn, name))
    return jsonify(arn_to_lambda.get(arn).aliases.get(name))


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['GET'])
def list_aliases(function):
    arn = func_arn(function)
    if arn not in arn_to_lambda:
        return not_found_error(arn)
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
        return not_found_error(arn)
    lambda_details.concurrency = data
    return jsonify(data)


@app.route('/<version>/tags/<arn>', methods=['GET'])
def list_tags(version, arn):
    func_details = arn_to_lambda.get(arn)
    if not func_details:
        return not_found_error(arn)
    result = {'Tags': func_details.tags}
    return jsonify(result)


@app.route('/<version>/tags/<arn>', methods=['POST'])
def tag_resource(version, arn):
    data = json.loads(request.data)
    tags = data.get('Tags', {})
    if tags:
        func_details = arn_to_lambda.get(arn)
        if not func_details:
            return not_found_error(arn)
        if func_details:
            func_details.tags.update(tags)
    return jsonify({})


@app.route('/<version>/tags/<arn>', methods=['DELETE'])
def untag_resource(version, arn):
    tag_keys = request.args.getlist('tagKeys')
    func_details = arn_to_lambda.get(arn)
    if not func_details:
        return not_found_error(arn)
    for tag_key in tag_keys:
        func_details.tags.pop(tag_key, None)
    return jsonify({})


def serve(port, quiet=True):
    # initialize the Lambda executor
    LAMBDA_EXECUTOR.startup()

    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
