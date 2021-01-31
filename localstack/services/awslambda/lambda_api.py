import re
import os
import imp
import sys
import json
import uuid
import time
import base64
import hashlib
import logging
import functools
import threading
import traceback
from io import BytesIO
from datetime import datetime
from flask import Flask, Response, jsonify, request
from six.moves import cStringIO as StringIO
from six.moves.urllib.parse import urlparse
from moto.apigateway.models import apigateway_backends
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.common import (
    to_str, to_bytes, load_file, save_file, TMP_FILES, ensure_readable, short_uid, long_uid, json_safe,
    mkdir, unzip, is_zip_file, run, first_char_to_lower, run_for_max_seconds,
    timestamp_millis, now_utc, safe_requests, FuncThread, isoformat_milliseconds, synchronized)
from localstack.services.awslambda import lambda_executors
from localstack.services.generic_proxy import RegionBackend
from localstack.services.awslambda.lambda_utils import (
    DOTNET_LAMBDA_RUNTIMES, multi_value_dict_for_list, get_handler_file_from_name,
    LAMBDA_DEFAULT_HANDLER, LAMBDA_DEFAULT_RUNTIME, LAMBDA_DEFAULT_STARTING_POSITION)
from localstack.utils.analytics import event_publisher
from localstack.utils.http_utils import parse_chunked_data
from localstack.utils.aws.aws_models import LambdaFunction, CodeSigningConfig
from localstack.services.cloudformation.service_models import LAMBDA_POLICY_NAME_PATTERN

# logger
LOG = logging.getLogger(__name__)

# constants
APP_NAME = 'lambda_api'
PATH_ROOT = '/2015-03-31'
ARCHIVE_FILE_PATTERN = '%s/lambda.handler.*.jar' % config.TMP_FOLDER
LAMBDA_SCRIPT_PATTERN = '%s/lambda_script_*.py' % config.TMP_FOLDER
LAMBDA_ZIP_FILE_NAME = 'original_lambda_archive.zip'
LAMBDA_JAR_FILE_NAME = 'original_lambda_archive.jar'

# default timeout in seconds
LAMBDA_DEFAULT_TIMEOUT = 3

INVALID_PARAMETER_VALUE_EXCEPTION = 'InvalidParameterValueException'
VERSION_LATEST = '$LATEST'
FUNCTION_MAX_SIZE = 69905067

BATCH_SIZE_RANGES = {
    'kinesis': (100, 10000),
    'dynamodb': (100, 1000),
    'sqs': (10, 10)
}

app = Flask(APP_NAME)

# mutex for access to CWD and ENV
EXEC_MUTEX = threading.RLock(1)

# whether to use Docker for execution
DO_USE_DOCKER = None

# start characters indicating that a lambda result should be parsed as JSON
JSON_START_CHAR_MAP = {
    list: ('[',),
    tuple: ('[',),
    dict: ('{',),
    str: ('"',),
    bytes: ('"',),
    bool: ('t', 'f'),
    type(None): ('n',),
    int: ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'),
    float: ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')
}
POSSIBLE_JSON_TYPES = (str, bytes)
JSON_START_TYPES = tuple(set(JSON_START_CHAR_MAP.keys()) - set(POSSIBLE_JSON_TYPES))
JSON_START_CHARS = tuple(set(functools.reduce(lambda x, y: x + y, JSON_START_CHAR_MAP.values())))

# SQS listener thread settings
SQS_LISTENER_THREAD = {}
SQS_POLL_INTERVAL_SEC = 1

# lambda executor instance
LAMBDA_EXECUTOR = lambda_executors.AVAILABLE_EXECUTORS.get(config.LAMBDA_EXECUTOR, lambda_executors.DEFAULT_EXECUTOR)

# IAM policy constants
IAM_POLICY_VERSION = '2012-10-17'

# Whether to check if the handler function exists while creating lambda function
CHECK_HANDLER_ON_CREATION = False

# Marker name to indicate that a bucket represents the local file system. This is used for testing
# Serverless applications where we mount the Lambda code directly into the container from the host OS.
BUCKET_MARKER_LOCAL = '__local__'


class LambdaRegion(RegionBackend):
    def __init__(self):
        # map ARN strings to lambda function objects
        self.lambdas = {}
        # map ARN strings to CodeSigningConfig object
        self.code_signing_configs = {}
        # list of event source mappings for the API
        self.event_source_mappings = []


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

    def __init__(self, func_details, qualifier=None, context=None):
        self.function_name = func_details.name()
        self.function_version = func_details.get_qualifier_version(qualifier)
        self.client_context = context.get('client_context')
        self.invoked_function_arn = func_details.arn()
        if qualifier:
            self.invoked_function_arn += ':' + qualifier
        self.cognito_identity = context.get('identity')

    def get_remaining_time_in_millis(self):
        # TODO implement!
        return 1000 * 60


def cleanup():
    region = LambdaRegion.get()
    region.lambdas = {}
    region.event_source_mappings = []
    LAMBDA_EXECUTOR.cleanup()


def func_arn(function_name):
    return aws_stack.lambda_function_arn(function_name)


def func_qualifier(function_name, qualifier=None):
    region = LambdaRegion.get()
    arn = aws_stack.lambda_function_arn(function_name)
    details = region.lambdas.get(arn)
    if not details:
        return details
    if details.qualifier_exists(qualifier):
        return '{}:{}'.format(arn, qualifier)
    return arn


def check_batch_size_range(source_arn, batch_size=None):
    batch_size_entry = BATCH_SIZE_RANGES.get(source_arn.split(':')[2].lower())
    if not batch_size_entry:
        raise ValueError(
            INVALID_PARAMETER_VALUE_EXCEPTION, 'Unsupported event source type'
        )

    batch_size = batch_size or batch_size_entry[0]
    if batch_size > batch_size_entry[1]:
        raise ValueError(
            INVALID_PARAMETER_VALUE_EXCEPTION,
            'BatchSize {} exceeds the max of {}'.format(batch_size, batch_size_entry[1])
        )

    return batch_size


def add_function_mapping(lambda_name, lambda_handler, lambda_cwd=None):
    region = LambdaRegion.get()
    arn = func_arn(lambda_name)
    lambda_details = region.lambdas[arn]
    lambda_details.versions.get(VERSION_LATEST)['Function'] = lambda_handler
    lambda_details.cwd = lambda_cwd or lambda_details.cwd


def add_event_source(function_name, source_arn, enabled, batch_size=None):
    batch_size = check_batch_size_range(source_arn, batch_size)
    region = LambdaRegion.get()

    mapping = {
        'UUID': str(uuid.uuid4()),
        'StateTransitionReason': 'User action',
        'LastModified': float(time.mktime(datetime.utcnow().timetuple())),
        'BatchSize': batch_size,
        'State': 'Enabled' if enabled in [True, None] else 'Disabled',
        'FunctionArn': func_arn(function_name),
        'EventSourceArn': source_arn,
        'LastProcessingResult': 'OK',
        'StartingPosition': LAMBDA_DEFAULT_STARTING_POSITION
    }
    region.event_source_mappings.append(mapping)
    return mapping


def update_event_source(uuid_value, function_name, enabled, batch_size):
    region = LambdaRegion.get()
    for m in region.event_source_mappings:
        if uuid_value == m['UUID']:
            if function_name:
                m['FunctionArn'] = func_arn(function_name)

            batch_size = check_batch_size_range(m['EventSourceArn'], batch_size or m['BatchSize'])

            m['BatchSize'] = batch_size
            m['State'] = 'Enabled' if enabled is True else 'Disabled'
            m['LastModified'] = float(time.mktime(datetime.utcnow().timetuple()))

            return m

    return {}


def delete_event_source(uuid_value):
    region = LambdaRegion.get()
    for i, m in enumerate(region.event_source_mappings):
        if uuid_value == m['UUID']:
            return region.event_source_mappings.pop(i)
    return {}


@synchronized(lock=EXEC_MUTEX)
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


def get_stage_variables(api_id, stage):
    region_name = [name for name, region in apigateway_backends.items() if api_id in region.apis][0]
    api_gateway_client = aws_stack.connect_to_service('apigateway', region_name=region_name)
    response = api_gateway_client.get_stage(restApiId=api_id, stageName=stage)
    return response.get('variables', None)


def fix_proxy_path_params(path_params):
    proxy_path_param_value = path_params.get('proxy+')
    if not proxy_path_param_value:
        return
    del path_params['proxy+']
    path_params['proxy'] = proxy_path_param_value


def message_attributes_to_lower(message_attrs):
    """ Convert message attribute details (first characters) to lower case (e.g., stringValue, dataType). """
    message_attrs = message_attrs or {}
    for _, attr in message_attrs.items():
        if not isinstance(attr, dict):
            continue
        for key, value in dict(attr).items():
            attr[first_char_to_lower(key)] = attr.pop(key)
    return message_attrs


def process_apigateway_invocation(func_arn, path, payload, stage, api_id, headers={},
                                  resource_path=None, method=None, path_params={},
                                  query_string_params=None, request_context={}, event_context={}):
    try:
        resource_path = resource_path or path
        path_params = dict(path_params)
        fix_proxy_path_params(path_params)
        event = {
            'path': path,
            'headers': dict(headers),
            'multiValueHeaders': multi_value_dict_for_list(headers),
            'pathParameters': path_params,
            'body': payload,
            'isBase64Encoded': False,
            'resource': resource_path,
            'httpMethod': method,
            'queryStringParameters': query_string_params,
            'multiValueQueryStringParameters': multi_value_dict_for_list(query_string_params),
            'requestContext': request_context,
            'stageVariables': get_stage_variables(api_id, stage),
        }
        LOG.debug('Running Lambda function %s from API Gateway invocation: %s %s' % (func_arn, method or 'GET', path))
        asynchronous = not config.SYNCHRONOUS_API_GATEWAY_EVENTS
        inv_result = run_lambda(event=event, context=event_context, func_arn=func_arn, asynchronous=asynchronous)
        return inv_result.result
    except Exception as e:
        LOG.warning('Unable to run Lambda function on API Gateway message: %s %s' % (e, traceback.format_exc()))


def process_sns_notification(func_arn, topic_arn, subscription_arn, message, message_id,
        message_attributes, unsubscribe_url, subject='',):
    event = {
        'Records': [{
            'EventSource': 'localstack:sns',
            'EventVersion': '1.0',
            'EventSubscriptionArn': subscription_arn,
            'Sns': {
                'Type': 'Notification',
                'MessageId': message_id,
                'TopicArn': topic_arn,
                'Subject': subject,
                'Message': message,
                'Timestamp': timestamp_millis(),
                'SignatureVersion': '1',
                # TODO Add a more sophisticated solution with an actual signature
                # Hardcoded
                'Signature': 'EXAMPLEpH+..',
                'SigningCertUrl': 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-000000000.pem',
                'UnsubscribeUrl': unsubscribe_url,
                'MessageAttributes': message_attributes
            }
        }]
    }
    inv_result = run_lambda(event=event, context={}, func_arn=func_arn, asynchronous=not config.SYNCHRONOUS_SNS_EVENTS)
    return inv_result.result


def process_kinesis_records(records, stream_name):
    def chunks(lst, n):
        # Yield successive n-sized chunks from lst.
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    # feed records into listening lambdas
    try:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        sources = get_event_sources(source_arn=stream_arn)
        for source in sources:
            arn = source['FunctionArn']
            for chunk in chunks(records, source['BatchSize']):
                event = {
                    'Records': [
                        {
                            'eventID': 'shardId-000000000000:{0}'.format(rec['sequenceNumber']),
                            'eventSourceARN': stream_arn,
                            'eventSource': 'aws:kinesis',
                            'eventVersion': '1.0',
                            'eventName': 'aws:kinesis:record',
                            'invokeIdentityArn': 'arn:aws:iam::{0}:role/lambda-role'.format(TEST_AWS_ACCOUNT_ID),
                            'awsRegion': aws_stack.get_region(),
                            'kinesis': rec
                        }
                        for rec in chunk
                    ]
                }
                run_lambda(event=event, context={}, func_arn=arn, asynchronous=not config.SYNCHRONOUS_KINESIS_EVENTS)
    except Exception as e:
        LOG.warning('Unable to run Lambda function on Kinesis records: %s %s' % (e, traceback.format_exc()))


def start_lambda_sqs_listener():
    if SQS_LISTENER_THREAD:
        return

    def send_event_to_lambda(queue_arn, queue_url, lambda_arn, messages, region):
        def delete_messages(result, func_arn, event, error=None, dlq_sent=None, **kwargs):
            if error and not dlq_sent:
                # Skip deleting messages from the queue in case of processing errors AND if
                # the message has not yet been sent to a dead letter queue (DLQ).
                # We'll pick them up and retry next time they become available on the queue.
                return

            sqs_client = aws_stack.connect_to_service('sqs')
            entries = [{'Id': r['receiptHandle'], 'ReceiptHandle': r['receiptHandle']} for r in records]
            sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=entries)

        records = []
        for msg in messages:
            message_attrs = message_attributes_to_lower(msg.get('MessageAttributes'))
            records.append({
                'body': msg['Body'],
                'receiptHandle': msg['ReceiptHandle'],
                'md5OfBody': msg['MD5OfBody'],
                'eventSourceARN': queue_arn,
                'eventSource': lambda_executors.EVENT_SOURCE_SQS,
                'awsRegion': region,
                'messageId': msg['MessageId'],
                'attributes': msg.get('Attributes', {}),
                'messageAttributes': message_attrs,
                'md5OfMessageAttributes': msg.get('MD5OfMessageAttributes'),
                'sqs': True,
            })

        event = {'Records': records}

        # TODO implement retries, based on "RedrivePolicy.maxReceiveCount" in the queue settings
        run_lambda(event=event, context={}, func_arn=lambda_arn, asynchronous=True, callback=delete_messages)

    def listener_loop(*args):
        while True:
            try:
                sources = get_event_sources(source_arn=r'.*:sqs:.*')
                if not sources:
                    # Temporarily disable polling if no event sources are configured
                    # anymore. The loop will get restarted next time a message
                    # arrives and if an event source is configured.
                    SQS_LISTENER_THREAD.pop('_thread_')
                    return

                sqs_client = aws_stack.connect_to_service('sqs')
                for source in sources:
                    queue_arn = source['EventSourceArn']
                    lambda_arn = source['FunctionArn']
                    batch_size = max(min(source.get('BatchSize', 1), 10), 1)

                    try:
                        region_name = queue_arn.split(':')[3]
                        queue_url = aws_stack.sqs_queue_url_for_arn(queue_arn)
                        result = sqs_client.receive_message(
                            QueueUrl=queue_url,
                            MessageAttributeNames=['All'],
                            MaxNumberOfMessages=batch_size
                        )
                        messages = result.get('Messages')
                        if not messages:
                            continue

                        send_event_to_lambda(queue_arn, queue_url, lambda_arn, messages, region=region_name)

                    except Exception as e:
                        LOG.debug('Unable to poll SQS messages for queue %s: %s' % (queue_arn, e))

            except Exception:
                pass
            finally:
                time.sleep(SQS_POLL_INTERVAL_SEC)

    LOG.debug('Starting SQS message polling thread for Lambda API')
    SQS_LISTENER_THREAD['_thread_'] = FuncThread(listener_loop)
    SQS_LISTENER_THREAD['_thread_'].start()


def process_sqs_message(queue_name, region_name=None):
    # feed message into the first listening lambda (message should only get processed once)
    try:
        region_name = region_name or aws_stack.get_region()
        queue_arn = aws_stack.sqs_queue_arn(queue_name, region_name=region_name)
        sources = get_event_sources(source_arn=queue_arn)
        arns = [s.get('FunctionArn') for s in sources]
        source = (sources or [None])[0]
        if not source:
            return False

        LOG.debug('Found %s source mappings for event from SQS queue %s: %s' % (len(arns), queue_arn, arns))
        start_lambda_sqs_listener()
        return True
    except Exception as e:
        LOG.warning('Unable to run Lambda function on SQS messages: %s %s' % (e, traceback.format_exc()))


def get_event_sources(func_name=None, source_arn=None):
    region = LambdaRegion.get()
    result = []
    for m in region.event_source_mappings:
        if not func_name or (m['FunctionArn'] in [func_name, func_arn(func_name)]):
            if _arn_match(mapped=m['EventSourceArn'], searched=source_arn):
                result.append(m)
    return result


def _arn_match(mapped, searched):
    if not searched or mapped == searched:
        return True
    # Some types of ARNs can end with a path separated by slashes, for
    # example the ARN of a DynamoDB stream is tableARN/stream/ID. It's
    # a little counterintuitive that a more specific mapped ARN can
    # match a less specific ARN on the event, but some integration tests
    # rely on it for things like subscribing to a stream and matching an
    # event labeled with the table ARN.
    if re.match(r'^%s$' % searched, mapped):
        return True
    if mapped.startswith(searched):
        suffix = mapped[len(searched):]
        return suffix[0] == '/'
    return False


def get_function_version(arn, version):
    region = LambdaRegion.get()
    func = region.lambdas.get(arn)
    return format_func_details(func, version=version, always_add_version=True)


def publish_new_function_version(arn):
    region = LambdaRegion.get()
    func_details = region.lambdas.get(arn)
    versions = func_details.versions
    max_version_number = func_details.max_version()
    next_version_number = max_version_number + 1
    latest_hash = versions.get(VERSION_LATEST).get('CodeSha256')
    max_version = versions.get(str(max_version_number))
    max_version_hash = max_version.get('CodeSha256') if max_version else ''

    if latest_hash != max_version_hash:
        versions[str(next_version_number)] = {
            'CodeSize': versions.get(VERSION_LATEST).get('CodeSize'),
            'CodeSha256': versions.get(VERSION_LATEST).get('CodeSha256'),
            'Function': versions.get(VERSION_LATEST).get('Function'),
            'RevisionId': str(uuid.uuid4())
        }
        max_version_number = next_version_number
    return get_function_version(arn, str(max_version_number))


def do_list_versions(arn):
    region = LambdaRegion.get()
    versions = [get_function_version(arn, version) for version in region.lambdas.get(arn).versions.keys()]
    return sorted(versions, key=lambda k: str(k.get('Version')))


def do_update_alias(arn, alias, version, description=None):
    region = LambdaRegion.get()
    new_alias = {
        'AliasArn': arn + ':' + alias,
        'FunctionVersion': version,
        'Name': alias,
        'Description': description or '',
        'RevisionId': str(uuid.uuid4())
    }
    region.lambdas.get(arn).aliases[alias] = new_alias
    return new_alias


def run_lambda(event, context, func_arn, version=None, suppress_output=False, asynchronous=False, callback=None):
    region = LambdaRegion.get()
    if suppress_output:
        stdout_ = sys.stdout
        stderr_ = sys.stderr
        stream = StringIO()
        sys.stdout = stream
        sys.stderr = stream
    try:
        func_arn = aws_stack.fix_arn(func_arn)
        func_details = region.lambdas.get(func_arn)
        if not func_details:
            result = not_found_error(msg='The resource specified in the request does not exist.')
            return lambda_executors.InvocationResult(result)

        context = LambdaContext(func_details, version, context)
        result = LAMBDA_EXECUTOR.execute(func_arn, func_details, event, context=context,
            version=version, asynchronous=asynchronous, callback=callback)

    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        response = {
            'errorType': str(exc_type.__name__),
            'errorMessage': str(e),
            'stackTrace': traceback.format_tb(exc_traceback)
        }
        LOG.info('Error executing Lambda function %s: %s %s' % (func_arn, e, traceback.format_exc()))
        log_output = e.log_output if isinstance(e, lambda_executors.InvocationException) else ''
        return lambda_executors.InvocationResult(Response(json.dumps(response), status=500), log_output)
    finally:
        if suppress_output:
            sys.stdout = stdout_
            sys.stderr = stderr_
    return result


def exec_lambda_code(script, handler_function='handler', lambda_cwd=None, lambda_env=None):
    if lambda_cwd or lambda_env:
        EXEC_MUTEX.acquire()
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
        pre_sys_modules_keys = set(sys.modules.keys())
        try:
            handler_module = imp.load_source(lambda_id, lambda_file)
            module_vars = handler_module.__dict__
        finally:
            # the above import can bring files for the function
            # (eg settings.py) into the global namespace. subsequent
            # calls can pick up file from another function, causing
            # general issues.
            post_sys_modules_keys = set(sys.modules.keys())
            for key in post_sys_modules_keys:
                if key not in pre_sys_modules_keys:
                    sys.modules.pop(key)
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
            EXEC_MUTEX.release()
    return module_vars[handler_function]


def get_handler_function_from_name(handler_name, runtime=LAMBDA_DEFAULT_RUNTIME):
    if runtime.startswith(tuple(DOTNET_LAMBDA_RUNTIMES)):
        return handler_name.split(':')[-1]
    return handler_name.split('.')[-1]


def error_response(msg, code=500, error_type='InternalFailure'):
    LOG.info(msg)
    return aws_responses.flask_error_response_json(msg, code=code, error_type=error_type)


def get_zip_bytes(function_code):
    """Returns the ZIP file contents from a FunctionCode dict.

    :type function_code: dict
    :param function_code: https://docs.aws.amazon.com/lambda/latest/dg/API_FunctionCode.html
    :returns: bytes of the Zip file.
    """
    function_code = function_code or {}
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
    elif 'ImageUri' in function_code:
        zip_file_content = None
    else:
        raise ClientError('No valid Lambda archive specified: %s' % list(function_code.keys()))
    return zip_file_content


def get_java_handler(zip_file_content, main_file, func_details=None):
    """Creates a Java handler from an uploaded ZIP or JAR.

    :type zip_file_content: bytes
    :param zip_file_content: ZIP file bytes.
    :type handler: str
    :param handler: The lambda handler path.
    :type main_file: str
    :param main_file: Filepath to the uploaded ZIP or JAR file.

    :returns: function or flask.Response
    """
    if is_zip_file(zip_file_content):
        def execute(event, context):
            result = lambda_executors.EXECUTOR_LOCAL.execute_java_lambda(
                event, context, main_file=main_file, func_details=func_details)
            return result
        return execute
    raise ClientError(error_response(
        'Unable to extract Java Lambda handler - file is not a valid zip/jar file', 400, error_type='ValidationError'))


def set_archive_code(code, lambda_name, zip_file_content=None):
    region = LambdaRegion.get()
    # get metadata
    lambda_arn = func_arn(lambda_name)
    lambda_details = region.lambdas[lambda_arn]
    is_local_mount = code.get('S3Bucket') == BUCKET_MARKER_LOCAL

    if is_local_mount and config.LAMBDA_REMOTE_DOCKER:
        msg = 'Please note that Lambda mounts (bucket name "%s") cannot be used with LAMBDA_REMOTE_DOCKER=1'
        raise Exception(msg % BUCKET_MARKER_LOCAL)

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(lambda_arn)

    if is_local_mount:
        # Mount or use a local folder lambda executors can reference
        # WARNING: this means we're pointing lambda_cwd to a local path in the user's
        # file system! We must ensure that there is no data loss (i.e., we must *not* add
        # this folder to TMP_FILES or similar).
        lambda_details.cwd = code.get('S3Key')
        return code['S3Key']

    # get file content
    zip_file_content = zip_file_content or get_zip_bytes(code)

    if not zip_file_content:
        return

    # Save the zip file to a temporary file that the lambda executors can reference
    code_sha_256 = base64.standard_b64encode(hashlib.sha256(zip_file_content).digest())
    latest_version = lambda_details.get_version(VERSION_LATEST)
    latest_version['CodeSize'] = len(zip_file_content)
    latest_version['CodeSha256'] = code_sha_256.decode('utf-8')
    tmp_dir = '%s/zipfile.%s' % (config.TMP_FOLDER, short_uid())
    mkdir(tmp_dir)
    tmp_file = '%s/%s' % (tmp_dir, LAMBDA_ZIP_FILE_NAME)
    save_file(tmp_file, zip_file_content)
    TMP_FILES.append(tmp_dir)
    lambda_details.cwd = tmp_dir
    return tmp_dir


def set_function_code(code, lambda_name, lambda_cwd=None):
    def _set_and_configure():
        lambda_handler = do_set_function_code(code, lambda_name, lambda_cwd=lambda_cwd)
        add_function_mapping(lambda_name, lambda_handler, lambda_cwd)
    # unzipping can take some time - limit the execution time to avoid client/network timeout issues
    run_for_max_seconds(25, _set_and_configure)
    return {'FunctionName': lambda_name}


def do_set_function_code(code, lambda_name, lambda_cwd=None):
    def generic_handler(event, context):
        raise ClientError(('Unable to find executor for Lambda function "%s". Note that ' +
            'Node.js, Golang, and .Net Core Lambdas currently require LAMBDA_EXECUTOR=docker') % lambda_name)

    region = LambdaRegion.get()
    arn = func_arn(lambda_name)
    lambda_details = region.lambdas[arn]
    runtime = lambda_details.runtime
    lambda_environment = lambda_details.envvars
    handler_name = lambda_details.handler = lambda_details.handler or LAMBDA_DEFAULT_HANDLER
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

    if not lambda_cwd:
        return

    # get local lambda working directory
    tmp_file = os.path.join(lambda_cwd, LAMBDA_ZIP_FILE_NAME)

    if not zip_file_content:
        zip_file_content = load_file(tmp_file, mode='rb')

    # Set the appropriate lambda handler.
    lambda_handler = generic_handler
    is_java = lambda_executors.is_java_lambda(runtime)

    if is_java:
        # The Lambda executors for Docker subclass LambdaExecutorContainers, which
        # runs Lambda in Docker by passing all *.jar files in the function working
        # directory as part of the classpath. Obtain a Java handler function below.
        lambda_handler = get_java_handler(zip_file_content, tmp_file, func_details=lambda_details)

    if not is_local_mount:
        # Lambda code must be uploaded in Zip format
        if not is_zip_file(zip_file_content):
            raise ClientError(
                'Uploaded Lambda code for runtime ({}) is not in Zip format'.format(runtime))
        # Unzip the Lambda archive contents
        unzip(tmp_file, lambda_cwd)

    # Obtain handler details for any non-Java Lambda function
    if not is_java:
        handler_file = get_handler_file_from_name(handler_name, runtime=runtime)
        handler_function = get_handler_function_from_name(handler_name, runtime=runtime)

        main_file = '%s/%s' % (lambda_cwd, handler_file)

        if CHECK_HANDLER_ON_CREATION and not os.path.exists(main_file):
            # Raise an error if (1) this is not a local mount lambda, or (2) we're
            # running Lambdas locally (not in Docker), or (3) we're using remote Docker.
            # -> We do *not* want to raise an error if we're using local mount in non-remote Docker
            if not is_local_mount or not use_docker() or config.LAMBDA_REMOTE_DOCKER:
                file_list = run('cd "%s"; du -d 3 .' % lambda_cwd)
                config_debug = ('Config for local mount, docker, remote: "%s", "%s", "%s"' %
                    (is_local_mount, use_docker(), config.LAMBDA_REMOTE_DOCKER))
                LOG.debug('Lambda archive content:\n%s' % file_list)
                raise ClientError(error_response(
                    'Unable to find handler script (%s) in Lambda archive. %s' % (main_file, config_debug),
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

    return lambda_handler


def do_list_functions():
    funcs = []
    region = LambdaRegion.get()
    this_region = aws_stack.get_region()
    for f_arn, func in region.lambdas.items():
        if type(func) != LambdaFunction:
            continue

        # filter out functions of current region
        func_region = f_arn.split(':')[3]
        if func_region != this_region:
            continue

        func_name = f_arn.split(':function:')[-1]
        arn = func_arn(func_name)
        func_details = region.lambdas.get(arn)
        if not func_details:
            # this can happen if we're accessing Lambdas from a different region (ARN mismatch)
            continue

        details = format_func_details(func_details)
        details['Tags'] = func.tags

        funcs.append(details)
    return funcs


def format_func_details(func_details, version=None, always_add_version=False):
    version = version or VERSION_LATEST
    func_version = func_details.get_version(version)
    result = {
        'CodeSha256': func_version.get('CodeSha256'),
        'Role': func_details.role,
        'KMSKeyArn': func_details.kms_key_arn,
        'Version': version,
        'VpcConfig': func_details.vpc_config,
        'FunctionArn': func_details.arn(),
        'FunctionName': func_details.name(),
        'CodeSize': func_version.get('CodeSize'),
        'Handler': func_details.handler,
        'Runtime': func_details.runtime,
        'Timeout': func_details.timeout,
        'Description': func_details.description,
        'MemorySize': func_details.memory_size,
        'LastModified': isoformat_milliseconds(func_details.last_modified) + '+0000',
        'TracingConfig': {'Mode': 'PassThrough'},
        'RevisionId': func_version.get('RevisionId'),
        'State': 'Active',
        'LastUpdateStatus': 'Successful',
        'PackageType': func_details.package_type
    }
    if func_details.dead_letter_config:
        result['DeadLetterConfig'] = func_details.dead_letter_config

    if func_details.envvars:
        result['Environment'] = {
            'Variables': func_details.envvars
        }
    if (always_add_version or version != VERSION_LATEST) and len(result['FunctionArn'].split(':')) <= 7:
        result['FunctionArn'] += ':%s' % version
    return result


def forward_to_fallback_url(func_arn, data):
    """ If LAMBDA_FALLBACK_URL is configured, forward the invocation of this non-existing
        Lambda to the configured URL. """
    if not config.LAMBDA_FALLBACK_URL:
        return None

    lambda_name = aws_stack.lambda_function_name(func_arn)
    if config.LAMBDA_FALLBACK_URL.startswith('dynamodb://'):
        table_name = urlparse(config.LAMBDA_FALLBACK_URL.replace('dynamodb://', 'http://')).netloc
        dynamodb = aws_stack.connect_to_service('dynamodb')
        item = {
            'id': {'S': short_uid()},
            'timestamp': {'N': str(now_utc())},
            'payload': {'S': str(data)},
            'function_name': {'S': lambda_name}
        }
        aws_stack.create_dynamodb_table(table_name, partition_key='id')
        dynamodb.put_item(TableName=table_name, Item=item)
        return ''
    if re.match(r'^https?://.+', config.LAMBDA_FALLBACK_URL):
        headers = {'lambda-function-name': lambda_name}
        response = safe_requests.post(config.LAMBDA_FALLBACK_URL, data, headers=headers)
        content = response.content
        try:
            # parse the response into a dictionary to get details
            # like function error etc.
            content = json.loads(content)
        except Exception:
            pass

        return content
    raise ClientError('Unexpected value for LAMBDA_FALLBACK_URL: %s' % config.LAMBDA_FALLBACK_URL)


def get_lambda_policy(function, qualifier=None):
    iam_client = aws_stack.connect_to_service('iam')
    policies = iam_client.list_policies(Scope='Local', MaxItems=500)['Policies']
    docs = []
    for p in policies:
        # !TODO: Cache policy documents instead of running N+1 API calls here!
        versions = iam_client.list_policy_versions(PolicyArn=p['Arn'])['Versions']
        default_version = [v for v in versions if v.get('IsDefaultVersion')]
        versions = default_version or versions
        doc = versions[0]['Document']
        doc = doc if isinstance(doc, dict) else json.loads(doc)
        if not isinstance(doc['Statement'], list):
            doc['Statement'] = [doc['Statement']]
        for stmt in doc['Statement']:
            stmt['Principal'] = stmt.get('Principal') or {'AWS': TEST_AWS_ACCOUNT_ID}
        doc['PolicyArn'] = p['Arn']
        doc['Id'] = 'default'
        docs.append(doc)
    res_qualifier = func_qualifier(function, qualifier)
    policy = [d for d in docs if d['Statement'][0]['Resource'] == res_qualifier]
    return (policy or [None])[0]


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
    region = LambdaRegion.get()
    arn = 'n/a'
    try:
        if len(request.data) > FUNCTION_MAX_SIZE:
            return error_response('Request size (%s) must be smaller than %s bytes for the CreateFunction operation' %
                (len(request.data), FUNCTION_MAX_SIZE), 413, error_type='RequestEntityTooLargeException')
        data = json.loads(to_str(request.data))
        lambda_name = data['FunctionName']
        event_publisher.fire_event(event_publisher.EVENT_LAMBDA_CREATE_FUNC,
            payload={'n': event_publisher.get_hash(lambda_name)})
        arn = func_arn(lambda_name)
        if arn in region.lambdas:
            return error_response('Function already exist: %s' %
                lambda_name, 409, error_type='ResourceConflictException')
        region.lambdas[arn] = func_details = LambdaFunction(arn)
        func_details.versions = {VERSION_LATEST: {'RevisionId': str(uuid.uuid4())}}
        func_details.vpc_config = data.get('VpcConfig', {})
        func_details.last_modified = datetime.utcnow()
        func_details.description = data.get('Description', '')
        func_details.handler = data.get('Handler')
        func_details.runtime = data.get('Runtime')
        func_details.envvars = data.get('Environment', {}).get('Variables', {})
        func_details.tags = data.get('Tags', {})
        func_details.timeout = data.get('Timeout', LAMBDA_DEFAULT_TIMEOUT)
        func_details.role = data['Role']
        func_details.kms_key_arn = data.get('KMSKeyArn')
        func_details.memory_size = data.get('MemorySize')
        func_details.code_signing_config_arn = data.get('CodeSigningConfigArn')
        func_details.code = data['Code']
        func_details.package_type = 'Zip'
        func_details.set_dead_letter_config(data)
        result = set_function_code(func_details.code, lambda_name)
        if isinstance(result, Response):
            del region.lambdas[arn]
            return result
        # remove content from code attribute, if present
        func_details.code.pop('ZipFile', None)
        # prepare result
        result.update(format_func_details(func_details))
        if data.get('Publish'):
            result['Version'] = publish_new_function_version(arn)['Version']
        return jsonify(result or {})
    except Exception as e:
        region.lambdas.pop(arn, None)
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
    region = LambdaRegion.get()
    funcs = do_list_functions()
    for func in funcs:
        if func['FunctionName'] == function:
            result = {
                'Configuration': func,
                'Code': {
                    'Location': '%s/code' % request.url
                },
                'Tags': func['Tags']
            }
            lambda_details = region.lambdas.get(func['FunctionArn'])
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
    result = {
        'Functions': funcs
    }
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
    region = LambdaRegion.get()
    arn = func_arn(function)

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(arn)

    try:
        region.lambdas.pop(arn)
    except KeyError:
        return not_found_error(func_arn(function))

    event_publisher.fire_event(event_publisher.EVENT_LAMBDA_DELETE_FUNC,
        payload={'n': event_publisher.get_hash(function)})
    i = 0
    while i < len(region.event_source_mappings):
        mapping = region.event_source_mappings[i]
        if mapping['FunctionArn'] == arn:
            del region.event_source_mappings[i]
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
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return error_response('Function not found: %s' %
                arn, 400, error_type='ResourceNotFoundException')
    data = json.loads(to_str(request.data))
    result = set_function_code(data, function)
    func_details = region.lambdas.get(arn)
    result.update(format_func_details(func_details))
    if data.get('Publish'):
        result['Version'] = publish_new_function_version(arn)['Version']
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
    region = LambdaRegion.get()
    arn = func_arn(function)
    lambda_cwd = region.lambdas[arn].cwd
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
    region = LambdaRegion.get()
    arn = func_arn(function)
    lambda_details = region.lambdas.get(arn)
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
    region = LambdaRegion.get()
    data = json.loads(to_str(request.data))
    arn = func_arn(function)

    # Stop/remove any containers that this arn uses.
    LAMBDA_EXECUTOR.cleanup(arn)

    lambda_details = region.lambdas.get(arn)
    if not lambda_details:
        return error_response('Unable to find Lambda function ARN "%s"' % arn,
            404, error_type='ResourceNotFoundException')

    if data.get('Handler'):
        lambda_details.handler = data['Handler']
    if data.get('Runtime'):
        lambda_details.runtime = data['Runtime']
    lambda_details.set_dead_letter_config(data)
    env_vars = data.get('Environment', {}).get('Variables')
    if env_vars is not None:
        lambda_details.envvars = env_vars
    if data.get('Timeout'):
        lambda_details.timeout = data['Timeout']
    if data.get('Role'):
        lambda_details.role = data['Role']
    if data.get('MemorySize'):
        lambda_details.memory_size = data['MemorySize']
    if data.get('Description'):
        lambda_details.description = data['Description']
    if data.get('VpcConfig'):
        lambda_details.vpc_config = data['VpcConfig']
    if data.get('KMSKeyArn'):
        lambda_details.kms_key_arn = data['KMSKeyArn']

    return jsonify(data)


def generate_policy_statement(sid, action, arn, sourcearn, principal):
    statement = {
        'Sid': sid,
        'Effect': 'Allow',
        'Action': action,
        'Resource': arn,
    }

    # Adds SourceArn only if SourceArn is present
    if sourcearn:
        condition = {
            'ArnLike': {
                'AWS:SourceArn': sourcearn
            }
        }
        statement['Condition'] = condition

    # Adds Principal only if Principal is present
    if principal:
        principal = {
            'Service': principal
        }
        statement['Principal'] = principal

    return statement


def generate_policy(sid, action, arn, sourcearn, principal):
    new_statement = generate_policy_statement(sid, action, arn, sourcearn, principal)
    policy = {
        'Version': IAM_POLICY_VERSION,
        'Id': 'LambdaFuncAccess-%s' % sid,
        'Statement': [new_statement]
    }

    return policy


@app.route('%s/functions/<function>/policy' % PATH_ROOT, methods=['POST'])
def add_permission(function):
    region = LambdaRegion.get()

    data = json.loads(to_str(request.data))
    iam_client = aws_stack.connect_to_service('iam')
    sid = data.get('StatementId')
    action = data.get('Action')
    principal = data.get('Principal')
    sourcearn = data.get('SourceArn')
    qualifier = request.args.get('Qualifier')
    arn = func_arn(function)
    previous_policy = get_lambda_policy(function)

    if arn not in region.lambdas:
        return not_found_error(func_arn(function))

    if not re.match(r'lambda:[*]|lambda:[a-zA-Z]+|[*]', action):
        return error_response('1 validation error detected: Value "%s" at "action" failed to satisfy '
                              'constraint: Member must satisfy regular expression pattern: '
                              '(lambda:[*]|lambda:[a-zA-Z]+|[*])' % action,
                              400, error_type='ValidationException')

    q_arn = func_qualifier(function, qualifier)
    new_policy = generate_policy(sid, action, q_arn, sourcearn, principal)

    if previous_policy:
        statment_with_sid = next((statement for statement in previous_policy['Statement'] if statement['Sid'] == sid),
            None)
        if statment_with_sid:
            return error_response('The statement id (%s) provided already exists. Please provide a new statement id,'
                        ' or remove the existing statement.' % sid, 400, error_type='ResourceConflictException')

        new_policy['Statement'].extend(previous_policy['Statement'])
        iam_client.delete_policy(PolicyArn=previous_policy['PolicyArn'])

    iam_client.create_policy(PolicyName=LAMBDA_POLICY_NAME_PATTERN % function,
        PolicyDocument=json.dumps(new_policy), Description='Policy for Lambda function "%s"' % function)

    result = {'Statement': json.dumps(new_policy['Statement'][0])}
    return jsonify(result)


@app.route('%s/functions/<function>/policy/<statement>' % PATH_ROOT, methods=['DELETE'])
def remove_permission(function, statement):
    qualifier = request.args.get('Qualifier')
    iam_client = aws_stack.connect_to_service('iam')
    policy = get_lambda_policy(function)
    if not policy:
        return error_response('Unable to find policy for Lambda function "%s"' % function,
            404, error_type='ResourceNotFoundException')
    iam_client.delete_policy(PolicyArn=policy['PolicyArn'])
    result = {
        'FunctionName': function,
        'Qualifier': qualifier,
        'StatementId': policy['Statement'][0]['Sid'],
    }
    return jsonify(result)


@app.route('%s/functions/<function>/policy' % PATH_ROOT, methods=['GET'])
def get_policy(function):
    qualifier = request.args.get('Qualifier')
    policy = get_lambda_policy(function, qualifier)
    if not policy:
        return error_response('The resource you requested does not exist.',
            404, error_type='ResourceNotFoundException')
    return jsonify({'Policy': json.dumps(policy), 'RevisionId': 'test1234'})


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
    invocation_type = request.headers.get('X-Amz-Invocation-Type', 'RequestResponse')
    log_type = request.headers.get('X-Amz-Log-Type')

    def _create_response(invocation_result, status_code=200, headers={}):
        """ Create the final response for the given invocation result. """
        if not isinstance(invocation_result, lambda_executors.InvocationResult):
            invocation_result = lambda_executors.InvocationResult(invocation_result)
        result = invocation_result.result
        log_output = invocation_result.log_output
        details = {
            'StatusCode': status_code,
            'Payload': result,
            'Headers': headers
        }
        if isinstance(result, Response):
            details['Payload'] = to_str(result.data)
            if result.status_code >= 400:
                details['FunctionError'] = 'Unhandled'
        elif isinstance(result, dict):
            for key in ('StatusCode', 'Payload', 'FunctionError'):
                if result.get(key):
                    details[key] = result[key]
        # Try to parse parse payload as JSON
        was_json = False
        payload = details['Payload']
        if payload and isinstance(payload, POSSIBLE_JSON_TYPES) and payload[0] in JSON_START_CHARS:
            try:
                details['Payload'] = json.loads(details['Payload'])
                was_json = True
            except Exception:
                pass
        # Set error headers
        if details.get('FunctionError'):
            details['Headers']['X-Amz-Function-Error'] = str(details['FunctionError'])
        # LogResult contains the last 4KB (~4k characters) of log outputs
        logs = log_output[-4000:] if log_type == 'Tail' else ''
        details['Headers']['X-Amz-Log-Result'] = base64.b64encode(to_bytes(logs))
        details['Headers']['X-Amz-Executed-Version'] = str(qualifier or VERSION_LATEST)
        # Construct response object
        response_obj = details['Payload']
        if was_json or isinstance(response_obj, JSON_START_TYPES):
            response_obj = json_safe(response_obj)
            response_obj = jsonify(response_obj)
            details['Headers']['Content-Type'] = 'application/json'
        else:
            response_obj = str(response_obj)
            details['Headers']['Content-Type'] = 'text/plain'
        return response_obj, details['StatusCode'], details['Headers']

    # check if this lambda function exists
    not_found = None
    region = LambdaRegion.get()
    if arn not in region.lambdas:
        not_found = not_found_error(arn)
    elif qualifier and not region.lambdas.get(arn).qualifier_exists(qualifier):
        not_found = not_found_error('{0}:{1}'.format(arn, qualifier))

    if not_found:
        forward_result = forward_to_fallback_url(arn, data)
        if forward_result is not None:
            return _create_response(forward_result)
        return not_found

    if invocation_type == 'RequestResponse':
        context = {'client_context': request.headers.get('X-Amz-Client-Context')}
        result = run_lambda(asynchronous=False, func_arn=arn, event=data, context=context, version=qualifier)
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
def get_event_source_mappings():
    """ List event source mappings
        ---
        operationId: 'listEventSourceMappings'
    """
    region = LambdaRegion.get()
    event_source_arn = request.args.get('EventSourceArn')
    function_name = request.args.get('FunctionName')

    mappings = region.event_source_mappings
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
    region = LambdaRegion.get()
    mappings = region.event_source_mappings
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
    try:
        mapping = add_event_source(
            data['FunctionName'], data['EventSourceArn'], data.get('Enabled'), data.get('BatchSize')
        )
        return jsonify(mapping)
    except ValueError as error:
        error_type, message = error.args
        return error_response(message, code=400, error_type=error_type)


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
    batch_size = data.get('BatchSize')

    try:
        mapping = update_event_source(mapping_uuid, function_name, enabled, batch_size)
        return jsonify(mapping)
    except ValueError as error:
        error_type, message = error.args
        return error_response(message, code=400, error_type=error_type)


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
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return not_found_error(arn)
    return jsonify(publish_new_function_version(arn))


@app.route('%s/functions/<function>/versions' % PATH_ROOT, methods=['GET'])
def list_versions(function):
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return not_found_error(arn)
    return jsonify({'Versions': do_list_versions(arn)})


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['POST'])
def create_alias(function):
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return not_found_error(arn)
    data = json.loads(request.data)
    alias = data.get('Name')
    if alias in region.lambdas.get(arn).aliases:
        return error_response('Alias already exists: %s' % arn + ':' + alias, 404,
                              error_type='ResourceConflictException')
    version = data.get('FunctionVersion')
    description = data.get('Description')
    return jsonify(do_update_alias(arn, alias, version, description))


@app.route('%s/functions/<function>/aliases/<name>' % PATH_ROOT, methods=['PUT'])
def update_alias(function, name):
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return not_found_error(arn)
    if name not in region.lambdas.get(arn).aliases:
        return not_found_error(msg='Alias not found: %s:%s' % (arn, name))
    current_alias = region.lambdas.get(arn).aliases.get(name)
    data = json.loads(request.data)
    version = data.get('FunctionVersion') or current_alias.get('FunctionVersion')
    description = data.get('Description') or current_alias.get('Description')
    return jsonify(do_update_alias(arn, name, version, description))


@app.route('%s/functions/<function>/aliases/<name>' % PATH_ROOT, methods=['GET'])
def get_alias(function, name):
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return not_found_error(arn)
    if name not in region.lambdas.get(arn).aliases:
        return not_found_error(msg='Alias not found: %s:%s' % (arn, name))
    return jsonify(region.lambdas.get(arn).aliases.get(name))


@app.route('%s/functions/<function>/aliases' % PATH_ROOT, methods=['GET'])
def list_aliases(function):
    region = LambdaRegion.get()
    arn = func_arn(function)
    if arn not in region.lambdas:
        return not_found_error(arn)
    return jsonify({'Aliases': sorted(region.lambdas.get(arn).aliases.values(),
                                      key=lambda x: x['Name'])})


@app.route('/<version>/functions/<function>/concurrency', methods=['GET', 'PUT', 'DELETE'])
def function_concurrency(version, function):
    region = LambdaRegion.get()
    # the version for put_concurrency != PATH_ROOT, at the time of this
    # writing it's: /2017-10-31 for this endpoint
    # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
    arn = func_arn(function)
    lambda_details = region.lambdas.get(arn)
    if not lambda_details:
        return not_found_error(arn)
    if request.method == 'GET':
        data = lambda_details.concurrency
    if request.method == 'PUT':
        data = json.loads(request.data)
        lambda_details.concurrency = data
    if request.method == 'DELETE':
        lambda_details.concurrency = None
        return Response('', status=204)
    return jsonify(data)


@app.route('/<version>/tags/<arn>', methods=['GET'])
def list_tags(version, arn):
    region = LambdaRegion.get()
    func_details = region.lambdas.get(arn)
    if not func_details:
        return not_found_error(arn)
    result = {'Tags': func_details.tags}
    return jsonify(result)


@app.route('/<version>/tags/<arn>', methods=['POST'])
def tag_resource(version, arn):
    region = LambdaRegion.get()
    data = json.loads(request.data)
    tags = data.get('Tags', {})
    if tags:
        func_details = region.lambdas.get(arn)
        if not func_details:
            return not_found_error(arn)
        if func_details:
            func_details.tags.update(tags)
    return jsonify({})


@app.route('/<version>/tags/<arn>', methods=['DELETE'])
def untag_resource(version, arn):
    region = LambdaRegion.get()
    tag_keys = request.args.getlist('tagKeys')
    func_details = region.lambdas.get(arn)
    if not func_details:
        return not_found_error(arn)
    for tag_key in tag_keys:
        func_details.tags.pop(tag_key, None)
    return jsonify({})


@app.route('/2019-09-25/functions/<function>/event-invoke-config', methods=['PUT', 'POST'])
def put_function_event_invoke_config(function):
    # TODO: resouce validation required to check if resource exists
    """ Add/Updates the configuration for asynchronous invocation for a function
        ---
        operationId: PutFunctionEventInvokeConfig | UpdateFunctionEventInvokeConfig
        parameters:
            - name: 'function'
              in: path
            - name: 'qualifier'
              in: path
            - name: 'request'
              in: body
    """
    region = LambdaRegion.get()
    data = json.loads(to_str(request.data))
    function_arn = func_arn(function)
    lambda_obj = region.lambdas[function_arn]

    if request.method == 'PUT':
        response = lambda_obj.clear_function_event_invoke_config()
    response = lambda_obj.put_function_event_invoke_config(data)

    return jsonify({
        'LastModified': timestamp_millis(response.last_modified),
        'FunctionArn': str(function_arn),
        'MaximumRetryAttempts': response.max_retry_attempts,
        'MaximumEventAgeInSeconds': response.max_event_age,
        'DestinationConfig': {
            'OnSuccess': {
                'Destination': str(response.on_successful_invocation)
            },
            'OnFailure': {
                'Destination': str(response.on_failed_invocation)
            }
        }
    })


@app.route('/2019-09-25/functions/<function>/event-invoke-config', methods=['GET'])
def get_function_event_invoke_config(function):
    """ Retrieves the configuration for asynchronous invocation for a function
        ---
        operationId: GetFunctionEventInvokeConfig
        parameters:
            - name: 'function'
              in: path
            - name: 'qualifier'
              in: path
            - name: 'request'
              in: body
    """
    region = LambdaRegion.get()
    try:
        function_arn = func_arn(function)
        lambda_obj = region.lambdas[function_arn]
    except Exception as e:
        return error_response(str(e), 400)

    response = lambda_obj.get_function_event_invoke_config()
    return jsonify(response)


@app.route('/2019-09-25/functions/<function>/event-invoke-config', methods=['DELETE'])
def delete_function_event_invoke_config(function):
    region = LambdaRegion.get()
    try:
        function_arn = func_arn(function)
        lambda_obj = region.lambdas[function_arn]
    except Exception as e:
        return error_response(str(e), 400)

    lambda_obj.clear_function_event_invoke_config()
    return Response('', status=204)


@app.route('/2020-06-30/functions/<function>/code-signing-config', methods=['GET'])
def get_function_code_signing_config(function):
    region = LambdaRegion.get()
    function_arn = func_arn(function)
    if function_arn not in region.lambdas:
        msg = 'Function not found: %s' % (function_arn)
        return error_response(msg, 404, error_type='ResourceNotFoundException')
    lambda_obj = region.lambdas[function_arn]

    if not lambda_obj.code_signing_config_arn:
        arn = None
        function = None
    else:
        arn = lambda_obj.code_signing_config_arn

    result = {
        'CodeSigningConfigArn': arn,
        'FunctionName': function
    }
    return Response(json.dumps(result), status=200)


@app.route('/2020-06-30/functions/<function>/code-signing-config', methods=['PUT'])
def put_function_code_signing_config(function):
    region = LambdaRegion.get()
    data = json.loads(request.data)

    arn = data.get('CodeSigningConfigArn')
    if arn not in region.code_signing_configs:
        msg = """The code signing configuration cannot be found.
        Check that the provided configuration is not deleted: %s.""" % (arn)
        return error_response(msg, 404, error_type='CodeSigningConfigNotFoundException')

    function_arn = func_arn(function)
    if function_arn not in region.lambdas:
        msg = 'Function not found: %s' % (function_arn)
        return error_response(msg, 404, error_type='ResourceNotFoundException')
    lambda_obj = region.lambdas[function_arn]

    if data.get('CodeSigningConfigArn'):
        lambda_obj.code_signing_config_arn = arn

    result = {
        'CodeSigningConfigArn': arn,
        'FunctionName': function
    }

    return Response(json.dumps(result), status=200)


@app.route('/2020-06-30/functions/<function>/code-signing-config', methods=['DELETE'])
def delete_function_code_signing_config(function):
    region = LambdaRegion.get()
    function_arn = func_arn(function)
    if function_arn not in region.lambdas:
        msg = 'Function not found: %s' % (function_arn)
        return error_response(msg, 404, error_type='ResourceNotFoundException')

    lambda_obj = region.lambdas[function_arn]

    lambda_obj.code_signing_config_arn = None

    return Response('', status=204)


@app.route('/2020-04-22/code-signing-configs/', methods=['POST'])
def create_code_signing_config():
    region = LambdaRegion.get()
    data = json.loads(request.data)
    signing_profile_version_arns = data.get('AllowedPublishers').get('SigningProfileVersionArns')

    code_signing_id = 'csc-%s' % long_uid().replace('-', '')[0:17]
    arn = aws_stack.code_signing_arn(code_signing_id)

    region.code_signing_configs[arn] = CodeSigningConfig(arn, code_signing_id, signing_profile_version_arns)

    code_signing_obj = region.code_signing_configs[arn]

    if data.get('Description'):
        code_signing_obj.description = data['Description']
    if data.get('CodeSigningPolicies', {}).get('UntrustedArtifactOnDeployment'):
        code_signing_obj.untrusted_artifact_on_deployment = data['CodeSigningPolicies']['UntrustedArtifactOnDeployment']
    code_signing_obj.last_modified = isoformat_milliseconds(datetime.utcnow()) + '+0000'

    result = {
        'CodeSigningConfig': {
            'AllowedPublishers': {
                'SigningProfileVersionArns': code_signing_obj.signing_profile_version_arns
            },
            'CodeSigningConfigArn': code_signing_obj.arn,
            'CodeSigningConfigId': code_signing_obj.id,
            'CodeSigningPolicies': {
                'UntrustedArtifactOnDeployment': code_signing_obj.untrusted_artifact_on_deployment
            },
            'Description': code_signing_obj.description,
            'LastModified': code_signing_obj.last_modified
        }
    }

    return Response(json.dumps(result), status=201)


@app.route('/2020-04-22/code-signing-configs/<arn>', methods=['GET'])
def get_code_signing_config(arn):
    region = LambdaRegion.get()
    try:
        code_signing_obj = region.code_signing_configs[arn]
    except KeyError:
        msg = 'The Lambda code signing configuration %s can not be found.' % arn
        return error_response(msg, 404, error_type='ResourceNotFoundException')

    result = {
        'CodeSigningConfig': {
            'AllowedPublishers': {
                'SigningProfileVersionArns': code_signing_obj.signing_profile_version_arns
            },
            'CodeSigningConfigArn': code_signing_obj.arn,
            'CodeSigningConfigId': code_signing_obj.id,
            'CodeSigningPolicies': {
                'UntrustedArtifactOnDeployment': code_signing_obj.untrusted_artifact_on_deployment
            },
            'Description': code_signing_obj.description,
            'LastModified': code_signing_obj.last_modified
        }
    }

    return Response(json.dumps(result), status=200)


@app.route('/2020-04-22/code-signing-configs/<arn>', methods=['DELETE'])
def delete_code_signing_config(arn):
    region = LambdaRegion.get()
    try:
        region.code_signing_configs.pop(arn)
    except KeyError:
        msg = 'The Lambda code signing configuration %s can not be found.' % (arn)
        return error_response(msg, 404, error_type='ResourceNotFoundException')

    return Response('', status=204)


@app.route('/2020-04-22/code-signing-configs/<arn>', methods=['PUT'])
def update_code_signing_config(arn):
    region = LambdaRegion.get()
    try:
        code_signing_obj = region.code_signing_configs[arn]
    except KeyError:
        msg = 'The Lambda code signing configuration %s can not be found.' % (arn)
        return error_response(msg, 404, error_type='ResourceNotFoundException')

    data = json.loads(request.data)
    is_updated = False
    if data.get('Description'):
        code_signing_obj.description = data['Description']
        is_updated = True
    if data.get('AllowedPublishers', {}).get('SigningProfileVersionArns'):
        code_signing_obj.signing_profile_version_arns = data['AllowedPublishers']['SigningProfileVersionArns']
        is_updated = True
    if data.get('CodeSigningPolicies', {}).get('UntrustedArtifactOnDeployment'):
        code_signing_obj.untrusted_artifact_on_deployment = data['CodeSigningPolicies']['UntrustedArtifactOnDeployment']
        is_updated = True

    if is_updated:
        code_signing_obj.last_modified = isoformat_milliseconds(datetime.utcnow()) + '+0000'

    result = {
        'CodeSigningConfig': {
            'AllowedPublishers': {
                'SigningProfileVersionArns': code_signing_obj.signing_profile_version_arns
            },
            'CodeSigningConfigArn': code_signing_obj.arn,
            'CodeSigningConfigId': code_signing_obj.id,
            'CodeSigningPolicies': {
                'UntrustedArtifactOnDeployment': code_signing_obj.untrusted_artifact_on_deployment
            },
            'Description': code_signing_obj.description,
            'LastModified': code_signing_obj.last_modified
        }
    }

    return Response(json.dumps(result), status=200)


def serve(port, quiet=True):
    from localstack.services import generic_proxy  # moved here to fix circular import errors

    # initialize the Lambda executor
    LAMBDA_EXECUTOR.startup()

    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
