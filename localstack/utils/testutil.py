import os
import json
import glob
import tempfile
import requests
import shutil
import zipfile
from six import iteritems
from localstack.constants import (LOCALSTACK_ROOT_FOLDER, LOCALSTACK_VENV_FOLDER,
    LAMBDA_TEST_ROLE, TEST_AWS_ACCOUNT_ID, DEFAULT_REGION)
from localstack.services.awslambda.lambda_api import (get_handler_file_from_name, LAMBDA_DEFAULT_HANDLER,
    LAMBDA_DEFAULT_RUNTIME, LAMBDA_DEFAULT_STARTING_POSITION, LAMBDA_DEFAULT_TIMEOUT)
from localstack.utils.common import mkdir, to_str, save_file, TMP_FILES
from localstack.utils.aws import aws_stack


ARCHIVE_DIR_PREFIX = 'lambda.archive.'


def create_lambda_archive(script, get_content=False, libs=[], runtime=None):
    """Utility method to create a Lambda function archive"""
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    TMP_FILES.append(tmp_dir)
    file_name = get_handler_file_from_name(LAMBDA_DEFAULT_HANDLER, runtime=runtime)
    script_file = os.path.join(tmp_dir, file_name)
    save_file(script_file, script)
    # copy libs
    for lib in libs:
        paths = [lib, '%s.py' % lib]
        target_dir = tmp_dir
        root_folder = os.path.join(LOCALSTACK_VENV_FOLDER, 'lib/python*/site-packages')
        if lib == 'localstack':
            paths = ['localstack/*.py', 'localstack/utils']
            root_folder = LOCALSTACK_ROOT_FOLDER
            target_dir = os.path.join(tmp_dir, lib)
            mkdir(target_dir)
        for path in paths:
            file_to_copy = os.path.join(root_folder, path)
            for file_path in glob.glob(file_to_copy):
                name = os.path.join(target_dir, file_path.split(os.path.sep)[-1])
                if os.path.isdir(file_path):
                    shutil.copytree(file_path, name)
                else:
                    shutil.copyfile(file_path, name)

    # create zip file
    return create_zip_file(tmp_dir, get_content=get_content)


def create_zip_file(file_path, get_content=False):
    base_dir = file_path
    if not os.path.isdir(file_path):
        base_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
        shutil.copy(file_path, base_dir)
        TMP_FILES.append(base_dir)
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    zip_file_name = 'archive.zip'
    full_zip_file = os.path.join(tmp_dir, zip_file_name)
    # create zip file
    with zipfile.ZipFile(full_zip_file, 'w') as zip_file:
        for root, dirs, files in os.walk(base_dir):
            for name in files:
                full_name = os.path.join(root, name)
                relative = root[len(base_dir):].lstrip(os.path.sep)
                dest = os.path.join(relative, name)
                zip_file.write(full_name, dest)
    if not get_content:
        TMP_FILES.append(tmp_dir)
        shutil.rmtree(tmp_dir)
        return full_zip_file
    zip_file_content = None
    with open(full_zip_file, 'rb') as file_obj:
        zip_file_content = file_obj.read()
    shutil.rmtree(tmp_dir)
    return zip_file_content


def create_lambda_function(func_name, zip_file, event_source_arn=None, handler=LAMBDA_DEFAULT_HANDLER,
        starting_position=LAMBDA_DEFAULT_STARTING_POSITION, runtime=LAMBDA_DEFAULT_RUNTIME,
        envvars={}, tags={}, delete=False):
    """Utility method to create a new function via the Lambda API"""

    client = aws_stack.connect_to_service('lambda')

    if delete:
        try:
            # Delete function if one already exists
            client.delete_function(FunctionName=func_name)
        except Exception:
            pass

    # create function
    client.create_function(
        FunctionName=func_name,
        Runtime=runtime,
        Handler=handler,
        Role=LAMBDA_TEST_ROLE,
        Code={
            'ZipFile': zip_file
        },
        Timeout=LAMBDA_DEFAULT_TIMEOUT,
        Environment=dict(Variables=envvars),
        Tags=tags
    )
    # create event source mapping
    if event_source_arn:
        client.create_event_source_mapping(
            FunctionName=func_name,
            EventSourceArn=event_source_arn,
            StartingPosition=starting_position
        )


def assert_objects(asserts, all_objects):
    if type(asserts) is not list:
        asserts = [asserts]
    for obj in asserts:
        assert_object(obj, all_objects)


def assert_object(expected_object, all_objects):
    # for Python 3 compatibility
    dict_values = type({}.values())
    if isinstance(all_objects, dict_values):
        all_objects = list(all_objects)
    # wrap single item in an array
    if type(all_objects) is not list:
        all_objects = [all_objects]
    found = find_object(expected_object, all_objects)
    if not found:
        raise Exception('Expected object not found: %s in list %s' % (expected_object, all_objects))


def find_object(expected_object, object_list):
    for obj in object_list:
        if isinstance(obj, list):
            found = find_object(expected_object, obj)
            if found:
                return found

        all_ok = True
        if obj != expected_object:
            if not isinstance(expected_object, dict):
                all_ok = False
            else:
                for k, v in iteritems(expected_object):
                    if not find_recursive(k, v, obj):
                        all_ok = False
                        break
        if all_ok:
            return obj
    return None


def find_recursive(key, value, obj):
    if isinstance(obj, dict):
        for k, v in iteritems(obj):
            if k == key and v == value:
                return True
            if find_recursive(key, value, v):
                return True
    elif isinstance(obj, list):
        for o in obj:
            if find_recursive(key, value, o):
                return True
    else:
        return False


def list_all_s3_objects():
    return map_all_s3_objects().values()


def download_s3_object(s3, bucket, path):
    with tempfile.SpooledTemporaryFile() as tmpfile:
        s3.Bucket(bucket).download_fileobj(path, tmpfile)
        tmpfile.seek(0)
        return to_str(tmpfile.read())


def map_all_s3_objects(to_json=True):
    s3_client = aws_stack.get_s3_client()
    result = {}
    for bucket in s3_client.buckets.all():
        for key in bucket.objects.all():
            value = download_s3_object(s3_client, key.bucket_name, key.key)
            if to_json:
                value = json.loads(value)
            result['%s/%s' % (key.bucket_name, key.key)] = value
    return result


def get_sample_arn(service, resource):
    return 'arn:aws:%s:%s:%s:%s' % (service, DEFAULT_REGION, TEST_AWS_ACCOUNT_ID, resource)


def send_describe_dynamodb_ttl_request(table_name):
    return send_dynamodb_request('', 'DescribeTimeToLive', json.dumps({'TableName': table_name}))


def send_update_dynamodb_ttl_request(table_name, ttl_status):
    return send_dynamodb_request('', 'UpdateTimeToLive', json.dumps({
        'TableName': table_name,
        'TimeToLiveSpecification': {
            'AttributeName': 'ExpireItem',
            'Enabled': ttl_status
        }
    }))


def send_dynamodb_request(path, action, request_body):
    headers = {
        'Host': 'dynamodb.amazonaws.com',
        'x-amz-target': 'DynamoDB_20120810.{}'.format(action),
        'authorization': 'some_token'
    }
    url = '{}/{}'.format(os.getenv('TEST_DYNAMODB_URL'), path)
    return requests.put(url, data=request_body, headers=headers, verify=False)


def create_sqs_queue(queue_name):
    """Utility method to create a new queue via SQS API"""

    client = aws_stack.connect_to_service('sqs')

    # create queue
    queue_url = client.create_queue(QueueName=queue_name)['QueueUrl']

    # get the queue arn
    queue_arn = client.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=['QueueArn'],
    )['Attributes']['QueueArn']

    return {
        'QueueUrl': queue_url,
        'QueueArn': queue_arn,
    }
