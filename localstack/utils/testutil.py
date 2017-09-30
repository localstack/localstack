import os
import json
import time
import glob
import tempfile
from six import iteritems
from localstack.constants import LOCALSTACK_ROOT_FOLDER, LOCALSTACK_VENV_FOLDER, LAMBDA_TEST_ROLE
from localstack.services.awslambda.lambda_api import (get_handler_file_from_name, LAMBDA_DEFAULT_HANDLER,
    LAMBDA_DEFAULT_RUNTIME, LAMBDA_DEFAULT_STARTING_POSITION, LAMBDA_DEFAULT_TIMEOUT)
from localstack.utils.common import run, mkdir, to_str, save_file, TMP_FILES
from localstack.utils.aws import aws_stack


ARCHIVE_DIR_PREFIX = 'lambda.archive.'


def create_dynamodb_table(table_name, partition_key, env=None, stream_view_type=None):
    """Utility method to create a DynamoDB table"""

    dynamodb = aws_stack.connect_to_service('dynamodb', env=env, client=True)
    stream_spec = {'StreamEnabled': False}
    key_schema = [{
        'AttributeName': partition_key,
        'KeyType': 'HASH'
    }]
    attr_defs = [{
        'AttributeName': partition_key,
        'AttributeType': 'S'
    }]
    if stream_view_type is not None:
        stream_spec = {
            'StreamEnabled': True,
            'StreamViewType': stream_view_type
        }
    table = None
    try:
        table = dynamodb.create_table(TableName=table_name, KeySchema=key_schema,
            AttributeDefinitions=attr_defs, ProvisionedThroughput={
                'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10
            },
            StreamSpecification=stream_spec
        )
    except Exception as e:
        if 'ResourceInUseException' in str(e):
            # Table already exists -> return table reference
            return aws_stack.connect_to_resource('dynamodb', env=env).Table(table_name)
    time.sleep(2)
    return table


def create_lambda_archive(script, stream=None, get_content=False, libs=[], runtime=None):
    """Utility method to create a Lambda function archive"""
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    TMP_FILES.append(tmp_dir)
    file_name = get_handler_file_from_name(LAMBDA_DEFAULT_HANDLER, runtime=runtime)
    script_file = '%s/%s' % (tmp_dir, file_name)
    save_file(script_file, script)
    # copy libs
    for lib in libs:
        paths = [lib, '%s.py' % lib]
        target_dir = tmp_dir
        root_folder = '%s/lib/python*/site-packages' % LOCALSTACK_VENV_FOLDER
        if lib == 'localstack':
            paths = ['localstack/*.py', 'localstack/utils']
            root_folder = LOCALSTACK_ROOT_FOLDER
            target_dir = '%s/%s/' % (tmp_dir, lib)
            mkdir(target_dir)
        for path in paths:
            file_to_copy = '%s/%s' % (root_folder, path)
            for file_path in glob.glob(file_to_copy):
                run('cp -r %s %s/' % (file_path, target_dir))

    # create zip file
    return create_zip_file(tmp_dir, get_content=True)


# TODO: Refactor this method and use built-in file operations instead of shell commands
def create_zip_file(file_path, include='*', get_content=False):
    base_dir = file_path
    if not os.path.isdir(file_path):
        base_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
        run('cp "%s" "%s"' % (file_path, base_dir))
        include = os.path.basename(file_path)
        TMP_FILES.append(base_dir)
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_DIR_PREFIX)
    zip_file_name = 'archive.zip'
    zip_file = '%s/%s' % (tmp_dir, zip_file_name)
    # create zip file
    run('cd "%s" && zip -r "%s" %s' % (base_dir, zip_file, include))
    if not get_content:
        TMP_FILES.append(tmp_dir)
        return zip_file
    zip_file_content = None
    with open(zip_file, 'rb') as file_obj:
        zip_file_content = file_obj.read()
    run('rm -r "%s"' % tmp_dir)
    return zip_file_content


def create_lambda_function(func_name, zip_file, event_source_arn=None, handler=LAMBDA_DEFAULT_HANDLER,
        starting_position=LAMBDA_DEFAULT_STARTING_POSITION, runtime=LAMBDA_DEFAULT_RUNTIME,
        envvars={}):
    """Utility method to create a new function via the Lambda API"""

    client = aws_stack.connect_to_service('lambda')
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
        Environment=dict(Variables=envvars)
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
