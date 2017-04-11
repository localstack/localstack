import json
import boto3
import uuid
import os
import time
from localstack.constants import REGION_LOCAL
from localstack.config import TEST_S3_URL
from localstack.mock.apis.lambda_api import (LAMBDA_DEFAULT_HANDLER,
    LAMBDA_DEFAULT_RUNTIME, LAMBDA_DEFAULT_STARTING_POSITION, LAMBDA_DEFAULT_TIMEOUT)
from localstack.utils.common import *
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import DynamoDB, ElasticSearch
from localstack.utils.kinesis import kinesis_connector

ARCHIVE_DIR_PATTERN = '/tmp/lambda.archive.*'
MAIN_SCRIPT_NAME = '%s.py' % LAMBDA_DEFAULT_HANDLER.split('.')[-2]


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
    table = dynamodb.create_table(TableName=table_name, KeySchema=key_schema,
        AttributeDefinitions=attr_defs, ProvisionedThroughput={
            'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10
        },
        StreamSpecification=stream_spec
    )
    time.sleep(2)
    return table


def create_lambda_archive(script, stream=None, get_content=False):
    """Utility method to create a Lambda function archive"""

    tmp_dir = ARCHIVE_DIR_PATTERN.replace('*', short_uid())
    run('mkdir -p %s' % tmp_dir)
    script_file = '%s/%s' % (tmp_dir, MAIN_SCRIPT_NAME)
    zip_file_name = 'archive.zip'
    zip_file = '%s/%s' % (tmp_dir, zip_file_name)
    save_file(script_file, script)
    # create zip file
    run('cd %s && zip -r %s *' % (tmp_dir, zip_file_name))
    if not get_content:
        TMP_FILES.append(tmp_dir)
        return zip_file
    zip_file_content = None
    with open(zip_file, "rb") as file_obj:
        zip_file_content = file_obj.read()
    run('rm -r %s' % tmp_dir)
    return zip_file_content


def create_lambda_function(func_name, zip_file, event_source_arn, handler=LAMBDA_DEFAULT_HANDLER,
        starting_position=LAMBDA_DEFAULT_STARTING_POSITION):
    """Utility method to create a new function via the Lambda API"""

    client = aws_stack.connect_to_service('lambda')
    # create function
    result = client.create_function(
        FunctionName=func_name,
        Runtime=LAMBDA_DEFAULT_RUNTIME,
        Handler=handler,
        Role=LAMBDA_TEST_ROLE,
        Code={
            'ZipFile': zip_file
        },
        Timeout=LAMBDA_DEFAULT_TIMEOUT
    )
    # create event source mapping
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
    if type(all_objects) is not list:
        all_objects = [all_objects]
    found = find_object(expected_object, all_objects)
    if not found:
        raise Exception("Expected object not found: %s in list %s" %
                        (expected_object, all_objects))


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
                for k, v in expected_object.iteritems():
                    if not find_recursive(k, v, obj):
                        all_ok = False
                        break
        if all_ok:
            return obj
    return None


def find_recursive(key, value, obj):
    if isinstance(obj, dict):
        for k, v in obj.iteritems():
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


def get_s3_client():
    return boto3.resource('s3',
        endpoint_url=TEST_S3_URL,
        config=boto3.session.Config(
            s3={'addressing_style': 'path'}))


def list_all_s3_objects():
    return map_all_s3_objects().values()


def download_s3_object(s3, bucket, path):
    tmpfile = '/tmp/%s' % str(uuid.uuid4())
    s3.Bucket(bucket).download_file(path, tmpfile)
    result = load_file(tmpfile)
    os.remove(tmpfile)
    return result


def map_all_s3_objects(to_json=True):
    s3_client = get_s3_client()
    result = {}
    for bucket in s3_client.buckets.all():
        for key in bucket.objects.all():
            value = download_s3_object(s3_client, key.bucket_name, key.key)
            if to_json:
                value = json.loads(value)
            result['%s/%s' % (key.bucket_name, key.key)] = value
    return result
