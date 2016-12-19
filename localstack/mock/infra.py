#!/usr/bin/env python

import os
import re
import sys
import time
import traceback
import logging
import requests
import json
import boto3
import __init__
from localstack.utils.aws import aws_stack
from localstack.utils import common
from localstack.utils.common import *
from localstack.mock import firehose_api, lambda_api, generic_proxy, dynamodbstreams_api
from localstack.mock.generic_proxy import GenericProxy
from localstack.constants import *

THIS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.realpath(os.path.join(THIS_PATH, '..'))

# will be set to True if user hits CTRL-C
KILLED = False

# cache table definitions - used for testing
TABLE_DEFINITIONS = {}

# constants
KINESIS_ACTION_PUT_RECORD = 'Kinesis_20131202.PutRecord'
KINESIS_ACTION_PUT_RECORDS = 'Kinesis_20131202.PutRecords'

INSTALL_DIR_INFRA = '%s/infra' % ROOT_PATH
INSTALL_DIR_NPM = '%s/node_modules' % ROOT_PATH
INSTALL_DIR_ES = '%s/elasticsearch' % INSTALL_DIR_INFRA
TMP_ARCHIVE_ES = '/tmp/localstack.es.zip'

# set up logger
LOGGER = logging.getLogger(__name__)


def do_run(cmd, async):
    if async:
        t = ShellCommandThread(cmd)
        t.start()
        TMP_THREADS.append(t)
        return t
    else:
        return run(cmd)


def install_elasticsearch():
    if not os.path.exists(INSTALL_DIR_ES):
        LOGGER.info('Downloading and installing local Elasticsearch server. This may take some time.')
        run('mkdir -p %s' % INSTALL_DIR_INFRA)
        if not os.path.exists(TMP_ARCHIVE_ES):
            run('curl -o "%s" "%s"' % (TMP_ARCHIVE_ES, ELASTICSEARCH_JAR_URL))
        cmd = 'cd %s && cp %s es.zip && unzip -q es.zip && mv elasticsearch* elasticsearch && rm es.zip'
        run(cmd % (INSTALL_DIR_INFRA, TMP_ARCHIVE_ES))


def install_kinesalite():
    target_dir = '%s/kinesalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        LOGGER.info('Downloading and installing local Kinesis server. This may take some time.')
        run('cd "%s" && npm install kinesalite' % ROOT_PATH)


def install_dynalite():
    target_dir = '%s/dynalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        LOGGER.info('Downloading and installing local DynamoDB server. This may take some time.')
        run('cd "%s" && npm install dynalite' % ROOT_PATH)


def install_component(name):
    if name == 'kinesis':
        install_kinesalite()
    elif name == 'dynamodb':
        install_dynalite()
    elif name == 'es':
        install_elasticsearch()


def install_components(names):
    common.parallelize(install_component, names)


def start_dynalite(port=DEFAULT_PORT_DYNAMODB, async=False, update_listener=None):
    install_dynalite()
    backend_port = DEFAULT_PORT_DYNAMODB_BACKEND
    cmd = '%s/node_modules/dynalite/cli.js --port %s' % (ROOT_PATH, backend_port)
    print("Starting mock DynamoDB (port %s)..." % port)
    proxy_thread = GenericProxy(port=port, forward_host='127.0.0.1:%s' %
                        backend_port, update_listener=update_listener)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)
    return do_run(cmd, async)


def start_kinesalite(port=DEFAULT_PORT_KINESIS, async=False, shard_limit=100, update_listener=None):
    install_kinesalite()
    backend_port = DEFAULT_PORT_KINESIS_BACKEND
    cmd = ('%s/node_modules/kinesalite/cli.js --shardLimit %s --port %s' %
        (ROOT_PATH, shard_limit, backend_port))
    print("Starting mock Kinesis (port %s)..." % port)
    proxy_thread = GenericProxy(port=port, forward_host='127.0.0.1:%s' %
                        backend_port, update_listener=update_listener)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)
    return do_run(cmd, async)


def start_elasticsearch(port=DEFAULT_PORT_ELASTICSEARCH, delete_data=True, async=False):
    install_elasticsearch()
    cmd = ('%s/infra/elasticsearch/bin/elasticsearch --http.port=%s --http.publish_port=%s' %
        (ROOT_PATH, port, port))
    print("Starting local Elasticsearch (port %s)..." % port)
    if delete_data:
        path = '%s/infra/elasticsearch/data/elasticsearch' % (ROOT_PATH)
        run('rm -rf %s' % path)
    return do_run(cmd, async)


def start_apigateway(port=DEFAULT_PORT_APIGATEWAY, async=False, update_listener=None):
    backend_port = DEFAULT_PORT_APIGATEWAY_BACKEND
    cmd = '%s/bin/moto_server apigateway -p%s' % (LOCALSTACK_VENV_FOLDER, backend_port)
    print("Starting mock API Gateway (port %s)..." % port)
    proxy_thread = GenericProxy(port=port, forward_host='127.0.0.1:%s' %
                        backend_port, update_listener=update_listener)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)
    return do_run(cmd, async)


def start_s3(port=DEFAULT_PORT_S3, async=False):
    cmd = '%s/bin/moto_server s3 -p%s' % (LOCALSTACK_VENV_FOLDER, port)
    print("Starting mock S3 server (port %s)..." % port)
    return do_run(cmd, async)


def start_sns(port=DEFAULT_PORT_SNS, async=False):
    cmd = '%s/bin/moto_server sns -p%s' % (LOCALSTACK_VENV_FOLDER, port)
    print("Starting mock SNS server (port %s)..." % port)
    return do_run(cmd, async)


def start_sqs(port=DEFAULT_PORT_SQS, async=False):
    cmd = '%s/bin/moto_server sqs -p%s' % (LOCALSTACK_VENV_FOLDER, port)
    print("Starting mock SQS server (port %s)..." % port)
    return do_run(cmd, async)


def start_firehose(port=DEFAULT_PORT_FIREHOSE, async=False):
    print("Starting mock Firehose (port %s)..." % port)
    if async:
        thread = FuncThread(firehose_api.serve, port, quiet=True)
        thread.start()
        TMP_THREADS.append(thread)
        return thread
    else:
        firehose_api.serve(port)


def start_dynamodbstreams(port=DEFAULT_PORT_DYNAMODBSTREAMS, async=False):
    print("Starting mock DynamoDB Streams (port %s)..." % port)
    if async:
        thread = FuncThread(dynamodbstreams_api.serve, port, quiet=True)
        thread.start()
        TMP_THREADS.append(thread)
        return thread
    else:
        firehose_api.serve(port)


def start_lambda(port=DEFAULT_PORT_LAMBDA, async=False):
    print("Starting mock Lambda (port %s)..." % port)
    lambda_api.cleanup()
    if async:
        thread = FuncThread(lambda_api.serve, port, quiet=True)
        thread.start()
        TMP_THREADS.append(thread)
        return thread
    else:
        lambda_api.serve(port)


def stop_infra():
    generic_proxy.QUIET = True
    common.cleanup(files=True, quiet=True)
    common.cleanup_resources()
    lambda_api.cleanup()
    time.sleep(1)
    # TODO: optimize this (takes too long currently)
    # check_infra(retries=2, expect_shutdown=True)


def check_infra_kinesis(expect_shutdown=False):
    out = None
    try:
        # check Kinesis
        out = aws_stack.connect_to_service(service_name='kinesis', client=True, env=ENV_DEV).list_streams()
    except Exception, e:
        pass
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['StreamNames'], list)


def check_infra_dynamodb(expect_shutdown=False):
    out = None
    try:
        # check DynamoDB
        out = aws_stack.connect_to_service(service_name='dynamodb', client=True, env=ENV_DEV).list_tables()
    except Exception, e:
        pass
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['TableNames'], list)


def check_infra_s3(expect_shutdown=False):
    out = None
    try:
        # check S3
        out = aws_stack.connect_to_service(service_name='s3', client=True, env=ENV_DEV).list_buckets()
    except Exception, e:
        pass
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['Buckets'], list)


def check_infra_elasticsearch(expect_shutdown=False):
    out = None
    try:
        # check Elasticsearch
        es = aws_stack.connect_elasticsearch()
        out = es.indices.get_aliases().keys()
    except Exception, e:
        pass
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out, list)


def check_infra(retries=5, expect_shutdown=False, apis=None, additional_checks=[]):
    try:
        # check Kinesis
        if apis is None or 'kinesis' in apis:
            check_infra_kinesis(expect_shutdown=expect_shutdown)
        # check DynamoDB
        if apis is None or 'dynamodb' in apis:
            check_infra_dynamodb(expect_shutdown=expect_shutdown)
        # check S3
        if apis is None or 's3' in apis:
            check_infra_s3(expect_shutdown=expect_shutdown)
        # check Elasticsearch
        if apis is None or 'es' in apis:
            check_infra_elasticsearch(expect_shutdown=expect_shutdown)
        for additional in additional_checks:
            additional(expect_shutdown=expect_shutdown)
    except Exception, e:
        if retries <= 0:
            print('ERROR checking state of local environment (after some retries): %s' % traceback.format_exc(e))
            raise e
        time.sleep(3)
        check_infra(retries - 1, expect_shutdown=expect_shutdown, apis=apis, additional_checks=additional_checks)


def check_aws_credentials():
    session = boto3.Session()
    credentials = session.get_credentials()
    if not credentials:
        # set temporary dummy credentials
        os.environ['AWS_ACCESS_KEY_ID'] = 'LocalStackDummyAccessKey'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'LocalStackDummySecretKey'
    session = boto3.Session()
    credentials = session.get_credentials()
    assert credentials


def start_infra(async=False, dynamodb_update_listener=None, kinesis_update_listener=None,
        apigateway_update_listener=None,
        apis=['s3', 'sns', 'sqs', 'es', 'apigateway', 'dynamodb', 'kinesis', 'dynamodbstreams', 'firehose', 'lambda']):
    try:
        if not dynamodb_update_listener:
            dynamodb_update_listener = update_dynamodb
        if not kinesis_update_listener:
            kinesis_update_listener = update_kinesis
        if not apigateway_update_listener:
            apigateway_update_listener = update_apigateway
        # set environment
        os.environ['AWS_REGION'] = DEFAULT_REGION
        os.environ['ENV'] = ENV_DEV
        # make sure AWS credentials are configured, otherwise boto3 bails on us
        check_aws_credentials()
        # install libs if not present
        install_components(apis)
        # start services
        thread = None
        if 'es' in apis:
            # delete Elasticsearch data that may be cached locally from a previous test run
            aws_stack.delete_all_elasticsearch_data()
            thread = start_elasticsearch(async=True)
        if 's3' in apis:
            thread = start_s3(async=True)
        if 'sns' in apis:
            thread = start_sns(async=True)
        if 'sqs' in apis:
            thread = start_sqs(async=True)
        if 'apigateway' in apis:
            thread = start_apigateway(async=True, update_listener=apigateway_update_listener)
        if 'dynamodb' in apis:
            thread = start_dynalite(async=True, update_listener=dynamodb_update_listener)
        if 'dynamodbstreams' in apis:
            thread = start_dynamodbstreams(async=True)
        if 'firehose' in apis:
            thread = start_firehose(async=True)
        if 'lambda' in apis:
            thread = start_lambda(async=True)
        if 'kinesis' in apis:
            thread = start_kinesalite(async=True, update_listener=kinesis_update_listener)
        # Elasticsearch and S3 take a bit to come up
        time.sleep(3)
        # check that all infra components are up and running
        check_infra(apis=apis)
        if not async and thread:
            thread.join()
        return thread
    except KeyboardInterrupt, e:
        print("Shutdown")
    finally:
        if not async:
            stop_infra()


def update_apigateway(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        # print('%s %s' % (method, path))
        regex1 = r'^/restapis/[A-Za-z0-9\-]+/deployments$'
        if method == 'POST' and re.match(regex1, path):
            # this is a request to deploy the API gateway, simply return HTTP code 200
            return 200

        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/([^/]+)$' % PATH_USER_REQUEST
        if method == 'POST' and re.match(regex2, path):
            api_id = re.search(regex2, path).group(1)
            sub_path = '/%s' % re.search(regex2, path).group(3)
            integration = aws_stack.get_apigateway_integration(api_id, method, sub_path)
            template = integration['requestTemplates'][APPLICATION_JSON]
            new_request = aws_stack.render_velocity_template(template, data)

            # forward records to our main kinesis stream
            # TODO check whether the target of this API method is 'kinesis'
            headers = aws_stack.mock_aws_request_headers(service='kinesis')
            headers['X-Amz-Target'] = 'Kinesis_20131202.PutRecords'
            result = common.make_http_request(url=TEST_KINESIS_URL,
                method='POST', data=new_request, headers=headers)
            return 200
        return True


def update_kinesis(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        return True

    action = headers['X-Amz-Target'] if 'X-Amz-Target' in headers else None
    if action == 'Kinesis_20131202.PutRecord':
        record = {
            'data': data['Data'],
            'partitionKey': data['PartitionKey']
        }
        records = [record]
        stream_name = data['StreamName']
        lambda_api.process_kinesis_records(records, stream_name)
    elif action == 'Kinesis_20131202.PutRecords':
        records = []
        for record in data['Records']:
            record = {
                'data': record['Data'],
                'partitionKey': record['PartitionKey']
            }
            records.append(record)
        stream_name = data['StreamName']
        lambda_api.process_kinesis_records(records, stream_name)


def update_dynamodb(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        return True

    # update table definitions
    if data and 'TableName' in data and 'KeySchema' in data:
        TABLE_DEFINITIONS[data['TableName']] = data

    action = headers.get('X-Amz-Target')
    if not action:
        return

    response_data = json.loads(response.text)
    record = {
        "eventID": "1",
        "eventVersion": "1.0",
        "dynamodb": {
            "StreamViewType": "NEW_AND_OLD_IMAGES",
            "SequenceNumber": "1",
            "SizeBytes": -1
        },
        "awsRegion": DEFAULT_REGION,
        "eventSource": "aws:dynamodb"
    }
    event = {
        'Records': [record]
    }

    if action == 'DynamoDB_20120810.UpdateItem':
        req = {'TableName': data['TableName']}
        req['Key'] = data['Key']
        new_item = aws_stack.dynamodb_get_item_raw(TEST_DYNAMODB_URL, req)
        if 'Item' not in new_item:
            if 'message' in new_item:
                print('WARNING: Unable to get item from DynamoDB: %s' % new_item['message'])
            return
        record['eventName'] = 'MODIFY'
        record['dynamodb']['Keys'] = data['Key']
        record['dynamodb']['NewImage'] = new_item['Item']
    elif action == 'DynamoDB_20120810.PutItem':
        record['eventName'] = 'INSERT'
        keys = dynamodb_extract_keys(item=data['Item'], table_name=data['TableName'])
        record['dynamodb']['Keys'] = keys
        record['dynamodb']['NewImage'] = data['Item']
    elif action == 'DynamoDB_20120810.DeleteItem':
        record['eventName'] = 'REMOVE'
        record['dynamodb']['Keys'] = data['Key']
    elif action == 'DynamoDB_20120810.CreateTable':
        if 'StreamSpecification' in data:
            stream = data['StreamSpecification']
            enabled = stream['StreamEnabled']
            if enabled:
                table_name = data['TableName']
                view_type = stream['StreamViewType']
                dynamodbstreams_api.add_dynamodb_stream(table_name=table_name,
                    view_type=view_type, enabled=enabled)
        return
    else:
        # nothing to do
        return
    record['eventSourceARN'] = aws_stack.dynamodb_table_arn(data['TableName'])
    sources = lambda_api.get_event_sources(source_arn=record['eventSourceARN'])
    if len(sources) > 0:
        pass
    for src in sources:
        func_to_call = lambda_api.lambda_arn_to_function[src['FunctionArn']]
        lambda_api.run_lambda(func_to_call, event=event, context={})


def dynamodb_extract_keys(item, table_name):
    result = {}
    if table_name not in TABLE_DEFINITIONS:
        print("WARN: unknown table: %s not found in %s" % (table_name, TABLE_DEFINITIONS))
        return None
    for key in TABLE_DEFINITIONS[table_name]['KeySchema']:
        attr_name = key['AttributeName']
        result[attr_name] = item[attr_name]
    return result


if __name__ == '__main__':
    print('Starting local dev environment. CTRL-C to quit.')
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger('elasticsearch').setLevel(logging.ERROR)
    start_infra()
