#!/usr/bin/env python

import os
import re
import sys
import time
import signal
import traceback
import logging
import requests
import json
import boto3
import __init__
from localstack import constants
from localstack.utils.aws import aws_stack
from localstack.utils import common
from localstack.utils.common import *
from localstack.mock import generic_proxy
from localstack.mock.apis import firehose_api, lambda_api, dynamodbstreams_api
from localstack.mock.proxy import apigateway_listener, dynamodb_listener, kinesis_listener, sns_listener
from localstack.mock.generic_proxy import GenericProxy

THIS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.realpath(os.path.join(THIS_PATH, '..'))

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False
INFRA_STOPPED = False

INSTALL_DIR_INFRA = '%s/infra' % ROOT_PATH
INSTALL_DIR_NPM = '%s/node_modules' % ROOT_PATH
INSTALL_DIR_ES = '%s/elasticsearch' % INSTALL_DIR_INFRA
TMP_ARCHIVE_ES = '/tmp/localstack.es.zip'

# list of default APIs to be spun up
DEFAULT_APIS = ['s3', 'sns', 'sqs', 'es', 'apigateway', 'dynamodb',
    'kinesis', 'dynamodbstreams', 'firehose', 'lambda', 'redshift']

# set up logger
LOGGER = logging.getLogger(__name__)


def register_signal_handlers():
    global SIGNAL_HANDLERS_SETUP
    if SIGNAL_HANDLERS_SETUP:
        return

    # register signal handlers
    def signal_handler(signal, frame):
        stop_infra()
        os._exit(0)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    SIGNAL_HANDLERS_SETUP = True


def do_run(cmd, async):
    sys.stdout.flush()
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


def install_all_components():
    install_components(DEFAULT_APIS)


def start_proxy(port, backend_port, update_listener):
    proxy_thread = GenericProxy(port=port, forward_host='127.0.0.1:%s' %
                        backend_port, update_listener=update_listener)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)


def start_dynalite(port=DEFAULT_PORT_DYNAMODB, async=False, update_listener=None):
    install_dynalite()
    backend_port = DEFAULT_PORT_DYNAMODB_BACKEND
    cmd = '%s/node_modules/dynalite/cli.js --port %s' % (ROOT_PATH, backend_port)
    print("Starting mock DynamoDB (port %s)..." % port)
    start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def start_kinesalite(port=DEFAULT_PORT_KINESIS, async=False, shard_limit=100, update_listener=None):
    install_kinesalite()
    backend_port = DEFAULT_PORT_KINESIS_BACKEND
    cmd = ('%s/node_modules/kinesalite/cli.js --shardLimit %s --port %s' %
        (ROOT_PATH, shard_limit, backend_port))
    print("Starting mock Kinesis (port %s)..." % port)
    start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def start_elasticsearch(port=DEFAULT_PORT_ELASTICSEARCH, delete_data=True, async=False):
    install_elasticsearch()
    cmd = (('%s/infra/elasticsearch/bin/elasticsearch --network.host=0.0.0.0 ' +
        '--http.port=%s --http.publish_port=%s') % (ROOT_PATH, port, port))
    print("Starting local Elasticsearch (port %s)..." % port)
    if delete_data:
        path = '%s/infra/elasticsearch/data/elasticsearch' % (ROOT_PATH)
        run('rm -rf %s' % path)
    return do_run(cmd, async)


def start_apigateway(port=DEFAULT_PORT_APIGATEWAY, async=False, update_listener=None):
    backend_port = DEFAULT_PORT_APIGATEWAY_BACKEND
    cmd = '%s/bin/moto_server apigateway -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, backend_port, constants.BIND_HOST)
    print("Starting mock API Gateway (port %s)..." % port)
    start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def start_s3(port=DEFAULT_PORT_S3, async=False):
    cmd = '%s/bin/moto_server s3 -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, port, constants.BIND_HOST)
    print("Starting mock S3 server (port %s)..." % port)
    return do_run(cmd, async)


def start_redshift(port=DEFAULT_PORT_REDSHIFT, async=False):
    cmd = '%s/bin/moto_server redshift -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, port, constants.BIND_HOST)
    print("Starting mock Redshift server (port %s)..." % port)
    return do_run(cmd, async)


def start_sns(port=DEFAULT_PORT_SNS, async=False, update_listener=None):
    backend_port = DEFAULT_PORT_SNS_BACKEND
    cmd = '%s/bin/moto_server sns -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, backend_port, constants.BIND_HOST)
    print("Starting mock SNS server (port %s)..." % port)
    start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def start_sqs(port=DEFAULT_PORT_SQS, async=False):
    cmd = '%s/bin/moto_server sqs -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, port, constants.BIND_HOST)
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
    global INFRA_STOPPED
    if INFRA_STOPPED:
        return
    generic_proxy.QUIET = True
    common.cleanup(files=True, quiet=True)
    common.cleanup_resources()
    lambda_api.cleanup()
    time.sleep(1)
    # TODO: optimize this (takes too long currently)
    # check_infra(retries=2, expect_shutdown=True)
    INFRA_STOPPED = True


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
        apigateway_update_listener=None, sns_update_listener=None, apis=DEFAULT_APIS):
    try:
        if not dynamodb_update_listener:
            dynamodb_update_listener = dynamodb_listener.update_dynamodb
        if not kinesis_update_listener:
            kinesis_update_listener = kinesis_listener.update_kinesis
        if not apigateway_update_listener:
            apigateway_update_listener = apigateway_listener.update_apigateway
        if not sns_update_listener:
            sns_update_listener = sns_listener.update_sns
        # set environment
        os.environ['AWS_REGION'] = DEFAULT_REGION
        os.environ['ENV'] = ENV_DEV
        # register signal handlers
        register_signal_handlers()
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
            thread = start_sns(async=True, update_listener=sns_update_listener)
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
        if 'redshift' in apis:
            start_redshift(async=True)
        # Elasticsearch and S3 take a bit to come up
        time.sleep(3)
        # check that all infra components are up and running
        check_infra(apis=apis)
        print('Ready.')
        sys.stdout.flush()
        if not async and thread:
            # this is a bit of an ugly hack, but we need to make sure that we
            # stay in the execution context of the main thread, otherwise our
            # signal handlers don't work
            while True:
                time.sleep(1)
        return thread
    except KeyboardInterrupt, e:
        print("Shutdown")
    finally:
        if not async:
            stop_infra()


if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == 'install':
        print('Initializing installation.')
        install_all_components()
        print('Done.')
        sys.exit(0)

    print('Starting local dev environment. CTRL-C to quit.')
    # set up logging
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger('elasticsearch').setLevel(logging.ERROR)
    # fire it up!
    start_infra()
