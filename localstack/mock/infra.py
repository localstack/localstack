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
import subprocess
import six

from localstack import constants
from localstack.config import *
from localstack.utils.aws import aws_stack
from localstack.utils import common
from localstack.utils.common import *
from localstack.mock import generic_proxy, install
from localstack.mock.install import ROOT_PATH
from localstack.mock.apis import firehose_api, lambda_api, dynamodbstreams_api, es_api
from localstack.mock.proxy import (apigateway_listener,
    dynamodb_listener, kinesis_listener, sns_listener, s3_listener)
from localstack.mock.generic_proxy import GenericProxy

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False
INFRA_STOPPED = False

# default backend host address
DEFAULT_BACKEND_HOST = '127.0.0.1'

# set up logger
LOGGER = logging.getLogger(os.path.basename(__file__))

# -----------------
# API ENTRY POINTS
# -----------------


def start_dynamodb(port=PORT_DYNAMODB, async=False, update_listener=None):
    install.install_dynalite()
    backend_port = DEFAULT_PORT_DYNAMODB_BACKEND
    ddb_data_dir_param = ''
    if DATA_DIR:
        ddb_data_dir = '%s/dynamodb' % DATA_DIR
        mkdir(ddb_data_dir)
        ddb_data_dir_param = '--path %s' % ddb_data_dir
    cmd = '%s/node_modules/dynalite/cli.js --port %s %s' % (ROOT_PATH, backend_port, ddb_data_dir_param)
    print("Starting mock DynamoDB (port %s)..." % port)
    start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def start_kinesis(port=PORT_KINESIS, async=False, shard_limit=100, update_listener=None):
    install.install_kinesalite()
    backend_port = DEFAULT_PORT_KINESIS_BACKEND
    kinesis_data_dir_param = ''
    if DATA_DIR:
        kinesis_data_dir = '%s/kinesis' % DATA_DIR
        mkdir(kinesis_data_dir)
        kinesis_data_dir_param = '--path %s' % kinesis_data_dir
    cmd = ('%s/node_modules/kinesalite/cli.js --shardLimit %s --port %s %s' %
        (ROOT_PATH, shard_limit, backend_port, kinesis_data_dir_param))
    print("Starting mock Kinesis (port %s)..." % port)
    start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def is_root():
    out = run('whoami').strip()
    return out == 'root'


def start_elasticsearch(port=PORT_ELASTICSEARCH, delete_data=True, async=False, update_listener=None):
    install.install_elasticsearch()
    backend_port = DEFAULT_PORT_ELASTICSEARCH_BACKEND
    es_data_dir = '%s/infra/elasticsearch/data' % (ROOT_PATH)
    if DATA_DIR:
        es_data_dir = '%s/elasticsearch' % DATA_DIR
    # Elasticsearch 5.x cannot be bound to 0.0.0.0 in some Docker environments,
    # hence we use the default bind address 127.0.0.0 and put a proxy in front of it
    cmd = (('ES_JAVA_OPTS=\"$ES_JAVA_OPTS -Xms200m -Xmx500m\" %s/infra/elasticsearch/bin/elasticsearch ' +
        '-E http.port=%s -E http.publish_port=%s -E path.data=%s') %
        (ROOT_PATH, backend_port, backend_port, es_data_dir))
    print("Starting local Elasticsearch (port %s)..." % port)
    if delete_data:
        run('rm -rf %s' % es_data_dir)
    # fix permissions
    run('chmod -R 777 %s/infra/elasticsearch' % ROOT_PATH)
    run('mkdir -p "%s"; chmod -R 777 "%s"' % (es_data_dir, es_data_dir))
    # start proxy and ES process
    start_proxy(port, backend_port, update_listener, quiet=True)
    if is_root():
        cmd = "su -c '%s' localstack" % cmd
    thread = do_run(cmd, async, print_output=True)
    return thread


def start_apigateway(port=PORT_APIGATEWAY, async=False, update_listener=None):
    return start_moto_server('apigateway', port, name='API Gateway', async=async,
        backend_port=DEFAULT_PORT_APIGATEWAY_BACKEND, update_listener=update_listener)


def start_s3(port=PORT_S3, async=False, update_listener=None):
    return start_moto_server('s3', port, name='S3', async=async,
        backend_port=DEFAULT_PORT_S3_BACKEND, update_listener=update_listener)


def start_sns(port=PORT_SNS, async=False, update_listener=None):
    return start_moto_server('sns', port, name='SNS', async=async,
        backend_port=DEFAULT_PORT_SNS_BACKEND, update_listener=update_listener)


def start_redshift(port=PORT_REDSHIFT, async=False):
    return start_moto_server('redshift', port, name='Redshift', async=async)


def start_sqs(port=PORT_SQS, async=False):
    return start_moto_server('sqs', port, name='SQS', async=async)


def start_route53(port=PORT_ROUTE53, async=False):
    return start_moto_server('route53', port, name='Route53', async=async)


def start_ses(port=PORT_SES, async=False):
    return start_moto_server('ses', port, name='SES', async=async)


def start_cloudformation(port=PORT_CLOUDFORMATION, async=False):
    return start_moto_server('cloudformation', port, name='CloudFormation', async=async)


def start_elasticsearch_service(port=PORT_ES, async=False):
    return start_local_api('ES', port, method=es_api.serve, async=async)


def start_firehose(port=PORT_FIREHOSE, async=False):
    return start_local_api('Firehose', port, method=firehose_api.serve, async=async)


def start_dynamodbstreams(port=PORT_DYNAMODBSTREAMS, async=False):
    return start_local_api('DynamoDB Streams', port, method=dynamodbstreams_api.serve, async=async)


def start_lambda(port=PORT_LAMBDA, async=False):
    return start_local_api('Lambda', port, method=lambda_api.serve, async=async)


# ---------------
# HELPER METHODS
# ---------------


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


def is_debug():
    return os.environ.get('DEBUG')


def do_run(cmd, async, print_output=False):
    sys.stdout.flush()
    if async:
        if is_debug():
            print_output = True
        outfile = subprocess.PIPE if print_output else None
        t = ShellCommandThread(cmd, outfile=outfile)
        t.start()
        TMP_THREADS.append(t)
        return t
    else:
        return run(cmd)


def start_proxy(port, backend_port, update_listener, quiet=False, backend_host=DEFAULT_BACKEND_HOST):
    proxy_thread = GenericProxy(port=port, forward_host='%s:%s' % (backend_host, backend_port),
                        update_listener=update_listener, quiet=quiet)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)


def start_moto_server(key, port, name=None, backend_port=None, async=False, update_listener=None):
    cmd = '%s/bin/moto_server %s -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, key,
        backend_port or port, constants.BIND_HOST)
    if not name:
        name = key
    print("Starting mock %s (port %s)..." % (name, port))
    if backend_port:
        start_proxy(port, backend_port, update_listener)
    return do_run(cmd, async)


def start_local_api(name, port, method, async=False):
    print("Starting mock %s service (port %s)..." % (name, port))
    if async:
        thread = FuncThread(method, port, quiet=True)
        thread.start()
        TMP_THREADS.append(thread)
        return thread
    else:
        method(port)


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


# -----------------------------
# INFRASTRUCTURE HEALTH CHECKS
# -----------------------------


def check_infra_kinesis(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check Kinesis
        out = aws_stack.connect_to_service(service_name='kinesis', client=True, env=ENV_DEV).list_streams()
    except Exception as e:
        if print_error:
            LOGGER.error('Kinesis health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['StreamNames'], list)


def check_infra_dynamodb(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check DynamoDB
        out = aws_stack.connect_to_service(service_name='dynamodb', client=True, env=ENV_DEV).list_tables()
    except Exception as e:
        if print_error:
            LOGGER.error('DynamoDB health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['TableNames'], list)


def check_infra_s3(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check S3
        out = aws_stack.connect_to_service(service_name='s3', client=True, env=ENV_DEV).list_buckets()
    except Exception as e:
        if print_error:
            LOGGER.error('S3 health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out['Buckets'], list)


def check_infra_elasticsearch(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check Elasticsearch
        es = aws_stack.connect_elasticsearch()
        out = es.cat.aliases()
    except Exception as e:
        if print_error:
            LOGGER.error('Elasticsearch health check failed: %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out, six.string_types)


def check_infra(retries=8, expect_shutdown=False, apis=None, additional_checks=[]):
    try:
        print_error = retries <= 0
        # check Kinesis
        if apis is None or 'kinesis' in apis:
            check_infra_kinesis(expect_shutdown=expect_shutdown, print_error=print_error)
        # check DynamoDB
        if apis is None or 'dynamodb' in apis:
            check_infra_dynamodb(expect_shutdown=expect_shutdown, print_error=print_error)
        # check S3
        if apis is None or 's3' in apis:
            check_infra_s3(expect_shutdown=expect_shutdown, print_error=print_error)
        # check Elasticsearch
        if apis is None or 'es' in apis:
            check_infra_elasticsearch(expect_shutdown=expect_shutdown, print_error=print_error)
        for additional in additional_checks:
            additional(expect_shutdown=expect_shutdown)
    except Exception as e:
        if retries <= 0:
            LOGGER.error('Error checking state of local environment (after some retries): %s' % traceback.format_exc())
            raise e
        time.sleep(3)
        check_infra(retries - 1, expect_shutdown=expect_shutdown, apis=apis, additional_checks=additional_checks)


# -------------
# MAIN STARTUP
# -------------


def start_infra(async=False,
        dynamodb_update_listener=None, kinesis_update_listener=None,
        apigateway_update_listener=None, sns_update_listener=None,
        s3_update_listener=None, apis=None):
    try:
        if not apis:
            apis = list(SERVICE_PORTS.keys())
        if not dynamodb_update_listener:
            dynamodb_update_listener = dynamodb_listener.update_dynamodb
        if not kinesis_update_listener:
            kinesis_update_listener = kinesis_listener.update_kinesis
        if not apigateway_update_listener:
            apigateway_update_listener = apigateway_listener.update_apigateway
        if not sns_update_listener:
            sns_update_listener = sns_listener.update_sns
        if not s3_update_listener:
            s3_update_listener = s3_listener.update_s3
        # set environment
        os.environ['AWS_REGION'] = DEFAULT_REGION
        os.environ['ENV'] = ENV_DEV
        # register signal handlers
        register_signal_handlers()
        # make sure AWS credentials are configured, otherwise boto3 bails on us
        check_aws_credentials()
        # install libs if not present
        install.install_components(apis)
        # Some services take a bit to come up
        sleep_time = 2
        # start services
        thread = None
        if 'elasticsearch' in apis or 'es' in apis:
            # delete Elasticsearch data that may be cached locally from a previous test run
            aws_stack.delete_all_elasticsearch_data()
            # run actual Elasticsearch endpoint
            thread = start_elasticsearch(async=True)
            sleep_time = max(sleep_time, 6)
        if 'es' in apis:
            # run Elasticsearch Service (ES) endpoint
            thread = start_elasticsearch_service(async=True)
        if 's3' in apis:
            thread = start_s3(async=True, update_listener=s3_update_listener)
            sleep_time = max(sleep_time, 3)
        if 'sns' in apis:
            thread = start_sns(async=True, update_listener=sns_update_listener)
        if 'sqs' in apis:
            thread = start_sqs(async=True)
        if 'apigateway' in apis:
            thread = start_apigateway(async=True, update_listener=apigateway_update_listener)
        if 'dynamodb' in apis:
            thread = start_dynamodb(async=True, update_listener=dynamodb_update_listener)
        if 'dynamodbstreams' in apis:
            thread = start_dynamodbstreams(async=True)
        if 'firehose' in apis:
            thread = start_firehose(async=True)
        if 'lambda' in apis:
            thread = start_lambda(async=True)
        if 'kinesis' in apis:
            thread = start_kinesis(async=True, update_listener=kinesis_update_listener)
        if 'redshift' in apis:
            thread = start_redshift(async=True)
        if 'route53' in apis:
            thread = start_route53(async=True)
        if 'ses' in apis:
            thread = start_ses(async=True)
        if 'cloudformation' in apis:
            thread = start_cloudformation(async=True)
        time.sleep(sleep_time)
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
    except KeyboardInterrupt as e:
        print("Shutdown")
    finally:
        if not async:
            stop_infra()


if __name__ == '__main__':

    print('Starting local dev environment. CTRL-C to quit.')
    # set up logging
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger('elasticsearch').setLevel(logging.ERROR)
    LOGGER.setLevel(logging.INFO)
    # fire it up!
    start_infra()
