import os
import logging
from localstack.utils.kinesis import kinesis_connector


def run_kcl_with_iam_assume_role():
    env_vars = {}
    if os.environ.get('AWS_ASSUME_ROLE_ARN'):
        env_vars['AWS_ASSUME_ROLE_ARN'] = os.environ.get('AWS_ASSUME_ROLE_ARN')
        env_vars['AWS_ASSUME_ROLE_SESSION_NAME'] = os.environ.get('AWS_ASSUME_ROLE_SESSION_NAME')
        env_vars['ENV'] = os.environ.get('ENV') or 'main'

        def process_records(records):
            print(records)

        # start Kinesis client
        stream_name = 'test-foobar'
        kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            listener_func=process_records,
            env_vars=env_vars,
            kcl_log_level=logging.INFO,
            wait_until_started=True)
