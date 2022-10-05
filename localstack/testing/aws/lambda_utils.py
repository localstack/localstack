import json
import os
from typing import Literal

from localstack.utils.common import to_str
from localstack.utils.sync import ShortCircuitWaitException, retry
from localstack.utils.testutil import get_lambda_log_events


def update_done(client, function_name):
    """wait fn for checking 'LastUpdateStatus' of lambda"""

    def _update_done():
        last_update_status = client.get_function_configuration(FunctionName=function_name)[
            "LastUpdateStatus"
        ]
        if last_update_status == "Failed":
            raise ShortCircuitWaitException(f"Lambda Config update failed: {last_update_status=}")
        else:
            return last_update_status == "Successful"

    return _update_done


def concurrency_update_done(client, function_name, qualifier):
    """wait fn for ProvisionedConcurrencyConfig 'Status'"""

    def _concurrency_update_done():
        status = client.get_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=qualifier
        )["Status"]
        if status == "FAILED":
            raise ShortCircuitWaitException(f"Concurrency update failed: {status=}")
        else:
            return status == "READY"

    return _concurrency_update_done


def get_invoke_init_type(
    client, function_name, qualifier
) -> Literal["on-demand", "provisioned-concurrency"]:
    """check the environment in the lambda for AWS_LAMBDA_INITIALIZATION_TYPE indicating ondemand/provisioned"""
    invoke_result = client.invoke(FunctionName=function_name, Qualifier=qualifier)
    return json.loads(to_str(invoke_result["Payload"].read()))["env"][
        "AWS_LAMBDA_INITIALIZATION_TYPE"
    ]


lambda_role = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
s3_lambda_permission = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:*",
                "dynamodb:DescribeStream",
                "dynamodb:GetRecords",
                "dynamodb:GetShardIterator",
                "dynamodb:ListStreams",
                "kinesis:DescribeStream",
                "kinesis:DescribeStreamSummary",
                "kinesis:GetRecords",
                "kinesis:GetShardIterator",
                "kinesis:ListShards",
                "kinesis:ListStreams",
                "kinesis:SubscribeToShard",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": ["*"],
        }
    ],
}


def _await_event_source_mapping_state(lambda_client, uuid, state, retries=30):
    def assert_mapping_disabled():
        assert lambda_client.get_event_source_mapping(UUID=uuid)["State"] == state

    retry(assert_mapping_disabled, sleep_before=2, retries=retries)


def _await_event_source_mapping_enabled(lambda_client, uuid, retries=30):
    return _await_event_source_mapping_state(
        lambda_client=lambda_client, uuid=uuid, retries=retries, state="Enabled"
    )


def _await_dynamodb_table_active(dynamodb_client, table_name, retries=6):
    def assert_table_active():
        assert (
            dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE"
        )

    retry(assert_table_active, retries=retries, sleep_before=2)


def _get_lambda_invocation_events(logs_client, function_name, expected_num_events, retries=30):
    def get_events():
        events = get_lambda_log_events(function_name, logs_client=logs_client)
        assert len(events) == expected_num_events
        return events

    return retry(get_events, retries=retries, sleep_before=2)


def is_old_provider():
    return (
        os.environ.get("TEST_TARGET") != "AWS_CLOUD"
        and os.environ.get("PROVIDER_OVERRIDE_LAMBDA") != "asf"
    )
