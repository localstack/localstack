import logging
import os
from typing import TYPE_CHECKING, List

import boto3
import botocore.config
import pytest

from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import create_dynamodb_table
from localstack.utils.common import is_alpine, short_uid

if TYPE_CHECKING:
    from mypy_boto3_apigateway import APIGatewayClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_kinesis import KinesisClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_secretsmanager import SecretsManagerClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sqs import SQSClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_stepfunctions import SFNClient

LOG = logging.getLogger(__name__)


def _client(service):
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client(service)
    # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
    config = (
        botocore.config.Config(
            connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
        )
        if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS")
        else None
    )
    return aws_stack.connect_to_service(service, config=config)


@pytest.fixture(scope="class")
def dynamodb_client() -> "DynamoDBClient":
    return _client("dynamodb")


@pytest.fixture(scope="class")
def apigateway_client() -> "APIGatewayClient":
    return _client("apigateway")


@pytest.fixture(scope="class")
def iam_client() -> "IAMClient":
    return _client("iam")


@pytest.fixture(scope="class")
def s3_client() -> "S3Client":
    return _client("s3")


@pytest.fixture(scope="class")
def sqs_client() -> "SQSClient":
    return _client("sqs")


@pytest.fixture(scope="class")
def sns_client() -> "SNSClient":
    return _client("sns")


@pytest.fixture(scope="class")
def cfn_client() -> "CloudFormationClient":
    return _client("cloudformation")


@pytest.fixture(scope="class")
def ssm_client() -> "SSMClient":
    return _client("ssm")


@pytest.fixture(scope="class")
def lambda_client() -> "LambdaClient":
    return _client("lambda")


@pytest.fixture(scope="class")
def kinesis_client() -> "KinesisClient":
    return _client("kinesis")


@pytest.fixture(scope="class")
def logs_client() -> "CloudWatchLogsClient":
    return _client("logs")


@pytest.fixture(scope="class")
def events_client() -> "EventBridgeClient":
    return _client("events")


@pytest.fixture(scope="class")
def secretsmanager_client() -> "SecretsManagerClient":
    return _client("secretsmanager")


@pytest.fixture(scope="class")
def stepfunctions_client() -> "SFNClient":
    return _client("stepfunctions")


@pytest.fixture
def dynamodb_create_table(dynamodb_client):
    tables = list()

    def factory(**kwargs):
        kwargs["client"] = dynamodb_client
        if "table_name" not in kwargs:
            kwargs["table_name"] = "test-table-%s" % short_uid()
        if "partition_key" not in kwargs:
            kwargs["partition_key"] = "id"

        kwargs["sleep_after"] = 0

        tables.append(kwargs["table_name"])

        return create_dynamodb_table(**kwargs)

    yield factory

    # cleanup
    for table in tables:
        try:
            dynamodb_client.delete_table(TableName=table)
        except Exception as e:
            LOG.debug("error cleaning up table %s: %s", table, e)


@pytest.fixture
def s3_create_bucket(s3_client):
    buckets = list()

    def factory(**kwargs) -> str:
        if "Bucket" not in kwargs:
            kwargs["Bucket"] = "test-bucket-%s" % short_uid()

        s3_client.create_bucket(**kwargs)
        buckets.append(kwargs["Bucket"])
        return kwargs["Bucket"]

    yield factory

    # cleanup
    for bucket in buckets:
        try:
            s3_client.delete_bucket(Bucket=bucket)
        except Exception as e:
            LOG.debug("error cleaning up bucket %s: %s", bucket, e)


@pytest.fixture
def s3_bucket(s3_create_bucket) -> str:
    return s3_create_bucket()


@pytest.fixture
def sqs_create_queue(sqs_client):
    queue_urls = list()

    def factory(**kwargs):
        if "QueueName" not in kwargs:
            kwargs["QueueName"] = "test-queue-%s" % short_uid()

        response = sqs_client.create_queue(QueueName=kwargs["QueueName"])
        url = response["QueueUrl"]
        queue_urls.append(url)

        return sqs_client.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])

    yield factory

    # cleanup
    for queue_url in queue_urls:
        try:
            sqs_client.delete_queue(QueueUrl=queue_url)
        except Exception as e:
            LOG.debug("error cleaning up queue %s: %s", queue_url, e)


@pytest.fixture
def sqs_queue(sqs_create_queue):
    return sqs_create_queue()


@pytest.fixture
def sns_topic(sns_client):
    # TODO: add fixture factories
    topic_name = "test-topic-%s" % short_uid()
    response = sns_client.create_topic(Name=topic_name)
    topic_arn = response["TopicArn"]
    yield sns_client.get_topic_attributes(TopicArn=topic_arn)
    sns_client.delete_topic(TopicArn=topic_arn)


# Cleanup fixtures
@pytest.fixture
def cleanup_stacks(cfn_client):
    def _cleanup_stacks(stacks: List[str]) -> None:
        for stack in stacks:
            try:
                cfn_client.delete_stack(StackName=stack)
            except Exception:
                LOG.debug(f"Failed to cleanup stack '{stack}'")

    return _cleanup_stacks


@pytest.fixture
def cleanup_changesets(cfn_client):
    def _cleanup_changesets(changesets: List[str]) -> None:
        for cs in changesets:
            try:
                cfn_client.delete_change_set(ChangeSetName=cs)
            except Exception:
                LOG.debug(f"Failed to cleanup changeset '{cs}'")

    return _cleanup_changesets


# Helpers for Cfn


@pytest.fixture
def is_change_set_created_and_available(cfn_client):
    def _is_change_set_created_and_available(change_set_id: str):
        def _inner():
            change_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
            return (
                # TODO: CREATE_FAILED should also not lead to further retries
                change_set.get("Status") == "CREATE_COMPLETE"
                and change_set.get("ExecutionStatus") == "AVAILABLE"
            )

        return _inner

    return _is_change_set_created_and_available


@pytest.fixture
def is_stack_created(cfn_client):
    def _is_stack_created(stack_id: str):
        def _inner():
            resp = cfn_client.describe_stacks(StackName=stack_id)
            s = resp["Stacks"][0]  # since the lookup  uses the id we can only get a single response
            return s.get("StackStatus") in ["CREATE_COMPLETE", "CREATE_FAILED"]

        return _inner

    return _is_stack_created


@pytest.fixture
def is_change_set_finished(cfn_client):
    def _is_change_set_finished(change_set_id: str):
        def _inner():
            check_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
            return check_set.get("ExecutionStatus") == "EXECUTE_COMPLETE"

        return _inner

    return _is_change_set_finished


only_in_alpine = pytest.mark.skipif(
    not is_alpine(),
    reason="test only applicable if run in alpine",
)
