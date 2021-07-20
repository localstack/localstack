import logging

import pytest

from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import create_dynamodb_table
from localstack.utils.common import short_uid

try:
    import botostubs
except ImportError:
    pass

LOG = logging.getLogger(__name__)


def _client(service):
    return aws_stack.connect_to_service(service)


@pytest.fixture(scope="class")
def dynamodb_client() -> "botostubs.DynamoDB":
    return _client("dynamodb")


@pytest.fixture(scope="class")
def s3_client() -> "botostubs.S3":
    return _client("s3")


@pytest.fixture(scope="class")
def sqs_client() -> "botostubs.SQS":
    return _client("sqs")


@pytest.fixture(scope="class")
def sns_client() -> "botostubs.SNS":
    return _client("sns")


@pytest.fixture
def dynamodb_create_table(dynamodb_client):
    tables = list()

    def factory(**kwargs) -> "botostubs.DynamoDB.CreateTableOutput":
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

    def factory(**kwargs) -> "botostubs.SQS.QueueAttributeMap":
        if "QueueName" not in kwargs:
            kwargs["QueueName"] = "test-queue-%s" % short_uid()

        response = sqs_client.create_queue(QueueName=kwargs["QueueName"])
        url = response["QueueUrl"]
        queue_urls.append(url)

        return sqs_client.get_queue_attributes(QueueUrl=url)

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
