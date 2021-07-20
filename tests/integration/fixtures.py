import logging

import pytest

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid

LOG = logging.getLogger(__name__)


def _client(service):
    return aws_stack.connect_to_service(service)


@pytest.fixture(scope="class")
def s3_client():
    return _client("s3")


@pytest.fixture(scope="class")
def sqs_client():
    return _client("sqs")


@pytest.fixture(scope="class")
def sns_client():
    return _client("sns")


@pytest.fixture
def s3_create_bucket(s3_client):
    buckets = list()

    def factory(**kwargs):
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
def s3_bucket(s3_create_bucket):
    return s3_create_bucket()


@pytest.fixture
def sqs_queue(sqs_client):
    queue_name = "test-queue-%s" % short_uid()
    response = sqs_client.create_queue(QueueName=queue_name)
    queue_url = response["QueueUrl"]
    yield sqs_client.get_queue_attributes(QueueUrl=queue_url)
    sqs_client.delete_queue(QueueUrl=queue_url)


@pytest.fixture
def sns_topic(sns_client):
    topic_name = "test-topic-%s" % short_uid()
    response = sns_client.create_topic(Name=topic_name)
    topic_arn = response["TopicArn"]
    yield sns_client.get_topic_attributes(TopicArn=topic_arn)
    sns_client.delete_topic(TopicArn=topic_arn)
