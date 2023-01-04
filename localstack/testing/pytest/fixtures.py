import contextlib
import dataclasses
import json
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

import boto3
import botocore.auth
import botocore.config
import botocore.credentials
import botocore.session
import pytest
from _pytest.config import Config
from _pytest.nodes import Item
from botocore.exceptions import ClientError
from botocore.regions import EndpointResolver
from moto.core import BackendDict, BaseBackend
from pytest_httpserver import HTTPServer

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.testing.aws.cloudformation_utils import load_template_file, render_template
from localstack.testing.aws.util import get_lambda_logs
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.client import SigningHttpClient
from localstack.utils.aws.resources import create_dynamodb_table
from localstack.utils.collections import ensure_list
from localstack.utils.functions import run_safe
from localstack.utils.http import safe_requests as requests
from localstack.utils.net import wait_for_port_open
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import ShortCircuitWaitException, poll_condition, retry, wait_until
from localstack.utils.testutil import start_http_server

if TYPE_CHECKING:
    from mypy_boto3_acm import ACMClient
    from mypy_boto3_apigateway import APIGatewayClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_cognito_idp import CognitoIdentityProviderClient
    from mypy_boto3_dynamodb import DynamoDBClient, DynamoDBServiceResource
    from mypy_boto3_dynamodbstreams import DynamoDBStreamsClient
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_ecr import ECRClient
    from mypy_boto3_es import ElasticsearchServiceClient
    from mypy_boto3_events import EventBridgeClient
    from mypy_boto3_firehose import FirehoseClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_kinesis import KinesisClient
    from mypy_boto3_kms import KMSClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_opensearch import OpenSearchServiceClient
    from mypy_boto3_redshift import RedshiftClient
    from mypy_boto3_resource_groups import ResourceGroupsClient
    from mypy_boto3_resourcegroupstaggingapi import ResourceGroupsTaggingAPIClient
    from mypy_boto3_route53 import Route53Client
    from mypy_boto3_route53resolver import Route53ResolverClient
    from mypy_boto3_s3 import S3Client, S3ServiceResource
    from mypy_boto3_s3control import S3ControlClient
    from mypy_boto3_secretsmanager import SecretsManagerClient
    from mypy_boto3_ses import SESClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sns.type_defs import GetTopicAttributesResponseTypeDef
    from mypy_boto3_sqs import SQSClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_stepfunctions import SFNClient
    from mypy_boto3_sts import STSClient
    from mypy_boto3_transcribe import TranscribeClient

LOG = logging.getLogger(__name__)


def is_pro_enabled() -> bool:
    """Return whether the Pro extensions are enabled, i.e., restricted modules can be imported"""
    try:
        import localstack_ext.utils.common  # noqa

        return True
    except Exception:
        return False


# marker to indicate that a test should be skipped if the Pro extensions are enabled
skip_if_pro_enabled = pytest.mark.skipif(
    condition=is_pro_enabled(), reason="skipping, as Pro extensions are enabled"
)


def _client(service, region_name=None, aws_access_key_id=None, *, additional_config=None):
    config = botocore.config.Config()

    # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
    if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS"):
        config = config.merge(
            botocore.config.Config(
                connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
            )
        )

    if additional_config:
        config = config.merge(additional_config)

    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client(service, region_name=region_name, config=config)

    return aws_stack.create_external_boto_client(
        service, config=config, region_name=region_name, aws_access_key_id=aws_access_key_id
    )


def _resource(service):
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.resource(service)
    # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
    config = (
        botocore.config.Config(
            connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
        )
        if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS")
        else None
    )
    return aws_stack.connect_to_resource_external(service, config=config)


@pytest.fixture(scope="class")
def create_boto_client():
    return _client


@pytest.fixture(scope="class")
def boto3_session():
    if os.environ.get("TEST_TARGET", "") == "AWS_CLOUD":
        return boto3.Session()

    return boto3.Session(
        # LocalStack assumes AWS_ACCESS_KEY_ID config contains the AWS_ACCOUNT_ID value.
        aws_access_key_id=get_aws_account_id(),
        aws_secret_access_key="__test_key__",
    )


@pytest.fixture(scope="class")
def aws_http_client_factory(boto3_session):
    """
    Returns a factory for creating new ``SigningHttpClient`` instances using a configurable botocore request signer.
    The default signer is a SigV4QueryAuth. The credentials are extracted from the ``boto3_sessions`` fixture that
    transparently uses your global profile when TEST_TARGET=AWS_CLOUD, or test credentials when running against
    LocalStack.

    Example invocations

        client = aws_signing_http_client_factory("sqs")
        client.get("http://localhost:4566/000000000000/my-queue")

    or
        client = aws_signing_http_client_factory("dynamodb", signer_factory=SigV4Auth)
        client.post("...")
    """

    def factory(
        service: str,
        region: str = None,
        signer_factory: Callable[
            [botocore.credentials.Credentials, str, str], botocore.auth.BaseSigner
        ] = botocore.auth.SigV4QueryAuth,
        endpoint_url: str = None,
    ):
        region = region or boto3_session.region_name
        region = region or config.DEFAULT_REGION

        credentials = boto3_session.get_credentials()
        creds = credentials.get_frozen_credentials()

        if not endpoint_url:
            if os.environ.get("TEST_TARGET", "") == "AWS_CLOUD":
                # FIXME: this is a bit raw. we should probably re-use boto in a better way
                resolver: EndpointResolver = boto3_session._session.get_component(
                    "endpoint_resolver"
                )
                endpoint_url = "https://" + resolver.construct_endpoint(service, region)["hostname"]
            else:
                endpoint_url = config.get_edge_url()

        return SigningHttpClient(signer_factory(creds, service, region), endpoint_url=endpoint_url)

    return factory


@pytest.fixture(scope="class")
def dynamodb_client() -> "DynamoDBClient":
    return _client("dynamodb")


@pytest.fixture(scope="class")
def dynamodb_resource() -> "DynamoDBServiceResource":
    return _resource("dynamodb")


@pytest.fixture(scope="class")
def dynamodbstreams_client() -> "DynamoDBStreamsClient":
    return _client("dynamodbstreams")


@pytest.fixture(scope="class")
def apigateway_client() -> "APIGatewayClient":
    return _client("apigateway")


@pytest.fixture(scope="class")
def cognito_idp_client() -> "CognitoIdentityProviderClient":
    return _client("cognito-idp")


@pytest.fixture(scope="class")
def iam_client() -> "IAMClient":
    return _client("iam")


@pytest.fixture(scope="class")
def s3_client() -> "S3Client":
    return _client("s3")


@pytest.fixture(scope="class")
def s3_vhost_client() -> "S3Client":
    boto_config = botocore.config.Config(s3={"addressing_style": "virtual"})
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client("s3", config=boto_config)
    # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
    if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS"):
        external_boto_config = botocore.config.Config(
            connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
        )
        boto_config = boto_config.merge(external_boto_config)

    return aws_stack.create_external_boto_client("s3", config=boto_config)


@pytest.fixture(scope="class")
def s3_presigned_client() -> "S3Client":
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return _client("s3")
    # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
    boto_config = (
        botocore.config.Config(
            connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
        )
        if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS")
        else None
    )
    return aws_stack.connect_to_service(
        "s3",
        config=boto_config,
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
    )


@pytest.fixture(scope="class")
def s3_resource() -> "S3ServiceResource":
    return _resource("s3")


@pytest.fixture(scope="class")
def s3control_client() -> "S3ControlClient":
    return _client("s3control")


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
def kms_client() -> "KMSClient":
    return _client("kms")


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


@pytest.fixture(scope="class")
def ses_client() -> "SESClient":
    return _client("ses")


@pytest.fixture(scope="class")
def acm_client() -> "ACMClient":
    return _client("acm")


@pytest.fixture(scope="class")
def es_client() -> "ElasticsearchServiceClient":
    return _client("es")


@pytest.fixture(scope="class")
def opensearch_client() -> "OpenSearchServiceClient":
    return _client("opensearch")


@pytest.fixture(scope="class")
def redshift_client() -> "RedshiftClient":
    return _client("redshift")


@pytest.fixture(scope="class")
def firehose_client() -> "FirehoseClient":
    return _client("firehose")


@pytest.fixture(scope="class")
def cloudwatch_client() -> "CloudWatchClient":
    return _client("cloudwatch")


@pytest.fixture(scope="class")
def sts_client() -> "STSClient":
    return _client("sts")


@pytest.fixture(scope="class")
def ec2_client() -> "EC2Client":
    return _client("ec2")


@pytest.fixture(scope="class")
def rg_client() -> "ResourceGroupsClient":
    return _client("resource-groups")


@pytest.fixture(scope="class")
def rgsa_client() -> "ResourceGroupsTaggingAPIClient":
    return _client("resourcegroupstaggingapi")


@pytest.fixture(scope="class")
def route53_client() -> "Route53Client":
    return _client("route53")


@pytest.fixture(scope="class")
def route53resolver_client() -> "Route53ResolverClient":
    return _client("route53resolver")


@pytest.fixture(scope="class")
def transcribe_client() -> "TranscribeClient":
    return _client("transcribe")


@pytest.fixture(scope="class")
def ecr_client() -> "ECRClient":
    return _client("ecr")


@pytest.fixture
def dynamodb_wait_for_table_active(dynamodb_client):
    def wait_for_table_active(table_name: str, client=None):
        def wait():
            return (client or dynamodb_client).describe_table(TableName=table_name)["Table"][
                "TableStatus"
            ] == "ACTIVE"

        poll_condition(wait, timeout=30)

    return wait_for_table_active


@pytest.fixture
def dynamodb_create_table_with_parameters(dynamodb_client, dynamodb_wait_for_table_active):
    tables = []

    def factory(**kwargs):
        if "TableName" not in kwargs:
            kwargs["TableName"] = f"test-table-{short_uid()}"

        tables.append(kwargs["TableName"])
        response = dynamodb_client.create_table(**kwargs)
        dynamodb_wait_for_table_active(kwargs["TableName"])
        return response

    yield factory

    # cleanup
    for table in tables:
        try:
            # table has to be in ACTIVE state before deletion
            dynamodb_wait_for_table_active(table)
            dynamodb_client.delete_table(TableName=table)
        except Exception as e:
            LOG.debug("error cleaning up table %s: %s", table, e)


@pytest.fixture
def dynamodb_create_table(dynamodb_client, dynamodb_wait_for_table_active):
    # beware, this swallows exception in create_dynamodb_table utility function
    tables = []

    def factory(**kwargs):
        kwargs["client"] = dynamodb_client
        if "table_name" not in kwargs:
            kwargs["table_name"] = "test-table-%s" % short_uid()
        if "partition_key" not in kwargs:
            kwargs["partition_key"] = "id"

        tables.append(kwargs["table_name"])

        return create_dynamodb_table(**kwargs)

    yield factory

    # cleanup
    for table in tables:
        try:
            # table has to be in ACTIVE state before deletion
            dynamodb_wait_for_table_active(table)
            dynamodb_client.delete_table(TableName=table)
        except Exception as e:
            LOG.debug("error cleaning up table %s: %s", table, e)


@pytest.fixture
def s3_create_bucket(s3_client, s3_resource):
    buckets = []

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
            bucket = s3_resource.Bucket(bucket)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            bucket.delete()
        except Exception as e:
            LOG.debug("error cleaning up bucket %s: %s", bucket, e)


@pytest.fixture
def s3_bucket(s3_client, s3_create_bucket) -> str:
    region = s3_client.meta.region_name
    kwargs = {}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    return s3_create_bucket(**kwargs)


@pytest.fixture
def sqs_create_queue(sqs_client):
    queue_urls = []

    def factory(**kwargs):
        if "QueueName" not in kwargs:
            kwargs["QueueName"] = "test-queue-%s" % short_uid()

        response = sqs_client.create_queue(**kwargs)
        url = response["QueueUrl"]
        queue_urls.append(url)

        return url

    yield factory

    # cleanup
    for queue_url in queue_urls:
        try:
            sqs_client.delete_queue(QueueUrl=queue_url)
        except Exception as e:
            LOG.debug("error cleaning up queue %s: %s", queue_url, e)


@pytest.fixture
def sqs_receive_messages_delete(sqs_client):
    def factory(
        queue_url: str,
        expected_messages: Optional[int] = None,
        wait_time: Optional[int] = 5,
    ):
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=wait_time,
        )
        messages = []
        for m in response["Messages"]:
            message = json.loads(to_str(m["Body"]))
            messages.append(message)

        if expected_messages is not None:
            assert len(messages) == expected_messages

        for message in response["Messages"]:
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])

        return messages

    return factory


@pytest.fixture
def sqs_receive_num_messages(sqs_receive_messages_delete):
    def factory(queue_url: str, expected_messages: int, max_iterations: int = 3):
        all_messages = []
        for _ in range(max_iterations):
            try:
                messages = sqs_receive_messages_delete(queue_url, wait_time=5)
            except KeyError:
                # there were no messages
                continue
            all_messages.extend(messages)

            if len(all_messages) >= expected_messages:
                return all_messages[:expected_messages]

        raise AssertionError(f"max iterations reached with {len(all_messages)} messages received")

    return factory


@pytest.fixture
def sqs_queue(sqs_create_queue):
    return sqs_create_queue()


@pytest.fixture
def sqs_queue_arn(sqs_client):
    def _get_arn(queue_url: str) -> str:
        return sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]

    return _get_arn


@pytest.fixture
def sqs_queue_exists(sqs_client):
    def _queue_exists(queue_url: str) -> bool:
        """
        Checks whether a queue with the given queue URL exists.
        :param queue_url: the queue URL
        :return: true if the queue exists, false otherwise
        """
        try:
            result = sqs_client.get_queue_url(QueueName=queue_url.split("/")[-1])
            return result.get("QueueUrl") == queue_url
        except ClientError as e:
            if "NonExistentQueue" in e.response["Error"]["Code"]:
                return False
            raise

    yield _queue_exists


@pytest.fixture
def sns_create_topic(sns_client):
    topic_arns = []

    def _create_topic(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = "test-topic-%s" % short_uid()
        response = sns_client.create_topic(**kwargs)
        topic_arns.append(response["TopicArn"])
        return response

    yield _create_topic

    for topic_arn in topic_arns:
        try:
            sns_client.delete_topic(TopicArn=topic_arn)
        except Exception as e:
            LOG.debug("error cleaning up topic %s: %s", topic_arn, e)


@pytest.fixture
def sns_wait_for_topic_delete(sns_client):
    def wait_for_topic_delete(topic_arn: str) -> None:
        def wait():
            try:
                sns_client.get_topic_attributes(TopicArn=topic_arn)
                return False
            except Exception as e:
                if "NotFound" in e.response["Error"]["Code"]:
                    return True

                raise

        poll_condition(wait, timeout=30)

    return wait_for_topic_delete


@pytest.fixture
def sns_subscription(sns_client):
    sub_arns = []

    def _create_sub(**kwargs):
        if kwargs.get("ReturnSubscriptionArn") is None:
            kwargs["ReturnSubscriptionArn"] = True

        # requires 'TopicArn', 'Protocol', and 'Endpoint'
        response = sns_client.subscribe(**kwargs)
        sub_arn = response["SubscriptionArn"]
        sub_arns.append(sub_arn)
        return response

    yield _create_sub

    for sub_arn in sub_arns:
        try:
            sns_client.unsubscribe(SubscriptionArn=sub_arn)
        except Exception as e:
            LOG.debug(f"error cleaning up subscription {sub_arn}: {e}")


@pytest.fixture
def sns_topic(sns_client, sns_create_topic) -> "GetTopicAttributesResponseTypeDef":
    topic_arn = sns_create_topic()["TopicArn"]
    return sns_client.get_topic_attributes(TopicArn=topic_arn)


@pytest.fixture
def sns_allow_topic_sqs_queue(sqs_client):
    def _allow_sns_topic(sqs_queue_url, sqs_queue_arn, sns_topic_arn) -> None:
        # allow topic to write to sqs queue
        sqs_client.set_queue_attributes(
            QueueUrl=sqs_queue_url,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": sqs_queue_arn,
                                "Condition": {"ArnEquals": {"aws:SourceArn": sns_topic_arn}},
                            }
                        ]
                    }
                )
            },
        )

    return _allow_sns_topic


@pytest.fixture
def sns_create_sqs_subscription(sns_client, sqs_client, sns_allow_topic_sqs_queue):
    subscriptions = []

    def _factory(topic_arn: str, queue_url: str) -> Dict[str, str]:
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]

        # connect sns topic to sqs
        subscription = sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
        )
        subscription_arn = subscription["SubscriptionArn"]

        # allow topic to write to sqs queue
        sns_allow_topic_sqs_queue(
            sqs_queue_url=queue_url, sqs_queue_arn=queue_arn, sns_topic_arn=topic_arn
        )

        subscriptions.append(subscription_arn)
        return sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)[
            "Attributes"
        ]

    yield _factory

    for arn in subscriptions:
        try:
            sns_client.unsubscribe(SubscriptionArn=arn)
        except Exception as e:
            LOG.error("error cleaning up subscription %s: %s", arn, e)


@pytest.fixture
def sns_create_http_endpoint(sns_client, sns_create_topic, sns_subscription):
    http_servers = []

    def _create_http_endpoint(
        raw_message_delivery: bool = False,
    ) -> Tuple[str, str, str, HTTPServer]:
        server = HTTPServer()
        server.start()
        http_servers.append(server)
        server.expect_request("/sns-endpoint").respond_with_data(status=200)
        endpoint_url = server.url_for("/sns-endpoint")
        wait_for_port_open(endpoint_url)

        topic_arn = sns_create_topic()["TopicArn"]
        subscription = sns_subscription(TopicArn=topic_arn, Protocol="http", Endpoint=endpoint_url)
        subscription_arn = subscription["SubscriptionArn"]
        delivery_policy = {
            "healthyRetryPolicy": {
                "minDelayTarget": 1,
                "maxDelayTarget": 1,
                "numRetries": 0,
                "numNoDelayRetries": 0,
                "numMinDelayRetries": 0,
                "numMaxDelayRetries": 0,
                "backoffFunction": "linear",
            },
            "sicklyRetryPolicy": None,
            "throttlePolicy": {"maxReceivesPerSecond": 1000},
            "guaranteed": False,
        }
        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="DeliveryPolicy",
            AttributeValue=json.dumps(delivery_policy),
        )

        if raw_message_delivery:
            sns_client.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            )

        return topic_arn, subscription_arn, endpoint_url, server

    yield _create_http_endpoint

    for http_server in http_servers:
        if http_server.is_running():
            http_server.stop()


@pytest.fixture
def route53_hosted_zone(route53_client):
    hosted_zones = []

    def factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"www.{short_uid()}.com."
        if "CallerReference" not in kwargs:
            kwargs["CallerReference"] = f"caller-ref-{short_uid()}"
        response = route53_client.create_hosted_zone(
            Name=kwargs["Name"], CallerReference=kwargs["CallerReference"]
        )
        hosted_zones.append(response["HostedZone"]["Id"])
        return response

    yield factory

    for zone in hosted_zones:
        try:
            route53_client.delete_hosted_zone(Id=zone)
        except Exception as e:
            LOG.debug(f"error cleaning up route53 HostedZone {zone}: {e}")


@pytest.fixture
def transcribe_create_job(transcribe_client, s3_client, s3_bucket):
    job_names = []

    def _create_job(audio_file: str, params: Optional[dict[str, Any]] = None) -> str:
        s3_key = "test-clip.wav"

        if not params:
            params = {}

        if "TranscriptionJobName" not in params:
            params["TranscriptionJobName"] = f"test-transcribe-{short_uid()}"

        if "LanguageCode" not in params:
            params["LanguageCode"] = "en-GB"

        if "Media" not in params:
            params["Media"] = {"MediaFileUri": f"s3://{s3_bucket}/{s3_key}"}

        # upload test wav to a s3 bucket
        with open(audio_file, "rb") as f:
            s3_client.upload_fileobj(f, s3_bucket, s3_key)

        transcribe_client.start_transcription_job(**params)

        job_names.append(params["TranscriptionJobName"])

        return params["TranscriptionJobName"]

    yield _create_job

    for job_name in job_names:
        with contextlib.suppress(ClientError):
            transcribe_client.delete_transcription_job(TranscriptionJobName=job_name)


@pytest.fixture
def kinesis_create_stream(kinesis_client):
    stream_names = []

    def _create_stream(**kwargs):
        if "StreamName" not in kwargs:
            kwargs["StreamName"] = f"test-stream-{short_uid()}"
        kinesis_client.create_stream(**kwargs)
        stream_names.append(kwargs["StreamName"])
        return kwargs["StreamName"]

    yield _create_stream

    for stream_name in stream_names:
        try:
            kinesis_client.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
        except Exception as e:
            LOG.debug("error cleaning up kinesis stream %s: %s", stream_name, e)


@pytest.fixture
def wait_for_stream_ready(kinesis_client):
    def _wait_for_stream_ready(stream_name: str):
        def is_stream_ready():
            describe_stream_response = kinesis_client.describe_stream(StreamName=stream_name)
            return describe_stream_response["StreamDescription"]["StreamStatus"] in [
                "ACTIVE",
                "UPDATING",
            ]

        poll_condition(is_stream_ready)

    return _wait_for_stream_ready


@pytest.fixture
def wait_for_delivery_stream_ready(firehose_client):
    def _wait_for_stream_ready(delivery_stream_name: str):
        def is_stream_ready():
            describe_stream_response = firehose_client.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
            return (
                describe_stream_response["DeliveryStreamDescription"]["DeliveryStreamStatus"]
                == "ACTIVE"
            )

        poll_condition(is_stream_ready)

    return _wait_for_stream_ready


@pytest.fixture
def wait_for_dynamodb_stream_ready(dynamodbstreams_client):
    def _wait_for_stream_ready(stream_arn: str):
        def is_stream_ready():
            describe_stream_response = dynamodbstreams_client.describe_stream(StreamArn=stream_arn)
            return describe_stream_response["StreamDescription"]["StreamStatus"] == "ENABLED"

        poll_condition(is_stream_ready)

    return _wait_for_stream_ready


@pytest.fixture()
def kms_create_key(create_boto_client):
    key_ids = []

    def _create_key(region=None, **kwargs):
        if "Description" not in kwargs:
            kwargs["Description"] = f"test description - {short_uid()}"
        key_metadata = create_boto_client("kms", region).create_key(**kwargs)["KeyMetadata"]
        key_ids.append((region, key_metadata["KeyId"]))
        return key_metadata

    yield _create_key

    for region, key_id in key_ids:
        try:
            create_boto_client("kms", region).schedule_key_deletion(KeyId=key_id)
        except Exception as e:
            exception_message = str(e)
            # Some tests schedule their keys for deletion themselves.
            if (
                "KMSInvalidStateException" not in exception_message
                or "is pending deletion" not in exception_message
            ):
                LOG.debug("error cleaning up KMS key %s: %s", key_id, e)


@pytest.fixture()
def kms_replicate_key(create_boto_client):
    key_ids = []

    def _replicate_key(region_from=None, **kwargs):
        region_to = kwargs.get("ReplicaRegion")
        key_ids.append((region_to, kwargs.get("KeyId")))
        return create_boto_client("kms", region_from).replicate_key(**kwargs)

    yield _replicate_key

    for region_to, key_id in key_ids:
        try:
            create_boto_client("kms", region_to).schedule_key_deletion(KeyId=key_id)
        except Exception as e:
            LOG.debug("error cleaning up KMS key %s: %s", key_id, e)


# kms_create_key fixture is used here not just to be able to create aliases without a key specified,
# but also to make sure that kms_create_key gets executed before and teared down after kms_create_alias -
# to make sure that we clean up aliases before keys get cleaned up.
@pytest.fixture()
def kms_create_alias(kms_client, kms_create_key):
    aliases = []

    def _create_alias(**kwargs):
        if "AliasName" not in kwargs:
            kwargs["AliasName"] = f"alias/{short_uid()}"
        if "TargetKeyId" not in kwargs:
            kwargs["TargetKeyId"] = kms_create_key()["KeyId"]

        kms_client.create_alias(**kwargs)
        aliases.append(kwargs["AliasName"])
        return kwargs["AliasName"]

    yield _create_alias

    for alias in aliases:
        try:
            kms_client.delete_alias(AliasName=alias)
        except Exception as e:
            LOG.debug("error cleaning up KMS alias %s: %s", alias, e)


@pytest.fixture()
def kms_create_grant(kms_client, kms_create_key):
    grants = []

    def _create_grant(**kwargs):
        # Just a random ARN, since KMS in LocalStack currently doesn't validate GranteePrincipal,
        # but some GranteePrincipal is required to create a grant.
        GRANTEE_PRINCIPAL_ARN = (
            "arn:aws:kms:eu-central-1:123456789876:key/198a5a78-52c3-489f-ac70-b06a4d11027a"
        )

        if "Operations" not in kwargs:
            kwargs["Operations"] = ["Decrypt", "Encrypt"]
        if "GranteePrincipal" not in kwargs:
            kwargs["GranteePrincipal"] = GRANTEE_PRINCIPAL_ARN
        if "KeyId" not in kwargs:
            kwargs["KeyId"] = kms_create_key()["KeyId"]

        grant_id = kms_client.create_grant(**kwargs)["GrantId"]
        grants.append((grant_id, kwargs["KeyId"]))
        return grant_id, kwargs["KeyId"]

    yield _create_grant

    for grant_id, key_id in grants:
        try:
            kms_client.retire_grant(GrantId=grant_id, KeyId=key_id)
        except Exception as e:
            LOG.debug("error cleaning up KMS grant %s: %s", grant_id, e)


@pytest.fixture
def kms_key(kms_create_key):
    return kms_create_key()


@pytest.fixture
def kms_grant_and_key(kms_client, kms_key, sts_client):
    user_arn = sts_client.get_caller_identity()["Arn"]

    return [
        kms_client.create_grant(
            KeyId=kms_key["KeyId"],
            GranteePrincipal=user_arn,
            Operations=["Decrypt", "Encrypt"],
        ),
        kms_key,
    ]


@pytest.fixture
def opensearch_wait_for_cluster(opensearch_client):
    def _wait_for_cluster(domain_name: str):
        def finished_processing():
            status = opensearch_client.describe_domain(DomainName=domain_name)["DomainStatus"]
            return status["Processing"] is False

        assert poll_condition(
            finished_processing, timeout=5 * 60
        ), f"could not start domain: {domain_name}"

    return _wait_for_cluster


@pytest.fixture
def opensearch_create_domain(opensearch_client, opensearch_wait_for_cluster):
    domains = []

    def factory(**kwargs) -> str:
        if "DomainName" not in kwargs:
            kwargs["DomainName"] = f"test-domain-{short_uid()}"

        opensearch_client.create_domain(**kwargs)

        opensearch_wait_for_cluster(domain_name=kwargs["DomainName"])

        domains.append(kwargs["DomainName"])
        return kwargs["DomainName"]

    yield factory

    # cleanup
    for domain in domains:
        try:
            opensearch_client.delete_domain(DomainName=domain)
        except Exception as e:
            LOG.debug("error cleaning up domain %s: %s", domain, e)


@pytest.fixture
def opensearch_domain(opensearch_create_domain) -> str:
    return opensearch_create_domain()


@pytest.fixture
def opensearch_endpoint(opensearch_client, opensearch_domain) -> str:
    status = opensearch_client.describe_domain(DomainName=opensearch_domain)["DomainStatus"]
    assert "Endpoint" in status
    return f"https://{status['Endpoint']}"


@pytest.fixture
def opensearch_document_path(opensearch_client, opensearch_endpoint):
    document = {
        "first_name": "Boba",
        "last_name": "Fett",
        "age": 41,
        "about": "I'm just a simple man, trying to make my way in the universe.",
        "interests": ["mandalorian armor", "tusken culture"],
    }
    document_path = f"{opensearch_endpoint}/bounty/hunters/1"
    response = requests.put(
        document_path,
        data=json.dumps(document),
        headers={"content-type": "application/json", "Accept-encoding": "identity"},
    )
    assert response.status_code == 201, f"could not create document at: {document_path}"
    return document_path


# Cleanup fixtures
@pytest.fixture
def cleanup_stacks(cfn_client):
    def _cleanup_stacks(stacks: List[str]) -> None:
        stacks = ensure_list(stacks)
        for stack in stacks:
            try:
                cfn_client.delete_stack(StackName=stack)
            except Exception:
                LOG.debug(f"Failed to cleanup stack '{stack}'")

    return _cleanup_stacks


@pytest.fixture
def cleanup_changesets(cfn_client):
    def _cleanup_changesets(changesets: List[str]) -> None:
        changesets = ensure_list(changesets)
        for cs in changesets:
            try:
                cfn_client.delete_change_set(ChangeSetName=cs)
            except Exception:
                LOG.debug(f"Failed to cleanup changeset '{cs}'")

    return _cleanup_changesets


# Helpers for Cfn


# TODO: exports(!)
@dataclasses.dataclass(frozen=True)
class DeployResult:
    change_set_id: str
    stack_id: str
    stack_name: str
    change_set_name: str
    outputs: Dict[str, str]

    destroy: Callable[[], None]


@pytest.fixture
def deploy_cfn_template(
    cfn_client,
    lambda_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_change_set_finished,
):
    state = []

    def _deploy(
        *,
        is_update: Optional[bool] = False,
        stack_name: Optional[str] = None,
        change_set_name: Optional[str] = None,
        template: Optional[str] = None,
        template_path: Optional[str | os.PathLike] = None,
        template_mapping: Optional[Dict[str, any]] = None,
        parameters: Optional[Dict[str, str]] = None,
        max_wait: Optional[int] = None,
    ) -> DeployResult:

        if is_update:
            assert stack_name
        stack_name = stack_name or f"stack-{short_uid()}"
        change_set_name = change_set_name or f"change-set-{short_uid()}"

        if template_path is not None:
            template = load_template_file(template_path)
        template_rendered = render_template(template, **(template_mapping or {}))

        response = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_rendered,
            Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            ChangeSetType=("UPDATE" if is_update else "CREATE"),
            Parameters=[
                {
                    "ParameterKey": k,
                    "ParameterValue": v,
                }
                for (k, v) in (parameters or {}).items()
            ],
        )
        change_set_id = response["Id"]
        stack_id = response["StackId"]
        state.append({"stack_id": stack_id, "change_set_id": change_set_id})

        assert wait_until(is_change_set_created_and_available(change_set_id), _max_wait=60)
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        assert wait_until(is_change_set_finished(change_set_id), _max_wait=max_wait or 60)

        outputs = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])

        mapped_outputs = {o["OutputKey"]: o["OutputValue"] for o in outputs}

        def _destroy_stack():
            cfn_client.delete_stack(StackName=stack_id)

            def _await_stack_delete():
                return (
                    cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
                    == "DELETE_COMPLETE"
                )

            assert wait_until(_await_stack_delete, _max_wait=max_wait or 60)
            # TODO: fix in localstack. stack should only be in DELETE_COMPLETE state after all resources have been deleted
            time.sleep(2)

        return DeployResult(
            change_set_id, stack_id, stack_name, change_set_name, mapped_outputs, _destroy_stack
        )

    yield _deploy

    for entry in state:
        entry_stack_id = entry.get("stack_id")
        entry_change_set_id = entry.get("change_set_id")
        try:
            entry_change_set_id and cleanup_changesets([entry_change_set_id])
            entry_stack_id and cleanup_stacks([entry_stack_id])
        except Exception as e:
            LOG.debug(
                f"Failed cleaning up change set {entry_change_set_id=} and stack {entry_stack_id=}: {e}"
            )


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
def is_change_set_failed_and_unavailable(cfn_client):
    def _is_change_set_created_and_available(change_set_id: str):
        def _inner():
            change_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
            return (
                # TODO: CREATE_FAILED should also not lead to further retries
                change_set.get("Status") == "FAILED"
                and change_set.get("ExecutionStatus") == "UNAVAILABLE"
            )

        return _inner

    return _is_change_set_created_and_available


@pytest.fixture
def is_stack_created(cfn_client):
    return _has_stack_status(cfn_client, ["CREATE_COMPLETE", "CREATE_FAILED"])


@pytest.fixture
def is_stack_updated(cfn_client):
    return _has_stack_status(cfn_client, ["UPDATE_COMPLETE", "UPDATE_FAILED"])


@pytest.fixture
def is_stack_deleted(cfn_client):
    return _has_stack_status(cfn_client, ["DELETE_COMPLETE"])


def _has_stack_status(cfn_client, statuses: List[str]):
    def _has_status(stack_id: str):
        def _inner():
            resp = cfn_client.describe_stacks(StackName=stack_id)
            s = resp["Stacks"][0]  # since the lookup  uses the id we can only get a single response
            return s.get("StackStatus") in statuses

        return _inner

    return _has_status


@pytest.fixture
def is_change_set_finished(cfn_client):
    def _is_change_set_finished(change_set_id: str, stack_name: Optional[str] = None):
        def _inner():
            kwargs = {"ChangeSetName": change_set_id}
            if stack_name:
                kwargs["StackName"] = stack_name

            check_set = cfn_client.describe_change_set(**kwargs)

            if check_set.get("ExecutionStatus") == "ROLLBACK_COMPLETE":
                LOG.warning("Change set failed")
                raise ShortCircuitWaitException()

            return check_set.get("ExecutionStatus") == "EXECUTE_COMPLETE"

        return _inner

    return _is_change_set_finished


@pytest.fixture
def wait_until_lambda_ready(lambda_client):
    def _wait_until_ready(function_name: str, qualifier: str = None, client=None):
        client = client or lambda_client

        def _is_not_pending():
            kwargs = {}
            if qualifier:
                kwargs["Qualifier"] = qualifier
            try:
                result = (
                    client.get_function(FunctionName=function_name)["Configuration"]["State"]
                    != "Pending"
                )
                LOG.debug(f"lambda state result: {result=}")
                return result
            except Exception as e:
                LOG.error(e)
                raise

        wait_until(_is_not_pending)

    return _wait_until_ready


role_assume_policy = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
""".strip()

role_policy = """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
""".strip()


@pytest.fixture
def create_lambda_function_aws(
    lambda_client,
):
    lambda_arns = []

    def _create_lambda_function(**kwargs):
        def _create_function():
            resp = lambda_client.create_function(**kwargs)
            lambda_arns.append(resp["FunctionArn"])

            def _is_not_pending():
                try:
                    result = (
                        lambda_client.get_function(FunctionName=resp["FunctionName"])[
                            "Configuration"
                        ]["State"]
                        != "Pending"
                    )
                    return result
                except Exception as e:
                    LOG.error(e)
                    raise

            wait_until(_is_not_pending)
            return resp

        # @AWS, takes about 10s until the role/policy is "active", until then it will fail
        # localstack should normally not require the retries and will just continue here
        return retry(_create_function, retries=3, sleep=4)

    yield _create_lambda_function

    for arn in lambda_arns:
        try:
            lambda_client.delete_function(FunctionName=arn)
        except Exception:
            LOG.debug(f"Unable to delete function {arn=} in cleanup")


@pytest.fixture
def create_lambda_function(
    lambda_client, logs_client, iam_client, wait_until_lambda_ready, lambda_su_role
):
    lambda_arns_and_clients = []
    log_groups = []

    def _create_lambda_function(*args, **kwargs):
        client = kwargs.get("client") or lambda_client
        kwargs["client"] = client
        func_name = kwargs.get("func_name")
        assert func_name
        del kwargs["func_name"]

        if not kwargs.get("role"):
            kwargs["role"] = lambda_su_role

        def _create_function():
            resp = testutil.create_lambda_function(func_name, **kwargs)
            lambda_arns_and_clients.append((resp["CreateFunctionResponse"]["FunctionArn"], client))
            wait_until_lambda_ready(function_name=func_name, client=client)
            log_group_name = f"/aws/lambda/{func_name}"
            log_groups.append(log_group_name)
            return resp

        # @AWS, takes about 10s until the role/policy is "active", until then it will fail
        # localstack should normally not require the retries and will just continue here
        return retry(_create_function, retries=3, sleep=4)

    yield _create_lambda_function

    for arn, client in lambda_arns_and_clients:
        try:
            client.delete_function(FunctionName=arn)
        except Exception:
            LOG.debug(f"Unable to delete function {arn=} in cleanup")

    for log_group_name in log_groups:
        try:
            logs_client.delete_log_group(logGroupName=log_group_name)
        except Exception:
            LOG.debug(f"Unable to delete log group {log_group_name} in cleanup")


@pytest.fixture
def check_lambda_logs(logs_client):
    def _check_logs(func_name: str, expected_lines: List[str] = None) -> List[str]:
        if not expected_lines:
            expected_lines = []
        log_events = get_lambda_logs(func_name, logs_client=logs_client)
        log_messages = [e["message"] for e in log_events]
        for line in expected_lines:
            if ".*" in line:
                found = [re.match(line, m, flags=re.DOTALL) for m in log_messages]
                if any(found):
                    continue
            assert line in log_messages
        return log_messages

    return _check_logs


@pytest.fixture
def create_policy(iam_client):
    policy_arns = []

    def _create_policy(*args, **kwargs):
        if "PolicyName" not in kwargs:
            kwargs["PolicyName"] = f"policy-{short_uid()}"
        response = iam_client.create_policy(*args, **kwargs)
        policy_arn = response["Policy"]["Arn"]
        policy_arns.append(policy_arn)
        return response

    yield _create_policy

    for policy_arn in policy_arns:
        try:
            iam_client.delete_policy(PolicyArn=policy_arn)
        except Exception:
            LOG.debug("Could not delete policy '%s' during test cleanup", policy_arn)


@pytest.fixture
def create_user(iam_client):
    usernames = []

    def _create_user(**kwargs):
        if "UserName" not in kwargs:
            kwargs["UserName"] = f"user-{short_uid()}"
        response = iam_client.create_user(**kwargs)
        usernames.append(response["User"]["UserName"])
        return response

    yield _create_user

    for username in usernames:
        inline_policies = iam_client.list_user_policies(UserName=username)["PolicyNames"]
        for inline_policy in inline_policies:
            try:
                iam_client.delete_user_policy(UserName=username, PolicyName=inline_policy)
            except Exception:
                LOG.debug(
                    "Could not delete user policy '%s' from '%s' during cleanup",
                    inline_policy,
                    username,
                )
        attached_policies = iam_client.list_attached_user_policies(UserName=username)[
            "AttachedPolicies"
        ]
        for attached_policy in attached_policies:
            try:
                iam_client.detach_user_policy(
                    UserName=username, PolicyArn=attached_policy["PolicyArn"]
                )
            except Exception:
                LOG.debug(
                    "Error detaching policy '%s' from user '%s'",
                    attached_policy["PolicyArn"],
                    username,
                )
        try:
            iam_client.delete_user(UserName=username)
        except Exception:
            LOG.debug("Error deleting user '%s' during test cleanup", username)


@pytest.fixture
def wait_and_assume_role(sts_client):
    def _wait_and_assume_role(role_arn: str, session_name: str = None):
        if not session_name:
            session_name = f"session-{short_uid()}"

        def assume_role():
            return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)[
                "Credentials"
            ]

        # need to retry a couple of times before we are allowed to assume this role in AWS
        keys = retry(assume_role, sleep=5, retries=4)
        return keys

    return _wait_and_assume_role


@pytest.fixture
def create_role(iam_client):
    role_names = []

    def _create_role(**kwargs):
        if not kwargs.get("RoleName"):
            kwargs["RoleName"] = f"role-{short_uid()}"
        result = iam_client.create_role(**kwargs)
        role_names.append(result["Role"]["RoleName"])
        return result

    yield _create_role

    for role_name in role_names:
        # detach policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        for attached_policy in attached_policies:
            try:
                iam_client.detach_role_policy(
                    RoleName=role_name, PolicyArn=attached_policy["PolicyArn"]
                )
            except Exception:
                LOG.debug(
                    "Could not detach role policy '%s' from '%s' during cleanup",
                    attached_policy["PolicyArn"],
                    role_name,
                )
        role_policies = iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]
        for role_policy in role_policies:
            try:
                iam_client.delete_role_policy(RoleName=role_name, PolicyName=role_policy)
            except Exception:
                LOG.debug(
                    "Could not delete role policy '%s' from '%s' during cleanup",
                    role_policy,
                    role_name,
                )
        try:
            iam_client.delete_role(RoleName=role_name)
        except Exception:
            LOG.debug("Could not delete role '%s' during cleanup", role_name)


@pytest.fixture
def create_parameter(ssm_client):
    params = []

    def _create_parameter(**kwargs):
        params.append(kwargs["Name"])
        return ssm_client.put_parameter(**kwargs)

    yield _create_parameter

    for param in params:
        ssm_client.delete_parameter(Name=param)


@pytest.fixture
def create_secret(secretsmanager_client):
    items = []

    def _create_parameter(**kwargs):
        create_response = secretsmanager_client.create_secret(**kwargs)
        items.append(create_response["ARN"])
        return create_response

    yield _create_parameter

    for item in items:
        secretsmanager_client.delete_secret(SecretId=item, ForceDeleteWithoutRecovery=True)


# TODO Figure out how to make cert creation tests pass against AWS.
#
# We would like to have localstack tests to pass not just against localstack, but also against AWS to make sure
# our emulation is correct. Unfortunately, with certificate creation there are some issues.
#
# In AWS newly created ACM certificates have to be validated either by email or by DNS. The latter is
# by adding some CNAME records as requested by ASW in response to a certificate request.
# For testing purposes the DNS one seems to be easier, at least as long as DNS is handled by Region53 AWS DNS service.
#
# The other possible option is to use IAM certificates instead of ACM ones. Those just have to be uploaded from files
# created by openssl etc. Not sure if there are other issues after that.
#
# The third option might be having in AWS some certificates created in advance - so they do not require validation
# and can be easily used in tests. The issie with such an approach is that for AppSync, for example, in order to
# register a domain name (https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateDomainName.html),
# the domain name in the API request has to match the domain name used in certificate creation. Which means that with
# pre-created certificates we would have to use specific domain names instead of random ones.
@pytest.fixture
def acm_request_certificate():
    certificate_arns = []

    def factory(**kwargs) -> str:
        if "DomainName" not in kwargs:
            kwargs["DomainName"] = f"test-domain-{short_uid()}.localhost.localstack.cloud"

        region_name = kwargs.pop("region_name", None)
        acm_client = _client("acm", region_name)

        response = acm_client.request_certificate(**kwargs)
        created_certificate_arn = response["CertificateArn"]
        certificate_arns.append((created_certificate_arn, region_name))
        return created_certificate_arn

    yield factory

    # cleanup
    for certificate_arn, region_name in certificate_arns:
        try:
            acm_client = _client("acm", region_name)
            acm_client.delete_certificate(CertificateArn=certificate_arn)
        except Exception as e:
            LOG.debug("error cleaning up certificate %s: %s", certificate_arn, e)


@pytest.fixture
def tmp_http_server():
    test_port, invocations, proxy = start_http_server()
    yield test_port, invocations, proxy
    proxy.stop()


role_policy_su = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
}


@pytest.fixture(scope="session")
def lambda_su_role():
    iam_client: IAMClient = _client("iam")

    role_name = f"lambda-autogenerated-{short_uid()}"
    role = iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=role_assume_policy)[
        "Role"
    ]
    policy_name = f"lambda-autogenerated-{short_uid()}"
    policy_arn = iam_client.create_policy(
        PolicyName=policy_name, PolicyDocument=json.dumps(role_policy_su)
    )["Policy"]["Arn"]
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    if os.environ.get("TEST_TARGET", "") == "AWS_CLOUD":  # dirty but necessary
        time.sleep(10)

    yield role["Arn"]

    run_safe(iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    run_safe(iam_client.delete_role(RoleName=role_name))
    run_safe(iam_client.delete_policy(PolicyArn=policy_arn))


@pytest.fixture
def create_iam_role_with_policy(iam_client):
    roles = {}

    def _create_role_and_policy(**kwargs):
        role = kwargs["RoleName"]
        policy = kwargs["PolicyName"]
        role_policy = json.dumps(kwargs["RoleDefinition"])

        result = iam_client.create_role(RoleName=role, AssumeRolePolicyDocument=role_policy)
        role_arn = result["Role"]["Arn"]
        policy_document = json.dumps(kwargs["PolicyDefinition"])
        iam_client.put_role_policy(RoleName=role, PolicyName=policy, PolicyDocument=policy_document)
        roles[role] = policy
        return role_arn

    yield _create_role_and_policy

    for role_name, policy_name in roles.items():
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam_client.delete_role(RoleName=role_name)


@pytest.fixture
def firehose_create_delivery_stream(firehose_client, wait_for_delivery_stream_ready):
    delivery_streams = {}

    def _create_delivery_stream(**kwargs):
        if "DeliveryStreamName" not in kwargs:
            kwargs["DeliveryStreamName"] = f"test-delivery-stream-{short_uid()}"

        delivery_stream = firehose_client.create_delivery_stream(**kwargs)
        delivery_streams.update({kwargs["DeliveryStreamName"]: delivery_stream})
        wait_for_delivery_stream_ready(kwargs["DeliveryStreamName"])
        return delivery_stream

    yield _create_delivery_stream

    for delivery_stream_name in delivery_streams.keys():
        firehose_client.delete_delivery_stream(DeliveryStreamName=delivery_stream_name)


@pytest.fixture
def events_create_rule(events_client):
    rules = []

    def _create_rule(**kwargs):
        rule_name = kwargs["Name"]
        bus_name = kwargs.get("EventBusName", "")
        pattern = kwargs.get("EventPattern", {})
        schedule = kwargs.get("ScheduleExpression", "")
        rule_arn = events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(pattern),
            ScheduleExpression=schedule,
        )["RuleArn"]
        rules.append({"name": rule_name, "bus": bus_name})
        return rule_arn

    yield _create_rule

    for rule in rules:
        targets = events_client.list_targets_by_rule(Rule=rule["name"], EventBusName=rule["bus"])[
            "Targets"
        ]

        targetIds = [target["Id"] for target in targets]
        if len(targetIds) > 0:
            events_client.remove_targets(Rule=rule["name"], EventBusName=rule["bus"], Ids=targetIds)

        events_client.delete_rule(Name=rule["name"], EventBusName=rule["bus"])


@pytest.fixture
def ses_configuration_set(ses_client):
    configuration_set_names = []

    def factory(name: str) -> None:
        ses_client.create_configuration_set(
            ConfigurationSet={
                "Name": name,
            },
        )
        configuration_set_names.append(name)

    yield factory

    for configuration_set_name in configuration_set_names:
        ses_client.delete_configuration_set(ConfigurationSetName=configuration_set_name)


@pytest.fixture
def ses_configuration_set_sns_event_destination(ses_client):
    event_destinations = []

    def factory(config_set_name: str, event_destination_name: str, topic_arn: str) -> None:
        ses_client.create_configuration_set_event_destination(
            ConfigurationSetName=config_set_name,
            EventDestination={
                "Name": event_destination_name,
                "Enabled": True,
                "MatchingEventTypes": ["send", "bounce", "delivery", "open", "click"],
                "SNSDestination": {
                    "TopicARN": topic_arn,
                },
            },
        )
        event_destinations.append((config_set_name, event_destination_name))

    yield factory

    for (created_config_set_name, created_event_destination_name) in event_destinations:
        ses_client.delete_configuration_set_event_destination(
            ConfigurationSetName=created_config_set_name,
            EventDestinationName=created_event_destination_name,
        )


@pytest.fixture
def ses_email_template(ses_client):
    template_names = []

    def factory(name: str, contents: str, subject: str = f"Email template {short_uid()}"):
        ses_client.create_template(
            Template={
                "TemplateName": name,
                "SubjectPart": subject,
                "TextPart": contents,
            }
        )
        template_names.append(name)

    yield factory

    for template_name in template_names:
        ses_client.delete_template(TemplateName=template_name)


@pytest.fixture
def ses_verify_identity(ses_client):
    identities = []

    def factory(email_address: str) -> None:
        ses_client.verify_email_identity(EmailAddress=email_address)

    yield factory

    for identity in identities:
        ses_client.delete_identity(Identity=identity)


@pytest.fixture
def cleanups(ec2_client):
    cleanup_fns = []

    yield cleanup_fns

    for cleanup_callback in cleanup_fns[::-1]:
        try:
            cleanup_callback()
        except Exception as e:
            LOG.warning("Failed to execute cleanup", exc_info=e)


@pytest.fixture(scope="session")
def account_id():
    sts_client = _client("sts")
    return sts_client.get_caller_identity()["Account"]


@pytest.hookimpl
def pytest_configure(config: Config):
    # TODO: migrate towards "whitebox" or similar structure
    config.addinivalue_line(
        "markers",
        "only_localstack: mark the test as incompatible with AWS / can't be run with AWS_CLOUD target",
    )


@pytest.hookimpl
def pytest_collection_modifyitems(config: Config, items: list[Item]):
    only_localstack = pytest.mark.skipif(
        os.environ.get("TEST_TARGET") == "AWS_CLOUD",
        reason="test only applicable if run against localstack",
    )
    for item in items:
        if "only_localstack" in item.keywords:
            item.add_marker(only_localstack)


@pytest.fixture
def sample_stores() -> AccountRegionBundle:
    class SampleStore(BaseStore):
        CROSS_REGION_ATTR = CrossRegionAttribute(default=list)
        region_specific_attr = LocalAttribute(default=list)

    return AccountRegionBundle("zzz", SampleStore, validate=False)


@pytest.fixture()
def sample_backend_dict() -> BackendDict:
    class SampleBackend(BaseBackend):
        def __init__(self, region_name, account_id):
            super().__init__(region_name, account_id)
            self.attributes = {}

    return BackendDict(SampleBackend, "sns")
