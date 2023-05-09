import contextlib
import dataclasses
import json
import logging
import os
import re
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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
from werkzeug import Request, Response

from localstack import config, constants
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.testing.aws.cloudformation_utils import load_template_file, render_template
from localstack.testing.aws.util import get_lambda_logs, is_aws_cloud
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.client import SigningHttpClient
from localstack.utils.aws.resources import create_dynamodb_table
from localstack.utils.collections import ensure_list
from localstack.utils.functions import run_safe
from localstack.utils.http import safe_requests as requests
from localstack.utils.json import json_safe
from localstack.utils.net import wait_for_port_open
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import ShortCircuitWaitException, poll_condition, retry, wait_until
from localstack.utils.testutil import start_http_server

LOG = logging.getLogger(__name__)

# URL of public HTTP echo server, used primarily for AWS parity/snapshot testing
PUBLIC_HTTP_ECHO_SERVER_URL = "http://httpbin.org"


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


# TODO: remove usage of this fixture
@pytest.fixture(scope="class")
def create_boto_client(aws_client_factory):
    def _factory_client(
        service, region_name=None, aws_access_key_id=None, *, additional_config=None
    ):
        return aws_client_factory.get_client(
            service_name=service, region_name=region_name, config=additional_config
        )

    return _factory_client


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
def dynamodb_resource():
    return _resource("dynamodb")


@pytest.fixture(scope="class")
def s3_vhost_client(aws_client_factory):
    return aws_client_factory(config=botocore.config.Config(s3={"addressing_style": "virtual"})).s3


# TODO: remove
@pytest.fixture(scope="class")
def s3_presigned_client(aws_client_factory):
    return aws_client_factory(
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID, aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY
    ).s3


@pytest.fixture(scope="class")
def s3_resource():
    return _resource("s3")


@pytest.fixture
def dynamodb_wait_for_table_active(aws_client):
    def wait_for_table_active(table_name: str, client=None):
        def wait():
            return (client or aws_client.dynamodb).describe_table(TableName=table_name)["Table"][
                "TableStatus"
            ] == "ACTIVE"

        poll_condition(wait, timeout=30)

    return wait_for_table_active


@pytest.fixture
def dynamodb_create_table_with_parameters(dynamodb_wait_for_table_active, aws_client):
    tables = []

    def factory(**kwargs):
        if "TableName" not in kwargs:
            kwargs["TableName"] = f"test-table-{short_uid()}"

        tables.append(kwargs["TableName"])
        response = aws_client.dynamodb.create_table(**kwargs)
        dynamodb_wait_for_table_active(kwargs["TableName"])
        return response

    yield factory

    # cleanup
    for table in tables:
        try:
            # table has to be in ACTIVE state before deletion
            dynamodb_wait_for_table_active(table)
            aws_client.dynamodb.delete_table(TableName=table)
        except Exception as e:
            LOG.debug("error cleaning up table %s: %s", table, e)


@pytest.fixture
def dynamodb_create_table(dynamodb_wait_for_table_active, aws_client):
    # beware, this swallows exception in create_dynamodb_table utility function
    tables = []

    def factory(**kwargs):
        kwargs["client"] = aws_client.dynamodb
        if "table_name" not in kwargs:
            kwargs["table_name"] = f"test-table-{short_uid()}"
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
            aws_client.dynamodb.delete_table(TableName=table)
        except Exception as e:
            LOG.debug("error cleaning up table %s: %s", table, e)


@pytest.fixture
def s3_create_bucket(s3_resource, aws_client):
    buckets = []

    def factory(**kwargs) -> str:
        if "Bucket" not in kwargs:
            kwargs["Bucket"] = "test-bucket-%s" % short_uid()

        if (
            "CreateBucketConfiguration" not in kwargs
            and aws_client.s3.meta.region_name != "us-east-1"
        ):
            kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": aws_client.s3.meta.region_name
            }

        aws_client.s3.create_bucket(**kwargs)
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
def s3_bucket(s3_create_bucket, aws_client) -> str:
    region = aws_client.s3.meta.region_name
    kwargs = {}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    return s3_create_bucket(**kwargs)


@pytest.fixture
def sqs_create_queue(aws_client):
    queue_urls = []

    def factory(**kwargs):
        if "QueueName" not in kwargs:
            kwargs["QueueName"] = "test-queue-%s" % short_uid()

        response = aws_client.sqs.create_queue(**kwargs)
        url = response["QueueUrl"]
        queue_urls.append(url)

        return url

    yield factory

    # cleanup
    for queue_url in queue_urls:
        try:
            aws_client.sqs.delete_queue(QueueUrl=queue_url)
        except Exception as e:
            LOG.debug("error cleaning up queue %s: %s", queue_url, e)


@pytest.fixture
def sqs_receive_messages_delete(aws_client):
    def factory(
        queue_url: str,
        expected_messages: Optional[int] = None,
        wait_time: Optional[int] = 5,
    ):
        response = aws_client.sqs.receive_message(
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
            aws_client.sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
            )

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
def sqs_queue_arn(aws_client):
    def _get_arn(queue_url: str) -> str:
        return aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]

    return _get_arn


@pytest.fixture
def sqs_queue_exists(aws_client):
    def _queue_exists(queue_url: str) -> bool:
        """
        Checks whether a queue with the given queue URL exists.
        :param queue_url: the queue URL
        :return: true if the queue exists, false otherwise
        """
        try:
            result = aws_client.sqs.get_queue_url(QueueName=queue_url.split("/")[-1])
            return result.get("QueueUrl") == queue_url
        except ClientError as e:
            if "NonExistentQueue" in e.response["Error"]["Code"]:
                return False
            raise

    yield _queue_exists


@pytest.fixture
def sns_create_topic(aws_client):
    topic_arns = []

    def _create_topic(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = "test-topic-%s" % short_uid()
        response = aws_client.sns.create_topic(**kwargs)
        topic_arns.append(response["TopicArn"])
        return response

    yield _create_topic

    for topic_arn in topic_arns:
        try:
            aws_client.sns.delete_topic(TopicArn=topic_arn)
        except Exception as e:
            LOG.debug("error cleaning up topic %s: %s", topic_arn, e)


@pytest.fixture
def sns_wait_for_topic_delete(aws_client):
    def wait_for_topic_delete(topic_arn: str) -> None:
        def wait():
            try:
                aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
                return False
            except Exception as e:
                if "NotFound" in e.response["Error"]["Code"]:
                    return True

                raise

        poll_condition(wait, timeout=30)

    return wait_for_topic_delete


@pytest.fixture
def sns_subscription(aws_client):
    sub_arns = []

    def _create_sub(**kwargs):
        if kwargs.get("ReturnSubscriptionArn") is None:
            kwargs["ReturnSubscriptionArn"] = True

        # requires 'TopicArn', 'Protocol', and 'Endpoint'
        response = aws_client.sns.subscribe(**kwargs)
        sub_arn = response["SubscriptionArn"]
        sub_arns.append(sub_arn)
        return response

    yield _create_sub

    for sub_arn in sub_arns:
        try:
            aws_client.sns.unsubscribe(SubscriptionArn=sub_arn)
        except Exception as e:
            LOG.debug(f"error cleaning up subscription {sub_arn}: {e}")


@pytest.fixture
def sns_topic(sns_create_topic, aws_client):
    topic_arn = sns_create_topic()["TopicArn"]
    return aws_client.sns.get_topic_attributes(TopicArn=topic_arn)


@pytest.fixture
def sns_allow_topic_sqs_queue(aws_client):
    def _allow_sns_topic(sqs_queue_url, sqs_queue_arn, sns_topic_arn) -> None:
        # allow topic to write to sqs queue
        aws_client.sqs.set_queue_attributes(
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
def sns_create_sqs_subscription(sns_allow_topic_sqs_queue, sqs_queue_arn, aws_client):
    subscriptions = []

    def _factory(topic_arn: str, queue_url: str, **kwargs) -> Dict[str, str]:
        queue_arn = sqs_queue_arn(queue_url=queue_url)

        # connect sns topic to sqs
        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, **kwargs
        )
        subscription_arn = subscription["SubscriptionArn"]

        # allow topic to write to sqs queue
        sns_allow_topic_sqs_queue(
            sqs_queue_url=queue_url, sqs_queue_arn=queue_arn, sns_topic_arn=topic_arn
        )

        subscriptions.append(subscription_arn)
        return aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)[
            "Attributes"
        ]

    yield _factory

    for arn in subscriptions:
        try:
            aws_client.sns.unsubscribe(SubscriptionArn=arn)
        except Exception as e:
            LOG.error("error cleaning up subscription %s: %s", arn, e)


@pytest.fixture
def sns_create_http_endpoint(sns_create_topic, sns_subscription, aws_client):
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
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="DeliveryPolicy",
            AttributeValue=json.dumps(delivery_policy),
        )

        if raw_message_delivery:
            aws_client.sns.set_subscription_attributes(
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
def route53_hosted_zone(aws_client):
    hosted_zones = []

    def factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"www.{short_uid()}.com."
        if "CallerReference" not in kwargs:
            kwargs["CallerReference"] = f"caller-ref-{short_uid()}"
        response = aws_client.route53.create_hosted_zone(
            Name=kwargs["Name"], CallerReference=kwargs["CallerReference"]
        )
        hosted_zones.append(response["HostedZone"]["Id"])
        return response

    yield factory

    for zone in hosted_zones:
        try:
            aws_client.route53.delete_hosted_zone(Id=zone)
        except Exception as e:
            LOG.debug(f"error cleaning up route53 HostedZone {zone}: {e}")


@pytest.fixture
def transcribe_create_job(s3_bucket, aws_client):
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
            aws_client.s3.upload_fileobj(f, s3_bucket, s3_key)

        response = aws_client.transcribe.start_transcription_job(**params)

        job_name = response["TranscriptionJob"]["TranscriptionJobName"]
        job_names.append(job_name)

        return job_name

    yield _create_job

    for job_name in job_names:
        with contextlib.suppress(ClientError):
            aws_client.transcribe.delete_transcription_job(TranscriptionJobName=job_name)


@pytest.fixture
def kinesis_create_stream(aws_client):
    stream_names = []

    def _create_stream(**kwargs):
        if "StreamName" not in kwargs:
            kwargs["StreamName"] = f"test-stream-{short_uid()}"
        aws_client.kinesis.create_stream(**kwargs)
        stream_names.append(kwargs["StreamName"])
        return kwargs["StreamName"]

    yield _create_stream

    for stream_name in stream_names:
        try:
            aws_client.kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
        except Exception as e:
            LOG.debug("error cleaning up kinesis stream %s: %s", stream_name, e)


@pytest.fixture
def wait_for_stream_ready(aws_client):
    def _wait_for_stream_ready(stream_name: str):
        def is_stream_ready():
            describe_stream_response = aws_client.kinesis.describe_stream(StreamName=stream_name)
            return describe_stream_response["StreamDescription"]["StreamStatus"] in [
                "ACTIVE",
                "UPDATING",
            ]

        poll_condition(is_stream_ready)

    return _wait_for_stream_ready


@pytest.fixture
def wait_for_delivery_stream_ready(aws_client):
    def _wait_for_stream_ready(delivery_stream_name: str):
        def is_stream_ready():
            describe_stream_response = aws_client.firehose.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
            return (
                describe_stream_response["DeliveryStreamDescription"]["DeliveryStreamStatus"]
                == "ACTIVE"
            )

        poll_condition(is_stream_ready)

    return _wait_for_stream_ready


@pytest.fixture
def wait_for_dynamodb_stream_ready(aws_client):
    def _wait_for_stream_ready(stream_arn: str):
        def is_stream_ready():
            describe_stream_response = aws_client.dynamodbstreams.describe_stream(
                StreamArn=stream_arn
            )
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
            # shortest amount of time you can schedule the deletion
            create_boto_client("kms", region).schedule_key_deletion(
                KeyId=key_id, PendingWindowInDays=7
            )
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
            # shortest amount of time you can schedule the deletion
            create_boto_client("kms", region_to).schedule_key_deletion(
                KeyId=key_id, PendingWindowInDays=7
            )
        except Exception as e:
            LOG.debug("error cleaning up KMS key %s: %s", key_id, e)


# kms_create_key fixture is used here not just to be able to create aliases without a key specified,
# but also to make sure that kms_create_key gets executed before and teared down after kms_create_alias -
# to make sure that we clean up aliases before keys get cleaned up.
@pytest.fixture()
def kms_create_alias(kms_create_key, aws_client):
    aliases = []

    def _create_alias(**kwargs):
        if "AliasName" not in kwargs:
            kwargs["AliasName"] = f"alias/{short_uid()}"
        if "TargetKeyId" not in kwargs:
            kwargs["TargetKeyId"] = kms_create_key()["KeyId"]

        aws_client.kms.create_alias(**kwargs)
        aliases.append(kwargs["AliasName"])
        return kwargs["AliasName"]

    yield _create_alias

    for alias in aliases:
        try:
            aws_client.kms.delete_alias(AliasName=alias)
        except Exception as e:
            LOG.debug("error cleaning up KMS alias %s: %s", alias, e)


@pytest.fixture()
def kms_create_grant(kms_create_key, aws_client):
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

        grant_id = aws_client.kms.create_grant(**kwargs)["GrantId"]
        grants.append((grant_id, kwargs["KeyId"]))
        return grant_id, kwargs["KeyId"]

    yield _create_grant

    for grant_id, key_id in grants:
        try:
            aws_client.kms.retire_grant(GrantId=grant_id, KeyId=key_id)
        except Exception as e:
            LOG.debug("error cleaning up KMS grant %s: %s", grant_id, e)


@pytest.fixture
def kms_key(kms_create_key):
    return kms_create_key()


@pytest.fixture
def kms_grant_and_key(kms_key, aws_client):
    user_arn = aws_client.sts.get_caller_identity()["Arn"]

    return [
        aws_client.kms.create_grant(
            KeyId=kms_key["KeyId"],
            GranteePrincipal=user_arn,
            Operations=["Decrypt", "Encrypt"],
        ),
        kms_key,
    ]


@pytest.fixture
def opensearch_wait_for_cluster(aws_client):
    def _wait_for_cluster(domain_name: str):
        def finished_processing():
            status = aws_client.opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
            return status["Processing"] is False

        assert poll_condition(
            finished_processing, timeout=5 * 60
        ), f"could not start domain: {domain_name}"

    return _wait_for_cluster


@pytest.fixture
def opensearch_create_domain(opensearch_wait_for_cluster, aws_client):
    domains = []

    def factory(**kwargs) -> str:
        if "DomainName" not in kwargs:
            kwargs["DomainName"] = f"test-domain-{short_uid()}"

        aws_client.opensearch.create_domain(**kwargs)

        opensearch_wait_for_cluster(domain_name=kwargs["DomainName"])

        domains.append(kwargs["DomainName"])
        return kwargs["DomainName"]

    yield factory

    # cleanup
    for domain in domains:
        try:
            aws_client.opensearch.delete_domain(DomainName=domain)
        except Exception as e:
            LOG.debug("error cleaning up domain %s: %s", domain, e)


@pytest.fixture
def opensearch_domain(opensearch_create_domain) -> str:
    return opensearch_create_domain()


@pytest.fixture
def opensearch_endpoint(opensearch_domain, aws_client) -> str:
    status = aws_client.opensearch.describe_domain(DomainName=opensearch_domain)["DomainStatus"]
    assert "Endpoint" in status
    return f"https://{status['Endpoint']}"


@pytest.fixture
def opensearch_document_path(opensearch_endpoint, aws_client):
    document = {
        "first_name": "Boba",
        "last_name": "Fett",
        "age": 41,
        "about": "I'm just a simple man, trying to make my way in the universe.",
        "interests": ["mandalorian armor", "tusken culture"],
    }
    document_path = f"{opensearch_endpoint}/bountyhunters/_doc/1"
    response = requests.put(
        document_path,
        data=json.dumps(document),
        headers={"content-type": "application/json", "Accept-encoding": "identity"},
    )
    assert response.status_code == 201, f"could not create document at: {document_path}"
    return document_path


# Cleanup fixtures
@pytest.fixture
def cleanup_stacks(aws_client):
    def _cleanup_stacks(stacks: List[str]) -> None:
        stacks = ensure_list(stacks)
        for stack in stacks:
            try:
                aws_client.cloudformation.delete_stack(StackName=stack)
            except Exception:
                LOG.debug(f"Failed to cleanup stack '{stack}'")

    return _cleanup_stacks


@pytest.fixture
def cleanup_changesets(aws_client):
    def _cleanup_changesets(changesets: List[str]) -> None:
        changesets = ensure_list(changesets)
        for cs in changesets:
            try:
                aws_client.cloudformation.delete_change_set(ChangeSetName=cs)
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
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_change_set_finished,
    aws_client,
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

        response = aws_client.cloudformation.create_change_set(
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
        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        assert wait_until(is_change_set_finished(change_set_id), _max_wait=max_wait or 60)

        outputs = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0].get(
            "Outputs", []
        )

        mapped_outputs = {o["OutputKey"]: o.get("OutputValue") for o in outputs}

        def _destroy_stack():
            aws_client.cloudformation.delete_stack(StackName=stack_id)

            def _await_stack_delete():
                return (
                    aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0][
                        "StackStatus"
                    ]
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
def is_change_set_created_and_available(aws_client):
    def _is_change_set_created_and_available(change_set_id: str):
        def _inner():
            change_set = aws_client.cloudformation.describe_change_set(ChangeSetName=change_set_id)
            return (
                # TODO: CREATE_FAILED should also not lead to further retries
                change_set.get("Status") == "CREATE_COMPLETE"
                and change_set.get("ExecutionStatus") == "AVAILABLE"
            )

        return _inner

    return _is_change_set_created_and_available


@pytest.fixture
def is_change_set_failed_and_unavailable(aws_client):
    def _is_change_set_created_and_available(change_set_id: str):
        def _inner():
            change_set = aws_client.cloudformation.describe_change_set(ChangeSetName=change_set_id)
            return (
                # TODO: CREATE_FAILED should also not lead to further retries
                change_set.get("Status") == "FAILED"
                and change_set.get("ExecutionStatus") == "UNAVAILABLE"
            )

        return _inner

    return _is_change_set_created_and_available


@pytest.fixture
def is_stack_created(aws_client):
    return _has_stack_status(aws_client.cloudformation, ["CREATE_COMPLETE", "CREATE_FAILED"])


@pytest.fixture
def is_stack_updated(aws_client):
    return _has_stack_status(aws_client.cloudformation, ["UPDATE_COMPLETE", "UPDATE_FAILED"])


@pytest.fixture
def is_stack_deleted(aws_client):
    return _has_stack_status(aws_client.cloudformation, ["DELETE_COMPLETE"])


def _has_stack_status(cfn_client, statuses: List[str]):
    def _has_status(stack_id: str):
        def _inner():
            resp = cfn_client.describe_stacks(StackName=stack_id)
            s = resp["Stacks"][0]  # since the lookup  uses the id we can only get a single response
            return s.get("StackStatus") in statuses

        return _inner

    return _has_status


@pytest.fixture
def is_change_set_finished(aws_client):
    def _is_change_set_finished(change_set_id: str, stack_name: Optional[str] = None):
        def _inner():
            kwargs = {"ChangeSetName": change_set_id}
            if stack_name:
                kwargs["StackName"] = stack_name

            check_set = aws_client.cloudformation.describe_change_set(**kwargs)

            if check_set.get("ExecutionStatus") == "EXECUTE_FAILED":
                LOG.warning("Change set failed")
                raise ShortCircuitWaitException()

            return check_set.get("ExecutionStatus") == "EXECUTE_COMPLETE"

        return _inner

    return _is_change_set_finished


@pytest.fixture
def wait_until_lambda_ready(aws_client):
    def _wait_until_ready(function_name: str, qualifier: str = None, client=None):
        client = client or aws_client.awslambda

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
def create_lambda_function_aws(aws_client):
    lambda_arns = []

    def _create_lambda_function(**kwargs):
        def _create_function():
            resp = aws_client.awslambda.create_function(**kwargs)
            lambda_arns.append(resp["FunctionArn"])

            def _is_not_pending():
                try:
                    result = (
                        aws_client.awslambda.get_function(FunctionName=resp["FunctionName"])[
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
            aws_client.awslambda.delete_function(FunctionName=arn)
        except Exception:
            LOG.debug(f"Unable to delete function {arn=} in cleanup")


@pytest.fixture
def create_lambda_function(aws_client, wait_until_lambda_ready, lambda_su_role):
    lambda_arns_and_clients = []
    log_groups = []
    lambda_client = aws_client.awslambda
    logs_client = aws_client.logs

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
def check_lambda_logs(aws_client):
    def _check_logs(func_name: str, expected_lines: List[str] = None) -> List[str]:
        if not expected_lines:
            expected_lines = []
        log_events = get_lambda_logs(func_name, logs_client=aws_client.logs)
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
def create_policy(aws_client):
    policy_arns = []

    def _create_policy(*args, **kwargs):
        if "PolicyName" not in kwargs:
            kwargs["PolicyName"] = f"policy-{short_uid()}"
        response = aws_client.iam.create_policy(*args, **kwargs)
        policy_arn = response["Policy"]["Arn"]
        policy_arns.append(policy_arn)
        return response

    yield _create_policy

    for policy_arn in policy_arns:
        try:
            aws_client.iam.delete_policy(PolicyArn=policy_arn)
        except Exception:
            LOG.debug("Could not delete policy '%s' during test cleanup", policy_arn)


@pytest.fixture
def create_user(aws_client):
    usernames = []

    def _create_user(**kwargs):
        if "UserName" not in kwargs:
            kwargs["UserName"] = f"user-{short_uid()}"
        response = aws_client.iam.create_user(**kwargs)
        usernames.append(response["User"]["UserName"])
        return response

    yield _create_user

    for username in usernames:
        inline_policies = aws_client.iam.list_user_policies(UserName=username)["PolicyNames"]
        for inline_policy in inline_policies:
            try:
                aws_client.iam.delete_user_policy(UserName=username, PolicyName=inline_policy)
            except Exception:
                LOG.debug(
                    "Could not delete user policy '%s' from '%s' during cleanup",
                    inline_policy,
                    username,
                )
        attached_policies = aws_client.iam.list_attached_user_policies(UserName=username)[
            "AttachedPolicies"
        ]
        for attached_policy in attached_policies:
            try:
                aws_client.iam.detach_user_policy(
                    UserName=username, PolicyArn=attached_policy["PolicyArn"]
                )
            except Exception:
                LOG.debug(
                    "Error detaching policy '%s' from user '%s'",
                    attached_policy["PolicyArn"],
                    username,
                )
        access_keys = aws_client.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for access_key in access_keys:
            try:
                aws_client.iam.delete_access_key(
                    UserName=username, AccessKeyId=access_key["AccessKeyId"]
                )
            except Exception:
                LOG.debug(
                    "Error deleting access key '%s' from user '%s'",
                    access_key["AccessKeyId"],
                    username,
                )

        try:
            aws_client.iam.delete_user(UserName=username)
        except Exception as e:
            LOG.debug("Error deleting user '%s' during test cleanup: %s", username, e)


@pytest.fixture
def wait_and_assume_role(aws_client):
    def _wait_and_assume_role(role_arn: str, session_name: str = None):
        if not session_name:
            session_name = f"session-{short_uid()}"

        def assume_role():
            return aws_client.sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)[
                "Credentials"
            ]

        # need to retry a couple of times before we are allowed to assume this role in AWS
        keys = retry(assume_role, sleep=5, retries=4)
        return keys

    return _wait_and_assume_role


@pytest.fixture
def create_role(aws_client):
    role_names = []

    def _create_role(**kwargs):
        if not kwargs.get("RoleName"):
            kwargs["RoleName"] = f"role-{short_uid()}"
        result = aws_client.iam.create_role(**kwargs)
        role_names.append(result["Role"]["RoleName"])
        return result

    yield _create_role

    for role_name in role_names:
        # detach policies
        attached_policies = aws_client.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        for attached_policy in attached_policies:
            try:
                aws_client.iam.detach_role_policy(
                    RoleName=role_name, PolicyArn=attached_policy["PolicyArn"]
                )
            except Exception:
                LOG.debug(
                    "Could not detach role policy '%s' from '%s' during cleanup",
                    attached_policy["PolicyArn"],
                    role_name,
                )
        role_policies = aws_client.iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for role_policy in role_policies:
            try:
                aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=role_policy)
            except Exception:
                LOG.debug(
                    "Could not delete role policy '%s' from '%s' during cleanup",
                    role_policy,
                    role_name,
                )
        try:
            aws_client.iam.delete_role(RoleName=role_name)
        except Exception:
            LOG.debug("Could not delete role '%s' during cleanup", role_name)


@pytest.fixture
def create_parameter(aws_client):
    params = []

    def _create_parameter(**kwargs):
        params.append(kwargs["Name"])
        return aws_client.ssm.put_parameter(**kwargs)

    yield _create_parameter

    for param in params:
        aws_client.ssm.delete_parameter(Name=param)


@pytest.fixture
def create_secret(aws_client):
    items = []

    def _create_parameter(**kwargs):
        create_response = aws_client.secretsmanager.create_secret(**kwargs)
        items.append(create_response["ARN"])
        return create_response

    yield _create_parameter

    for item in items:
        aws_client.secretsmanager.delete_secret(SecretId=item, ForceDeleteWithoutRecovery=True)


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
def acm_request_certificate(aws_client_factory):
    certificate_arns = []

    def factory(**kwargs) -> str:
        if "DomainName" not in kwargs:
            kwargs["DomainName"] = f"test-domain-{short_uid()}.localhost.localstack.cloud"

        region_name = kwargs.pop("region_name", None)
        acm_client = aws_client_factory(region_name=region_name).acm

        response = acm_client.request_certificate(**kwargs)
        created_certificate_arn = response["CertificateArn"]
        certificate_arns.append((created_certificate_arn, region_name))
        return response

    yield factory

    # cleanup
    for certificate_arn, region_name in certificate_arns:
        try:
            acm_client = aws_client_factory(region_name=region_name).acm
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
def lambda_su_role(aws_client):
    role_name = f"lambda-autogenerated-{short_uid()}"
    role = aws_client.iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=role_assume_policy
    )["Role"]
    policy_name = f"lambda-autogenerated-{short_uid()}"
    policy_arn = aws_client.iam.create_policy(
        PolicyName=policy_name, PolicyDocument=json.dumps(role_policy_su)
    )["Policy"]["Arn"]
    aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    if os.environ.get("TEST_TARGET", "") == "AWS_CLOUD":  # dirty but necessary
        time.sleep(10)

    yield role["Arn"]

    run_safe(aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    run_safe(aws_client.iam.delete_role(RoleName=role_name))
    run_safe(aws_client.iam.delete_policy(PolicyArn=policy_arn))


@pytest.fixture
def create_iam_role_with_policy(aws_client):
    roles = {}

    def _create_role_and_policy(**kwargs):
        role = kwargs["RoleName"]
        policy = kwargs["PolicyName"]
        role_policy = json.dumps(kwargs["RoleDefinition"])

        result = aws_client.iam.create_role(RoleName=role, AssumeRolePolicyDocument=role_policy)
        role_arn = result["Role"]["Arn"]
        policy_document = json.dumps(kwargs["PolicyDefinition"])
        aws_client.iam.put_role_policy(
            RoleName=role, PolicyName=policy, PolicyDocument=policy_document
        )
        roles[role] = policy
        return role_arn

    yield _create_role_and_policy

    for role_name, policy_name in roles.items():
        aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        aws_client.iam.delete_role(RoleName=role_name)


@pytest.fixture
def firehose_create_delivery_stream(wait_for_delivery_stream_ready, aws_client):
    delivery_streams = {}

    def _create_delivery_stream(**kwargs):
        if "DeliveryStreamName" not in kwargs:
            kwargs["DeliveryStreamName"] = f"test-delivery-stream-{short_uid()}"

        delivery_stream = aws_client.firehose.create_delivery_stream(**kwargs)
        delivery_streams.update({kwargs["DeliveryStreamName"]: delivery_stream})
        wait_for_delivery_stream_ready(kwargs["DeliveryStreamName"])
        return delivery_stream

    yield _create_delivery_stream

    for delivery_stream_name in delivery_streams.keys():
        aws_client.firehose.delete_delivery_stream(DeliveryStreamName=delivery_stream_name)


@pytest.fixture
def events_create_rule(aws_client):
    rules = []

    def _create_rule(**kwargs):
        rule_name = kwargs["Name"]
        bus_name = kwargs.get("EventBusName", "")
        pattern = kwargs.get("EventPattern", {})
        schedule = kwargs.get("ScheduleExpression", "")
        rule_arn = aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(pattern),
            ScheduleExpression=schedule,
        )["RuleArn"]
        rules.append({"name": rule_name, "bus": bus_name})
        return rule_arn

    yield _create_rule

    for rule in rules:
        targets = aws_client.events.list_targets_by_rule(
            Rule=rule["name"], EventBusName=rule["bus"]
        )["Targets"]

        targetIds = [target["Id"] for target in targets]
        if len(targetIds) > 0:
            aws_client.events.remove_targets(
                Rule=rule["name"], EventBusName=rule["bus"], Ids=targetIds
            )

        aws_client.events.delete_rule(Name=rule["name"], EventBusName=rule["bus"])


@pytest.fixture
def ses_configuration_set(aws_client):
    configuration_set_names = []

    def factory(name: str) -> None:
        aws_client.ses.create_configuration_set(
            ConfigurationSet={
                "Name": name,
            },
        )
        configuration_set_names.append(name)

    yield factory

    for configuration_set_name in configuration_set_names:
        aws_client.ses.delete_configuration_set(ConfigurationSetName=configuration_set_name)


@pytest.fixture
def ses_configuration_set_sns_event_destination(aws_client):
    event_destinations = []

    def factory(config_set_name: str, event_destination_name: str, topic_arn: str) -> None:
        aws_client.ses.create_configuration_set_event_destination(
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
        aws_client.ses.delete_configuration_set_event_destination(
            ConfigurationSetName=created_config_set_name,
            EventDestinationName=created_event_destination_name,
        )


@pytest.fixture
def ses_email_template(aws_client):
    template_names = []

    def factory(name: str, contents: str, subject: str = f"Email template {short_uid()}"):
        aws_client.ses.create_template(
            Template={
                "TemplateName": name,
                "SubjectPart": subject,
                "TextPart": contents,
            }
        )
        template_names.append(name)

    yield factory

    for template_name in template_names:
        aws_client.ses.delete_template(TemplateName=template_name)


@pytest.fixture
def ses_verify_identity(aws_client):
    identities = []

    def factory(email_address: str) -> None:
        aws_client.ses.verify_email_identity(EmailAddress=email_address)

    yield factory

    for identity in identities:
        aws_client.ses.delete_identity(Identity=identity)


@pytest.fixture
def ec2_create_security_group(aws_client):
    ec2_sgs = []

    def factory(ports=None, **kwargs):
        if "GroupName" not in kwargs:
            kwargs["GroupName"] = f"test-sg-{short_uid()}"
        security_group = aws_client.ec2.create_security_group(**kwargs)

        permissions = [
            {
                "FromPort": port,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "ToPort": port,
            }
            for port in ports or []
        ]
        aws_client.ec2.authorize_security_group_ingress(
            GroupName=kwargs["GroupName"],
            IpPermissions=permissions,
        )

        ec2_sgs.append(security_group["GroupId"])
        return security_group

    yield factory

    for sg_group_id in ec2_sgs:
        try:
            aws_client.ec2.delete_security_group(GroupId=sg_group_id)
        except Exception as e:
            LOG.debug("Error cleaning up EC2 security group: %s, %s", sg_group_id, e)


@pytest.fixture
def cleanups(aws_client):
    cleanup_fns = []

    yield cleanup_fns

    for cleanup_callback in cleanup_fns[::-1]:
        try:
            cleanup_callback()
        except Exception as e:
            LOG.warning("Failed to execute cleanup", exc_info=e)


@pytest.fixture(scope="session")
def account_id(aws_client):
    sts_client = aws_client.sts
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
        CROSS_ACCOUNT_ATTR = CrossAccountAttribute(default=list)
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


@pytest.fixture
def create_rest_apigw(aws_client_factory):
    rest_apis = []

    def _create_apigateway_function(**kwargs):
        region_name = kwargs.pop("region_name", None)
        apigateway_client = aws_client_factory(region_name=region_name).apigateway

        response = apigateway_client.create_rest_api(**kwargs)
        api_id = response.get("id")
        rest_apis.append((api_id, region_name))
        resources = apigateway_client.get_resources(restApiId=api_id)
        root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]

        return api_id, response.get("name"), root_id

    yield _create_apigateway_function

    for rest_api_id, region_name in rest_apis:
        with contextlib.suppress(Exception):
            apigateway_client = aws_client_factory(region_name=region_name).apigateway
            apigateway_client.delete_rest_api(restApiId=rest_api_id)


@pytest.fixture
def create_rest_apigw_openapi(aws_client_factory):
    rest_apis = []

    def _create_apigateway_function(**kwargs):
        region_name = kwargs.pop("region_name", None)
        apigateway_client = aws_client_factory(region_name=region_name).apigateway

        response = apigateway_client.import_rest_api(**kwargs)
        api_id = response.get("id")
        rest_apis.append((api_id, region_name))
        return api_id, response

    yield _create_apigateway_function

    for rest_api_id, region_name in rest_apis:
        with contextlib.suppress(Exception):
            apigateway_client = aws_client_factory(region_name=region_name).apigateway
            apigateway_client.delete_rest_api(restApiId=rest_api_id)


@pytest.fixture
def appsync_create_api(aws_client):
    graphql_apis = []

    def factory(**kwargs):
        if "name" not in kwargs:
            kwargs["name"] = f"graphql-api-testing-name-{short_uid()}"
        if not kwargs.get("authenticationType"):
            kwargs["authenticationType"] = "API_KEY"

        result = aws_client.appsync.create_graphql_api(**kwargs)["graphqlApi"]
        graphql_apis.append(result["apiId"])
        return result

    yield factory

    for api in graphql_apis:
        try:
            aws_client.appsync.delete_graphql_api(apiId=api)
        except Exception as e:
            LOG.debug(f"Error cleaning up AppSync API: {api}, {e}")


@pytest.fixture
def assert_host_customisation(monkeypatch):
    hostname_external = f"external-host-{short_uid()}"
    # `LOCALSTACK_HOSTNAME` is really an internal variable that has been
    # exposed to the user at some point in the past. It is used by some
    # services that start resources (e.g. OpenSearch) to determine if the
    # service has been started correctly (i.e. a health check). This means that
    # the value must be resolvable by LocalStack or else the service resources
    # won't start properly.
    #
    # One hostname that's always resolvable is the hostname of the process
    # running LocalStack, so use that here.
    #
    # Note: We cannot use `localhost` since we explicitly check that the URL
    # passed in does not contain `localhost`, unless it is requried to.
    localstack_hostname = socket.gethostname()
    monkeypatch.setattr(config, "HOSTNAME_EXTERNAL", hostname_external)
    monkeypatch.setattr(config, "LOCALSTACK_HOSTNAME", localstack_hostname)

    def asserter(
        url: str,
        *,
        use_hostname_external: bool = False,
        use_localstack_hostname: bool = False,
        use_localstack_cloud: bool = False,
        use_localhost: bool = False,
        custom_host: Optional[str] = None,
    ):
        if use_hostname_external:
            assert hostname_external in url

            assert localstack_hostname not in url
            assert constants.LOCALHOST_HOSTNAME not in url
            assert constants.LOCALHOST not in url
        elif use_localstack_hostname:
            assert localstack_hostname in url

            assert hostname_external not in url
            assert constants.LOCALHOST_HOSTNAME not in url
            assert constants.LOCALHOST not in url
        elif use_localstack_cloud:
            assert constants.LOCALHOST_HOSTNAME in url

            assert hostname_external not in url
            assert localstack_hostname not in url
        elif use_localhost:
            assert constants.LOCALHOST in url

            assert constants.LOCALHOST_HOSTNAME not in url
            assert hostname_external not in url
            assert localstack_hostname not in url
        elif custom_host is not None:
            assert custom_host in url

            assert constants.LOCALHOST_HOSTNAME not in url
            assert hostname_external not in url
            assert localstack_hostname not in url
        else:
            raise ValueError("no assertions made")

    yield asserter


@pytest.fixture
def echo_http_server(httpserver: HTTPServer):
    """Spins up a local HTTP echo server and returns the endpoint URL"""

    def _echo(request: Request) -> Response:
        result = {
            "data": request.data or "{}",
            "headers": dict(request.headers),
            "url": request.url,
            "method": request.method,
        }
        response_body = json.dumps(json_safe(result))
        return Response(response_body, status=200)

    httpserver.expect_request("").respond_with_handler(_echo)
    http_endpoint = httpserver.url_for("/")

    return http_endpoint


@pytest.fixture
def echo_http_server_post(echo_http_server):
    """
    Returns an HTTP echo server URL for POST requests that work both locally and for parity tests (against real AWS)
    """
    if is_aws_cloud():
        return f"{PUBLIC_HTTP_ECHO_SERVER_URL}/post"

    return f"{echo_http_server}/post"


def create_policy_doc(effect: str, actions: List, resource=None) -> Dict:
    actions = ensure_list(actions)
    resource = resource or "*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                # TODO statement ids have to be alphanumeric [0-9A-Za-z], write a test for it
                "Sid": f"s{short_uid()}",
                "Effect": effect,
                "Action": actions,
                "Resource": resource,
            }
        ],
    }


@pytest.fixture
def create_policy_generated_document(create_policy):
    def _create_policy_with_doc(effect, actions, policy_name=None, resource=None):
        policy_name = policy_name or f"p-{short_uid()}"
        policy = create_policy_doc(effect, actions, resource=resource)
        response = create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy))
        policy_arn = response["Policy"]["Arn"]
        return policy_arn

    return _create_policy_with_doc


@pytest.fixture
def create_role_with_policy(create_role, create_policy_generated_document, aws_client):
    def _create_role_with_policy(effect, actions, assume_policy_doc, resource=None, attach=True):
        role_name = f"role-{short_uid()}"
        result = create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_policy_doc)
        role_arn = result["Role"]["Arn"]
        policy_name = f"p-{short_uid()}"

        if attach:
            # create role and attach role policy
            policy_arn = create_policy_generated_document(
                effect, actions, policy_name=policy_name, resource=resource
            )
            aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        else:
            # put role policy
            policy_document = create_policy_doc(effect, actions, resource=resource)
            policy_document = json.dumps(policy_document)
            aws_client.iam.put_role_policy(
                RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document
            )

        return role_name, role_arn

    return _create_role_with_policy


@pytest.fixture
def create_user_with_policy(create_policy_generated_document, create_user, aws_client):
    def _create_user_with_policy(effect, actions, resource=None):
        policy_arn = create_policy_generated_document(effect, actions, resource=resource)
        username = f"user-{short_uid()}"
        create_user(UserName=username)
        aws_client.iam.attach_user_policy(UserName=username, PolicyArn=policy_arn)
        keys = aws_client.iam.create_access_key(UserName=username)["AccessKey"]
        return username, keys

    return _create_user_with_policy


@pytest.fixture()
def register_extension(s3_bucket, aws_client):
    cfn_client = aws_client.cloudformation
    extensions_arns = []

    def _register(extension_name, extension_type, artifact_path):
        bucket = s3_bucket
        key = f"artifact-{short_uid()}"

        aws_client.s3.upload_file(artifact_path, bucket, key)

        register_response = cfn_client.register_type(
            Type=extension_type,
            TypeName=extension_name,
            SchemaHandlerPackage=f"s3://{bucket}/{key}",
        )

        registration_token = register_response["RegistrationToken"]
        cfn_client.get_waiter("type_registration_complete").wait(
            RegistrationToken=registration_token
        )

        describe_response = cfn_client.describe_type_registration(
            RegistrationToken=registration_token
        )

        extensions_arns.append(describe_response["TypeArn"])
        cfn_client.set_type_default_version(Arn=describe_response["TypeVersionArn"])

        return describe_response

    yield _register

    for arn in extensions_arns:
        versions = cfn_client.list_type_versions(Arn=arn)["TypeVersionSummaries"]
        for v in versions:
            try:
                cfn_client.deregister_type(Arn=v["Arn"])
            except Exception:
                continue
        cfn_client.deregister_type(Arn=arn)
