import dataclasses
import json
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Dict, List, Optional

import boto3
import botocore.config
import pytest

from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import create_dynamodb_table
from localstack.utils.common import ensure_list, load_file, poll_condition, retry
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import short_uid
from localstack.utils.functions import run_safe
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.testutil import start_http_server
from tests.integration.cloudformation.utils import render_template, template_path
from tests.integration.util import get_lambda_logs

if TYPE_CHECKING:
    from mypy_boto3_acm import ACMClient
    from mypy_boto3_apigateway import APIGatewayClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_cognito_idp import CognitoIdentityProviderClient
    from mypy_boto3_dynamodb import DynamoDBClient, DynamoDBServiceResource
    from mypy_boto3_dynamodbstreams import DynamoDBStreamsClient
    from mypy_boto3_ec2 import EC2Client
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
    from mypy_boto3_resourcegroupstaggingapi import ResourceGroupsTaggingAPIClient
    from mypy_boto3_route53 import Route53Client
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
    return aws_stack.create_external_boto_client(service, config=config)


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
def rgsa_client() -> "ResourceGroupsTaggingAPIClient":
    return _client("resourcegroupstaggingapi")


@pytest.fixture(scope="class")
def route53_client() -> "Route53Client":
    return _client("route53")


@pytest.fixture
def dynamodb_create_table(dynamodb_client):
    tables = []

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
            # table has to be in ACTIVE state before deletion
            def wait_for_table_created():
                return (
                    dynamodb_client.describe_table(TableName=table)["Table"]["TableStatus"]
                    == "ACTIVE"
                )

            poll_condition(wait_for_table_created, timeout=30)
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
def sns_create_sqs_subscription(sns_client, sqs_client):
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
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": queue_arn,
                                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                            }
                        ]
                    }
                )
            },
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
def kinesis_create_stream(kinesis_client):
    stream_names = []

    def _create_stream(**kwargs):
        if "StreamName" not in kwargs:
            kwargs["StreamName"] = f"test-stream-{short_uid()}"
        if "ShardCount" not in kwargs:
            kwargs["ShardCount"] = 2
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
def kms_key(kms_client):
    return kms_client.create_key(
        Policy="policy1", Description="test key 123", KeyUsage="ENCRYPT_DECRYPT"
    )


@pytest.fixture
def kms_grant_and_key(kms_client, kms_key):
    return [
        kms_client.create_grant(
            KeyId=kms_key["KeyMetadata"]["KeyId"],
            GranteePrincipal="arn:aws:iam::000000000000:role/test",
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


@dataclasses.dataclass(frozen=True)
class DeployResult:
    change_set_id: str
    stack_id: str
    stack_name: str
    change_set_name: str
    outputs: Dict[str, str]


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
        template: Optional[str] = None,
        template_file_name: Optional[str] = None,
        template_mapping: Optional[Dict[str, any]] = None,
        parameters: Optional[Dict[str, str]] = None,
    ) -> DeployResult:
        if is_update:
            assert stack_name
        else:
            stack_name = f"stack-{short_uid()}"
        change_set_name = f"change-set-{short_uid()}"

        if template_file_name is not None and os.path.exists(template_path(template_file_name)):
            template = load_file(template_path(template_file_name))
        template_rendered = render_template(template, **(template_mapping or {}))

        response = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_rendered,
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

        assert wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        assert wait_until(is_change_set_finished(change_set_id))

        outputs = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])

        mapped_outputs = {o["OutputKey"]: o["OutputValue"] for o in outputs}

        state.append({"stack_id": stack_id, "change_set_id": change_set_id})
        return DeployResult(change_set_id, stack_id, stack_name, change_set_name, mapped_outputs)

    yield _deploy

    for entry in state:
        entry_stack_id = entry.get("stack_id")
        entry_change_set_id = entry.get("change_set_id")
        try:
            entry_change_set_id and cleanup_changesets(entry_change_set_id)
            entry_stack_id and cleanup_stacks(entry_stack_id)
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
    def _is_change_set_finished(change_set_id: str):
        def _inner():
            check_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
            return check_set.get("ExecutionStatus") == "EXECUTE_COMPLETE"

        return _inner

    return _is_change_set_finished


@pytest.fixture
def wait_until_lambda_ready(lambda_client):
    def _wait_until_ready(function_name: str, qualifier: str = None):
        def _is_not_pending():
            kwargs = {}
            if qualifier:
                kwargs["Qualifier"] = qualifier
            try:
                result = (
                    lambda_client.get_function(FunctionName=function_name)["Configuration"]["State"]
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
def create_lambda_function(lambda_client, iam_client, wait_until_lambda_ready):
    lambda_arns = []
    role_names = []
    policy_arns = []

    def _create_lambda_function(*args, **kwargs):
        kwargs["client"] = lambda_client
        func_name = kwargs.get("func_name")
        assert func_name
        del kwargs["func_name"]

        if not kwargs.get("role"):
            role_name = f"lambda-autogenerated-{short_uid()}"
            role_names.append(role_name)
            role = iam_client.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=role_assume_policy
            )["Role"]
            policy_name = f"lambda-autogenerated-{short_uid()}"
            policy_arn = iam_client.create_policy(
                PolicyName=policy_name, PolicyDocument=role_policy
            )["Policy"]["Arn"]
            policy_arns.append(policy_arn)
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            kwargs["role"] = role["Arn"]

        def _create_function():
            resp = testutil.create_lambda_function(func_name, **kwargs)
            lambda_arns.append(resp["CreateFunctionResponse"]["FunctionArn"])
            wait_until_lambda_ready(function_name=func_name)
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

    for role_name in role_names:
        try:
            iam_client.delete_role(RoleName=role_name)
        except Exception:
            LOG.debug(f"Unable to delete role {role_name=} in cleanup")

    for policy_arn in policy_arns:
        try:
            iam_client.delete_policy(PolicyArn=policy_arn)
        except Exception:
            LOG.debug(f"Unable to delete policy {policy_arn=} in cleanup")


@pytest.fixture
def check_lambda_logs(logs_client):
    def _check_logs(func_name: str, expected_lines: List[str] = None):
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

    return _check_logs


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
        secretsmanager_client.delete_secret(SecretId=item)


@pytest.fixture
def acm_request_certificate(acm_client):
    certificate_arns = []

    def factory(**kwargs) -> str:
        if "DomainName" not in kwargs:
            kwargs["DomainName"] = f"test-domain-{short_uid()}.localhost.localstack.cloud"

        response = acm_client.request_certificate(**kwargs)
        created_certificate_arn = response["CertificateArn"]
        certificate_arns.append(created_certificate_arn)
        return created_certificate_arn

    yield factory

    # cleanup
    for certificate_arn in certificate_arns:
        try:
            acm_client.delete_certificate(CertificateArn=certificate_arn)
        except Exception as e:
            LOG.debug("error cleaning up certificate %s: %s", certificate_arn, e)


only_localstack = pytest.mark.skipif(
    os.environ.get("TEST_TARGET") == "AWS_CLOUD",
    reason="test only applicable if run against localstack",
)


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
def cleanups(ec2_client):
    cleanup_fns = []

    yield cleanup_fns

    for cleanup_callback in cleanup_fns[::-1]:
        try:
            cleanup_callback()
        except Exception as e:
            LOG.warning("Failed to execute cleanup", exc_info=e)
