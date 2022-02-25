import dataclasses
import json
import logging
import os
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
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.testutil import start_http_server
from tests.integration.cloudformation.utils import render_template, template_path

if TYPE_CHECKING:
    from mypy_boto3_acm import ACMClient
    from mypy_boto3_apigateway import APIGatewayClient
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_dynamodb import DynamoDBClient
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
    from mypy_boto3_s3 import S3Client
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
            dynamodb_client.delete_table(TableName=table)
        except Exception as e:
            LOG.debug("error cleaning up table %s: %s", table, e)


@pytest.fixture
def s3_create_bucket(s3_client):
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
            s3_client.delete_bucket(Bucket=bucket)
        except Exception as e:
            LOG.debug("error cleaning up bucket %s: %s", bucket, e)


@pytest.fixture
def s3_bucket(s3_create_bucket) -> str:
    return s3_create_bucket()


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
def sns_topic(sns_client, sns_create_topic) -> "GetTopicAttributesResponseTypeDef":
    topic_arn = sns_create_topic()["TopicArn"]
    return sns_client.get_topic_attributes(TopicArn=topic_arn)


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
            kinesis_client.delete_stream(StreamName=stream_name)
        except Exception as e:
            LOG.debug("error cleaning up kinesis stream %s: %s", stream_name, e)


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
    stack_name = f"stack-{short_uid()}"
    state = []

    def _deploy(
        *,
        is_update: Optional[bool] = False,
        template: Optional[str] = None,
        template_file_name: Optional[str] = None,
        template_mapping: Optional[Dict[str, any]] = None,
        parameters: Optional[Dict[str, str]] = None,
    ) -> DeployResult:
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

        outputs = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]

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
def create_lambda_function(lambda_client: "LambdaClient", iam_client):
    lambda_arns = []
    role_names = []

    def _create_lambda_function(**kwargs):
        kwargs["client"] = lambda_client

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
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            kwargs["role"] = role["Arn"]

        def _create_function():
            resp = testutil.create_lambda_function(**kwargs)
            lambda_arns.append(resp["CreateFunctionResponse"]["FunctionArn"])

            def _is_not_pending():
                try:
                    result = (
                        lambda_client.get_function(FunctionName=kwargs["func_name"])[
                            "Configuration"
                        ]["State"]
                        != "Pending"
                    )
                    LOG.debug(f"lambda state result: {result=}")
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

    for role_name in role_names:
        try:
            iam_client.delete_role(RoleName=role_name)
        except Exception:
            LOG.debug(f"Unable to delete role {role_name=} in cleanup")


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


only_localstack = pytest.mark.skipif(
    os.environ.get("TEST_TARGET") == "AWS_CLOUD",
    reason="test only applicable if run against localstack",
)


@pytest.fixture
def tmp_http_server():
    test_port, invocations, proxy = start_http_server()
    yield test_port, invocations, proxy
    proxy.stop()
