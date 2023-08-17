import boto3
import botocore.session
import jsonpath_ng
import mypy_boto3_sns
import pytest
from botocore.model import OperationModel

from localstack.utils.strings import short_uid


def clear_bucket(client_factory, *, Bucket: str):
    # TODO: get list of all files, try to delete them
    raise NotImplementedError()


mappings = {
    # SNS
    "sns.CreateTopic": [("sns.delete_topic", {"TopicArn": "$.TopicArn"})],
    # SQS
    "sqs.CreateQueue": [("sqs.delete_queue", {"QueueUrl": "$.QueueUrl"})],
    # Lambda
    "lambda.CreateFunction": [("lambda.delete_function", {"FunctionName": "$.FunctionArn"})],
    "lambda.PublishLayerVersion": [("lambda.delete_layer_version", {"LayerName": "$.LayerArn", "VersionNumber": "$.Version"})],
    "lambda.CreateEventSourceMapping": [("lambda.delete_event_source_mapping", {"Uuid": "$.UUID"})],
    # CloudFormation
    "cloudformation.CreateStack": [("cloudformation.delete_stack", {"StackName": "$.StackId"})],
    "cloudformation.CreateChangeSet": [("cloudformation.delete_stack", {"StackName": "$.StackId"})],
    # IAM
    "iam.CreateUser": [("iam.delete_user", {"UserName": "$.User.UserName"})],
    "iam.CreateRole": [("iam.delete_role", {"RoleName": "$.Role.RoleName"})],
    "iam.CreatePolicy": [("iam.delete_policy", {"PolicyArn": "$.Policy.Arn"})],
    # S3
    # order here matters(!)
    "s3.CreateBucket": [
        (clear_bucket, {"Bucket": (lambda resp: resp["Location"][1:])}),
        ("s3.delete_bucket", {"Bucket": (lambda resp: resp["Location"][1:])}),
    ],
    # DynamoDB
    "dynamodb.CreateTable": [("dynamodb.DeleteTable", {"TableName": "$.TableDescription.TableName"})],
}


def resolve_jsonpath(jsonpath_item, result):
    parsed = jsonpath_ng.parse(jsonpath_item)
    results = parsed.find(result)
    return results[0].value


def perform_cleanup(boto_session, cleanup_operations, parsed_result):
    """
    The actual core logic.
    Builds a client from the spec and calls the inverse/cleanup function with the dynamically resolved parameters
    """

    for op in cleanup_operations:
        cleanup_fn_spec, cleanup_params = op

        # resolve cleanup function
        if isinstance(cleanup_fn_spec, str):
            svc_name, operation_name = cleanup_fn_spec.split(".")
            client = boto_session.client(svc_name)
            cleanup_fn = getattr(client, operation_name)
        elif callable(cleanup_fn_spec):
            cleanup_fn = cleanup_fn_spec
        else:
            raise TypeError("unknown type for cleanup_fn_spec")

        # resolve parameters
        params = {}
        for k, v in cleanup_params.items():
            if callable(v):
                params[k] = v(parsed_result)

            elif isinstance(v, str) and v.startswith("$"):
                # currently assuming jsonpath
                params[k] = resolve_jsonpath(v, parsed_result)
            elif isinstance(v, str):
                # assuming static string to pass
                params[k] = v
            else:
                raise TypeError("Unknown type for cleanup parameter")

        # TODO: retries
        # TODO: waiting for status checks before/after
        result = cleanup_fn(**params)
        print(result)


@pytest.fixture(scope="function")
def cleanup_session(cleanups):
    session = botocore.session.get_session()
    boto3_session = boto3.session.Session(botocore_session=session)
    boto3.DEFAULT_SESSION = (
        boto3_session  # this should hopefully also then work for the testutil calls
    )

    def register_cleanup_handler(
        http_response, parsed, model: OperationModel, context, event_name, **kwargs
    ):
        key = f"{model.service_model.service_name}.{model.name}"
        cleanup_spec = mappings.get(key)
        if cleanup_spec:
            cleanups.append(lambda: perform_cleanup(boto3_session, cleanup_spec, parsed))

    session.register("after-call.*", register_cleanup_handler)
    return boto3_session


@pytest.fixture(scope="function")
def sns_clientv2(cleanup_session) -> mypy_boto3_sns.SNSClient:
    return cleanup_session.client("sns")


def test_cleanup_sns(sns_clientv2):
    sns_clientv2.create_topic(Name=f"test-cleanup-topic-{short_uid()}")
    sns_clientv2.create_topic(Name=f"test-cleanup-topic-{short_uid()}")
    print("done")
