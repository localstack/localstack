import logging

import jsonpath_ng
import pytest
from botocore.model import OperationModel

from localstack.testing.pytest import markers

LOG = logging.getLogger("AUTOCLEANUP")

def clear_bucket(client_factory, *, Bucket: str):
    # TODO: get list of all files, try to delete them
    raise NotImplementedError()

def handle_bucket(*args, **kwargs):
    print(":(")


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
        # (clear_bucket, {"Bucket": (lambda resp: resp["Location"][1:])}),
        # ("s3.delete_bucket", {"Bucket": (lambda resp: resp["Location"][1:])}),
        ("s3.delete_bucket", {"Bucket": handle_bucket}),
    ],
    # DynamoDB
    "dynamodb.CreateTable": [("dynamodb.DeleteTable", {"TableName": "$.TableDescription.TableName"})],
}


def resolve_jsonpath(jsonpath_item, result):
    parsed = jsonpath_ng.parse(jsonpath_item)
    results = parsed.find(result)
    return results[0].value


def perform_cleanup(factory_factory, boto_session, cleanup_operations, parsed_result):
    """
    The actual core logic.
    Builds a client from the spec and calls the inverse/cleanup function with the dynamically resolved parameters
    """
    LOG.info("Performing resource cleanup on AWS")
    LOG.info("-----------------")
    LOG.info(f"{parsed_result=}")
    LOG.info("-----------------")

    for op in cleanup_operations:
        cleanup_fn_spec, cleanup_params = op

        # resolve cleanup function
        if isinstance(cleanup_fn_spec, str):
            svc_name, operation_name = cleanup_fn_spec.split(".")
            factory = factory_factory(boto_session)
            client = factory.get_client(service_name=svc_name)
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
        LOG.info(f"result of cleanup: {result=}")
        LOG.info("-----------------")


TOPIC_NAME = "test-automatic-cleanup-topic-2"

class TestSnsResourceCleanup:

    @pytest.fixture(scope="function")
    def aws_cleanup_client(self, aws_session, cleanups):
        """ this fixture returns a client factory that will perform automatic cleanups """
        from localstack.testing.aws.util import base_aws_client_factory
        boto3_session = aws_session

        def register_cleanup_handler(
                http_response, parsed, model: OperationModel, context, event_name, **kwargs
        ):
            key = f"{model.service_model.service_name}.{model.name}"
            cleanup_spec = mappings.get(key)
            if cleanup_spec:
                cleanups.append(lambda: perform_cleanup(base_aws_client_factory, boto3_session, cleanup_spec, parsed))

        boto3_session._session.register("after-call.*", register_cleanup_handler)
        factory = base_aws_client_factory(boto3_session)
        return factory()

    @markers.aws.validated
    def test_create_topic(self, aws_cleanup_client):
        """ create a topic and verify it exists """

        aws_cleanup_client.sns.create_topic(Name=TOPIC_NAME)
        topics = aws_cleanup_client.sns.get_paginator("list_topics").paginate().build_full_result()['Topics']
        assert any([TOPIC_NAME in t['TopicArn'] for t in topics])

    @markers.aws.validated
    def test_topic_removed(self, aws_cleanup_client):
        """ verify that the created SNS topic from above does not exist anymore """
        topics = aws_cleanup_client.sns.get_paginator("list_topics").paginate().build_full_result()['Topics']
        assert not any([TOPIC_NAME in t['TopicArn'] for t in topics])


TEST_BUCKET = "localstack-test-bucket-autocleanup"
class TestS3BucketAutoCleanup:

    @pytest.fixture(scope="function")
    def aws_cleanup_client(self, aws_session, cleanups):
        """ this fixture returns a client factory that will perform automatic cleanups """
        from localstack.testing.aws.util import base_aws_client_factory
        boto3_session = aws_session

        def register_cleanup_handler(
                http_response, parsed, model: OperationModel, context, event_name, **kwargs
        ):
            key = f"{model.service_model.service_name}.{model.name}"
            cleanup_spec = mappings.get(key)
            if cleanup_spec:
                cleanups.append(lambda: perform_cleanup(base_aws_client_factory, boto3_session, cleanup_spec, parsed))

        boto3_session._session.register("after-call.*", register_cleanup_handler)
        factory = base_aws_client_factory(boto3_session)
        return factory()

    @markers.aws.validated
    def test_create_resource(self, aws_cleanup_client):
        """ create a topic and verify it exists """
        create_response = aws_cleanup_client.s3.create_bucket(Bucket=TEST_BUCKET)
        # create_response = aws_cleanup_client.s3.create_bucket(Bucket=TEST_BUCKET, CreateBucketConfiguration={"LocationConstraint": "EU"})
        # bucket_location = aws_cleanup_client.s3.create_bucket(Bucket=TEST_BUCKET, CreateBucketConfiguration={"LocationConstraint": "EU"})['Location']
        aws_cleanup_client.s3.get_bucket_location(Bucket=TEST_BUCKET)

    @markers.aws.validated
    def test_resource_removed(self, aws_cleanup_client):
        """ verify that the created SNS topic from above does not exist anymore """
        aws_cleanup_client.s3.delete_bucket(Bucket=TEST_BUCKET)
        with pytest.raises(aws_cleanup_client.s3.exceptions.NoSuchBucket):
            aws_cleanup_client.s3.get_bucket_location(Bucket=TEST_BUCKET)

