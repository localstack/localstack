from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.handlers.response_aggregator import get_resource_id
from localstack.http import Response

empty_response = Response(status=200)


class TestGetResourceId:
    def test_sqs_create_queue(self):
        context = create_aws_request_context("sqs", "CreateQueue", {"QueueName": "foobar"})
        assert get_resource_id(context, empty_response) == "foobar"

    def test_sqs_delete_queue(self):
        context = create_aws_request_context(
            "sqs", "DeleteQueue", {"QueueUrl": "http://localhost:4566/000000000000/foobar"}
        )
        assert get_resource_id(context, empty_response) == "foobar"

    def test_sns_delete_topic(self):
        context = create_aws_request_context(
            "sns", "DeleteTopic", {"TopicArn": "arn:aws:sns:us-east-1:000000000000:foobar"}
        )
        assert get_resource_id(context, empty_response) == "foobar"

    def test_unknown_operation_returns_none(self):
        context = create_aws_request_context("sqs", "ListQueues", {})
        assert get_resource_id(context, empty_response) is None

    def test_missing_parameter_returns_none(self):
        context = create_aws_request_context("sns", "CreateTopic", {"Name": "foobar"})
        context.service_request = {}  # provoke the error case
        assert get_resource_id(context, empty_response) is None
