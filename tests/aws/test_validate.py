from localstack.testing.pytest import markers

"""This is to demonstrate how to write tests for server-side request validation. Ideally these tests are part of the
service test suite."""
import pytest
from botocore.auth import SigV4Auth


@pytest.mark.skip(reason="there is no generalized way of server-side request validation yet")
class TestMissingParameter:
    @markers.aws.validated
    def test_opensearch(self, aws_http_client_factory):
        client = aws_http_client_factory("es", signer_factory=SigV4Auth)

        response = client.post(
            "/2021-01-01/opensearch/domain",
            data='{"foobar": "bazed"}',
        )

        assert (
            response.text
            == '{"message":"1 validation error detected: Value null at \'domainName\' failed to satisfy constraint: '
            'Member must not be null"}'
        )

    @markers.aws.validated
    def test_sns(self, aws_http_client_factory):
        client = aws_http_client_factory("sns", region="us-east-1")

        response = client.post(
            "/?Action=CreatePlatformApplication&Name=Foobar&Platform=Bar",
        )

        assert "<Code>ValidationError</Code>" in response.text
        assert (
            "<Message>1 validation error detected: Value null at 'attributes' failed to satisfy constraint: Member "
            "must not be null</Message>" in response.text
        )

    @markers.aws.validated
    def test_elasticache(self, aws_http_client_factory):
        client = aws_http_client_factory("elasticache")

        response = client.post(
            "/",
            params={
                "Action": "CreateCacheCluster",
            },
        )

        assert "<Code>InvalidParameterValue</Code>" in response.text
        assert (
            "<Message>The parameter CacheClusterIdentifier must be provided and must not be blank.</Message>"
            in response.text
        )

    @markers.aws.validated
    def test_sqs_create_queue(self, aws_http_client_factory):
        client = aws_http_client_factory("sqs")

        response = client.post(
            "/",
            params={
                "Action": "CreateQueue",
                "FooBar": "baz",
            },
        )

        assert "<Code>InvalidParameterValue</Code>" in response.text
        assert (
            "<Message>Value for parameter QueueName is invalid. Reason: Must specify a queue name.</Message>"
            in response.text
        )

    @markers.aws.validated
    def test_sqs_send_message(self, aws_http_client_factory, sqs_queue):
        client = aws_http_client_factory("sqs")

        response = client.post(
            "/",
            params={"Action": "SetQueueAttributes", "Version": "2012-11-05", "QueueUrl": sqs_queue},
        )

        assert "<Code>MissingParameter</Code>" in response.text
        assert (
            "<Message>The request must contain the parameter Attribute.Name.</Message>"
            in response.text
        )
