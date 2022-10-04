import boto3

from localstack.aws.api import handler
from localstack.aws.proxy import AwsApiListener
from localstack.utils import testutil


class TestAwsApiListener:
    def test_request_response(self):
        # define a AWS provider
        class Provider:
            @handler("ListQueues", expand=False)
            def list_queues(self, context, request):
                return {
                    "QueueUrls": [
                        "http://localhost:4566/000000000000/foo-queue",
                    ],
                }

        # create a proxy listener for the provider
        listener = AwsApiListener("sqs", Provider())

        # start temp proxy listener and connect to it
        with testutil.proxy_server(listener) as url:
            client = boto3.client(
                "sqs",
                aws_access_key_id="test",
                aws_secret_access_key="test",
                aws_session_token="test",
                region_name="us-east-1",
                endpoint_url=url,
            )

            result = client.list_queues()
            assert result["QueueUrls"] == [
                "http://localhost:4566/000000000000/foo-queue",
            ]
