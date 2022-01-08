import boto3

from localstack.aws.api import handler
from localstack.aws.proxy import AsfWithFallbackListener, AwsApiListener
from localstack.services.generic_proxy import ProxyListener
from localstack.utils import testutil
from localstack.utils.aws.aws_responses import requests_response


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


class TestAsfWithFallbackListener:
    def test_request_response(self):
        provider_calls = []
        fallback_calls = []

        class Provider:
            @handler("ListQueues", expand=False)
            def list_queues(self, context, request):
                return {
                    "QueueUrls": [
                        "http://localhost:4566/000000000000/foo-queue",
                    ],
                }

            @handler("DeleteQueue", expand=False)
            def delete_queue(self, context, request):
                provider_calls.append((context, request))
                raise NotImplementedError

        class Fallback(ProxyListener):
            def forward_request(self, method: str, path: str, data, headers):
                fallback_calls.append((method, path, data, headers))
                return requests_response("<Response></Response>")

        # create a proxy listener for the provider
        listener = AsfWithFallbackListener("sqs", Provider(), Fallback())

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

            # check that provider is called correctly
            result = client.list_queues()
            assert result["QueueUrls"] == [
                "http://localhost:4566/000000000000/foo-queue",
            ]
            assert len(provider_calls) == 0
            assert len(fallback_calls) == 0

            # check that fallback is called correctly
            client.delete_queue(QueueUrl="http://localhost:4566/000000000000/somequeue")
            assert len(provider_calls) == 1
            assert len(fallback_calls) == 1
