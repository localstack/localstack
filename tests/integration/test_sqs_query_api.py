from urllib.parse import urlencode

import pytest
import requests

from localstack import config
from localstack.utils.strings import short_uid


@pytest.mark.skipif(
    config.SERVICE_PROVIDER_CONFIG.get_provider("sqs") != "asf",
    reason="query API implemented as part of the new ASF provider",
)
class TestSqsQueryApi:
    @pytest.mark.aws_validated
    def test_get_queue_without_action_returns_unknown_operation(self, sqs_client, sqs_create_queue):
        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        assert queue_url.endswith(f"/{queue_name}")

        response = requests.get(queue_url)
        assert not response.ok
        assert response.status_code == 404
        assert "<UnknownOperationException" in response.text

    def test_get_queue_attributes_with_query_args(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()
        query = {
            "Action": "GetQueueAttributes",
            "AttributeName.1": "All",
            # TODO: AUTHPARAMS when testing against AWS
        }
        url = f"{queue_url}?{urlencode(query)}"

        response = requests.get(url)
        print(response.text)
        # TODO: maybe use the botocore parser to validate the response instead?
        assert response.ok
        assert "<GetQueueAttributesResponse" in response.text
        assert "<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs" in response.text
        assert queue_url.split("/")[-1] in response.text
