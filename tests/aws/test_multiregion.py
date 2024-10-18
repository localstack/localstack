import base64
import json

import requests

from localstack import config
from localstack.constants import PATH_USER_REQUEST
from localstack.services.apigateway.legacy.helpers import connect_api_gateway_to_sqs
from localstack.testing.pytest import markers
from localstack.utils.aws import arns, queries
from localstack.utils.common import short_uid, to_str

REGION1 = "us-east-1"
REGION2 = "us-east-2"
REGION3 = "us-west-1"
REGION4 = "eu-central-1"


class TestMultiRegion:
    @markers.aws.validated
    def test_multi_region_sns(self, aws_client_factory):
        sns_1 = aws_client_factory(region_name=REGION1).sns
        sns_2 = aws_client_factory(region_name=REGION2).sns
        len_1 = len(sns_1.list_topics()["Topics"])
        len_2 = len(sns_2.list_topics()["Topics"])

        topic_name1 = "t-%s" % short_uid()
        sns_1.create_topic(Name=topic_name1)
        result1 = sns_1.list_topics()["Topics"]
        result2 = sns_2.list_topics()["Topics"]
        assert len(result1) == len_1 + 1
        assert len(result2) == len_2
        assert REGION1 in result1[0]["TopicArn"]

        topic_name2 = "t-%s" % short_uid()
        sns_2.create_topic(Name=topic_name2)
        result2 = sns_2.list_topics()["Topics"]
        assert len(result2) == len_2 + 1
        assert REGION2 in result2[0]["TopicArn"]

    @markers.aws.needs_fixing
    def test_multi_region_api_gateway(self, aws_client_factory, account_id):
        gw_1 = aws_client_factory(region_name=REGION1).apigateway
        gw_2 = aws_client_factory(region_name=REGION2).apigateway
        gw_3 = aws_client_factory(region_name=REGION3).apigateway
        sqs_1 = aws_client_factory(region_name=REGION3).sqs

        len_1 = len(gw_1.get_rest_apis()["items"])
        len_2 = len(gw_2.get_rest_apis()["items"])

        api_name1 = "a-%s" % short_uid()
        gw_1.create_rest_api(name=api_name1)
        result1 = gw_1.get_rest_apis()["items"]
        assert len(result1) == len_1 + 1
        assert len(gw_2.get_rest_apis()["items"]) == len_2

        api_name2 = "a-%s" % short_uid()
        gw_2.create_rest_api(name=api_name2)
        result2 = gw_2.get_rest_apis()["items"]
        assert len(gw_1.get_rest_apis()["items"]) == len_1 + 1
        assert len(result2) == len_2 + 1

        api_name3 = "a-%s" % short_uid()
        queue_name1 = "q-%s" % short_uid()
        sqs_1.create_queue(QueueName=queue_name1)
        queue_arn = arns.sqs_queue_arn(queue_name1, region_name=REGION3, account_id=account_id)

        result = connect_api_gateway_to_sqs(
            api_name3,
            stage_name="test",
            queue_arn=queue_arn,
            path="/data",
            account_id=account_id,
            region_name=REGION3,
        )

        api_id = result["id"]
        result = gw_3.get_rest_apis()["items"]
        assert result[-1]["name"] == api_name3

        # post message and receive from SQS
        url = self._gateway_request_url(api_id=api_id, stage_name="test", path="/data")
        test_data = {"foo": "bar"}
        result = requests.post(url, data=json.dumps(test_data))
        assert result.status_code == 200
        messages = queries.sqs_receive_message(queue_arn)["Messages"]
        assert len(messages) == 1
        assert json.loads(to_str(base64.b64decode(to_str(messages[0]["Body"])))) == test_data

    def _gateway_request_url(self, api_id, stage_name, path):
        pattern = "%s/restapis/{api_id}/{stage_name}/%s{path}" % (
            config.internal_service_url(),
            PATH_USER_REQUEST,
        )
        return pattern.format(api_id=api_id, stage_name=stage_name, path=path)
