import base64
import json
import unittest

import requests

from localstack import config
from localstack.constants import PATH_USER_REQUEST
from localstack.services.apigateway.helpers import connect_api_gateway_to_sqs
from localstack.utils.aws import arns, aws_stack, queries
from localstack.utils.common import short_uid, to_str

REGION1 = "us-east-1"
REGION2 = "us-east-2"
REGION3 = "us-west-1"
REGION4 = "eu-central-1"


class TestMultiRegion(unittest.TestCase):
    def test_multi_region_sns(self):
        sns_1 = aws_stack.create_external_boto_client("sns", region_name=REGION1)
        sns_2 = aws_stack.create_external_boto_client("sns", region_name=REGION2)
        len_1 = len(sns_1.list_topics()["Topics"])
        len_2 = len(sns_2.list_topics()["Topics"])

        topic_name1 = "t-%s" % short_uid()
        sns_1.create_topic(Name=topic_name1)
        result1 = sns_1.list_topics()["Topics"]
        result2 = sns_2.list_topics()["Topics"]
        self.assertEqual(len(result1), len_1 + 1)
        self.assertEqual(len(result2), len_2)
        self.assertIn(REGION1, result1[0]["TopicArn"])

        topic_name2 = "t-%s" % short_uid()
        sns_2.create_topic(Name=topic_name2)
        result2 = sns_2.list_topics()["Topics"]
        self.assertEqual(len(result2), len_2 + 1)
        self.assertIn(REGION2, result2[0]["TopicArn"])

    def test_multi_region_api_gateway(self):
        gw_1 = aws_stack.create_external_boto_client("apigateway", region_name=REGION1)
        gw_2 = aws_stack.create_external_boto_client("apigateway", region_name=REGION2)
        gw_3 = aws_stack.create_external_boto_client("apigateway", region_name=REGION3)
        sqs_1 = aws_stack.create_external_boto_client("sqs", region_name=REGION1)
        len_1 = len(gw_1.get_rest_apis()["items"])
        len_2 = len(gw_2.get_rest_apis()["items"])

        api_name1 = "a-%s" % short_uid()
        gw_1.create_rest_api(name=api_name1)
        result1 = gw_1.get_rest_apis()["items"]
        self.assertEqual(len(result1), len_1 + 1)
        self.assertEqual(len(gw_2.get_rest_apis()["items"]), len_2)

        api_name2 = "a-%s" % short_uid()
        gw_2.create_rest_api(name=api_name2)
        result2 = gw_2.get_rest_apis()["items"]
        self.assertEqual(len(gw_1.get_rest_apis()["items"]), len_1 + 1)
        self.assertEqual(len(result2), len_2 + 1)

        api_name3 = "a-%s" % short_uid()
        queue_name1 = "q-%s" % short_uid()
        sqs_1.create_queue(QueueName=queue_name1)
        queue_arn = arns.sqs_queue_arn(queue_name1, region_name=REGION1)
        result = connect_api_gateway_to_sqs(
            api_name3, stage_name="test", queue_arn=queue_arn, path="/data", region_name=REGION3
        )
        api_id = result["id"]
        result = gw_3.get_rest_apis()["items"]
        self.assertEqual(result[-1]["name"], api_name3)

        # post message and receive from SQS
        url = self._gateway_request_url(api_id=api_id, stage_name="test", path="/data")
        test_data = {"foo": "bar"}
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(result.status_code, 200)
        messages = queries.sqs_receive_message(queue_arn)["Messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(
            json.loads(to_str(base64.b64decode(to_str(messages[0]["Body"])))), test_data
        )

    def _gateway_request_url(self, api_id, stage_name, path):
        pattern = "%s/restapis/{api_id}/{stage_name}/%s{path}" % (
            config.service_url("apigateway"),
            PATH_USER_REQUEST,
        )
        return pattern.format(api_id=api_id, stage_name=stage_name, path=path)
