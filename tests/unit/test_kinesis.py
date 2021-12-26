import json
import unittest

from requests.models import Response

from localstack import config
from localstack.services.kinesis.kinesis_listener import UPDATE_KINESIS
from localstack.utils.common import to_str

TEST_DATA = '{"StreamName": "NotExistingStream"}'


class KinesisListenerTest(unittest.TestCase):
    def test_describe_stream_summary_is_redirected(self):
        if config.KINESIS_PROVIDER == "kinesalite":
            describe_stream_summary_header = {
                "X-Amz-Target": "Kinesis_20131202.DescribeStreamSummary"
            }

            response = UPDATE_KINESIS.forward_request(
                "POST", "/", TEST_DATA, describe_stream_summary_header
            )

            self.assertTrue(response)
        else:
            self.assertTrue(True)

    def test_random_error_on_put_record(self):
        put_record_header = {"X-Amz-Target": "Kinesis_20131202.PutRecord"}
        config.KINESIS_ERROR_PROBABILITY = 1.0

        response = UPDATE_KINESIS.forward_request("POST", "/", TEST_DATA, put_record_header)

        self.assertEqual(response.status_code, 400)
        resp_json = json.loads(to_str(response.content))
        self.assertEqual("ProvisionedThroughputExceededException", resp_json["__type"])
        self.assertEqual(
            "Rate exceeded for shard X in stream Y under account Z.",
            resp_json["ErrorMessage"],
        )

    def test_random_error_on_put_records(self):
        put_records_header = {"X-Amz-Target": "Kinesis_20131202.PutRecords"}
        data_with_one_record = '{"Records": ["test"]}'
        config.KINESIS_ERROR_PROBABILITY = 1.0

        response = UPDATE_KINESIS.forward_request(
            "POST", "/", data_with_one_record, put_records_header
        )

        self.assertEqual(200, response.status_code)
        resp_json = json.loads(to_str(response.content))
        self.assertEqual(1, resp_json["FailedRecordCount"])
        self.assertEqual(1, len(resp_json["Records"]))
        failed_record = resp_json["Records"][0]
        self.assertEqual("ProvisionedThroughputExceededException", failed_record["ErrorCode"])
        self.assertEqual(
            "Rate exceeded for shard X in stream Y under account Z.",
            failed_record["ErrorMessage"],
        )

    def test_overwrite_update_shard_count_on_error(self):
        if config.KINESIS_PROVIDER == "kinesalite":
            update_shard_count_header = {"X-Amz-Target": "Kinesis_20131202.UpdateShardCount"}
            request_data = '{"StreamName": "TestStream", "TargetShardCount": 2, "ScalingType": "UNIFORM_SCALING"}'
            error_response = Response()
            error_response.status_code = 400

            response = UPDATE_KINESIS.return_response(
                "POST", "/", request_data, update_shard_count_header, error_response
            )

            self.assertEqual(200, response.status_code)
            resp_json = json.loads(to_str(response.content))
            self.assertEqual("TestStream", resp_json["StreamName"])
            self.assertEqual(1, resp_json["CurrentShardCount"])
            self.assertEqual(2, resp_json["TargetShardCount"])
        else:
            self.assertTrue(True)
