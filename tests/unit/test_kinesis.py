import json
import unittest
from requests.models import Response
from localstack import config
from localstack.services.kinesis.kinesis_listener import UPDATE_KINESIS
from localstack.utils.common import to_str

TEST_DATA = '{"StreamName": "NotExistingStream"}'


class KinesisListenerTest(unittest.TestCase):

    def test_describe_stream_summary_is_redirected(self):
        describe_stream_summary_header = {'X-Amz-Target': 'Kinesis_20131202.DescribeStreamSummary'}

        response = UPDATE_KINESIS.forward_request('POST', '/', TEST_DATA, describe_stream_summary_header)

        self.assertEqual(response, True)

    def test_random_error_on_put_record(self):
        put_record_header = {'X-Amz-Target': 'Kinesis_20131202.PutRecord'}
        config.KINESIS_ERROR_PROBABILITY = 1.0

        response = UPDATE_KINESIS.forward_request('POST', '/', TEST_DATA, put_record_header)

        self.assertEqual(response.status_code, 400)
        resp_json = json.loads(to_str(response.content))
        self.assertEqual(resp_json['ErrorCode'], 'ProvisionedThroughputExceededException')
        self.assertEqual(resp_json['ErrorMessage'], 'Rate exceeded for shard X in stream Y under account Z.')

    def test_random_error_on_put_records(self):
        put_records_header = {'X-Amz-Target': 'Kinesis_20131202.PutRecords'}
        data_with_one_record = '{"Records": ["test"]}'
        config.KINESIS_ERROR_PROBABILITY = 1.0

        response = UPDATE_KINESIS.forward_request('POST', '/', data_with_one_record, put_records_header)

        self.assertEqual(response.status_code, 200)
        resp_json = json.loads(to_str(response.content))
        self.assertEqual(resp_json['FailedRecordCount'], 1)
        self.assertEqual(len(resp_json['Records']), 1)
        failed_record = resp_json['Records'][0]
        self.assertEqual(failed_record['ErrorCode'], 'ProvisionedThroughputExceededException')
        self.assertEqual(failed_record['ErrorMessage'], 'Rate exceeded for shard X in stream Y under account Z.')

    def test_overwrite_update_shard_count_on_error(self):
        update_shard_count_header = {'X-Amz-Target': 'Kinesis_20131202.UpdateShardCount'}
        request_data = '{"StreamName": "TestStream", "TargetShardCount": 2, "ScalingType": "UNIFORM_SCALING"}'
        error_response = Response()
        error_response.status_code = 400

        response = UPDATE_KINESIS.return_response('POST', '/', request_data, update_shard_count_header, error_response)

        self.assertEqual(response.status_code, 200)
        resp_json = json.loads(to_str(response.content))
        self.assertEqual(resp_json['StreamName'], 'TestStream')
        self.assertEqual(resp_json['CurrentShardCount'], 1)
        self.assertEqual(resp_json['TargetShardCount'], 2)
