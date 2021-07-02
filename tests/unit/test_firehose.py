import unittest

from localstack.services.firehose import firehose_api
from localstack.utils.common import short_uid

TEST_STREAM_NAME = "firehose_test_" + short_uid()
TEST_TAG_1 = {"Key": "MyTag", "Value": "TestValue"}
TEST_TAG_2 = {"Key": "AnotherTag", "Value": "AnotherValue"}
TEST_TAGS = [TEST_TAG_1, TEST_TAG_2]


class FirehoseApiTest(unittest.TestCase):
    def setUp(self):
        firehose_api.create_stream(TEST_STREAM_NAME, tags=TEST_TAGS)

    def tearDown(self):
        firehose_api.delete_stream(TEST_STREAM_NAME)

    def test_delivery_stream_tags(self):
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME)
        self.assertEqual(TEST_TAGS, result["Tags"])
        result = firehose_api.get_delivery_stream_tags(
            TEST_STREAM_NAME, exclusive_start_tag_key="MyTag"
        )
        self.assertEqual([TEST_TAG_2], result["Tags"])
        result = firehose_api.get_delivery_stream_tags(TEST_STREAM_NAME, limit=1)
        self.assertEqual([TEST_TAG_1], result["Tags"])
        self.assertTrue(result["HasMore"])
