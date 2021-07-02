import unittest

from localstack.utils.tagging import TaggingService


class TestTaggingService(unittest.TestCase):
    svc = TaggingService()

    def test_list_empty(self):
        result = self.svc.list_tags_for_resource("test")
        self.assertEqual({"Tags": []}, result)

    def test_create_tag(self):
        tags = [{"Key": "key_key", "Value": "value_value"}]
        self.svc.tag_resource("arn", tags)
        actual = self.svc.list_tags_for_resource("arn")
        expected = {"Tags": [{"Key": "key_key", "Value": "value_value"}]}
        self.assertDictEqual(expected, actual)

    def test_delete_tag(self):
        tags = [{"Key": "key_key", "Value": "value_value"}]
        self.svc.tag_resource("arn", tags)
        self.svc.untag_resource("arn", ["key_key"])
        result = self.svc.list_tags_for_resource("arn")
        self.assertEqual({"Tags": []}, result)

    def test_list_empty_delete(self):
        self.svc.untag_resource("arn", ["key_key"])
        result = self.svc.list_tags_for_resource("arn")
        self.assertEqual({"Tags": []}, result)
