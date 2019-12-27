import unittest
from localstack.utils.tagging import TaggingService


class TestTaggingService(unittest.TestCase):
    svc = TaggingService()

    def test_list_empty(self):
        result = self.svc.list_tags_for_resource('test')
        self.assertEqual(result, '{"Tags":[]}')

    def test_create_tag(self):
        tags = [{'Key': 'key_key', 'Value': 'value_value'}]
        self.svc.tag_resource('arn', tags)
        result = self.svc.list_tags_for_resource('arn')
        self.assertEqual(
            result, '{"Tags":[{"Key": "key_key", "Value": "value_value"}]}')

    def test_delete_tag(self):
        tags = [{'Key': 'key_key', 'Value': 'value_value'}]
        self.svc.tag_resource('arn', tags)
        self.svc.untag_resource('arn', ['key_key'])
        result = self.svc.list_tags_for_resource('arn')
        self.assertEqual(
            result, '{"Tags":[]}')

    def test_list_empty_delete(self):
        self.svc.untag_resource('arn', ['key_key'])
        result = self.svc.list_tags_for_resource('arn')
        self.assertEqual(
            result, '{"Tags":[]}')
