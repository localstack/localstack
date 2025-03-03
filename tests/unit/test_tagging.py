import pytest

from localstack.utils.tagging import TaggingService


class TestTaggingService:
    @pytest.fixture
    def tagging_service(self):
        def _factory(**kwargs):
            return TaggingService(**kwargs)

        return _factory

    def test_list_empty(self, tagging_service):
        svc = tagging_service()
        result = svc.list_tags_for_resource("test")
        assert result == {"Tags": []}

    def test_create_tag(self, tagging_service):
        svc = tagging_service()
        tags = [{"Key": "key_key", "Value": "value_value"}]
        svc.tag_resource("arn", tags)
        actual = svc.list_tags_for_resource("arn")
        expected = {"Tags": [{"Key": "key_key", "Value": "value_value"}]}
        assert actual == expected

    def test_delete_tag(self, tagging_service):
        svc = tagging_service()
        tags = [{"Key": "key_key", "Value": "value_value"}]
        svc.tag_resource("arn", tags)
        svc.untag_resource("arn", ["key_key"])
        result = svc.list_tags_for_resource("arn")
        assert result == {"Tags": []}

    def test_list_empty_delete(self, tagging_service):
        svc = tagging_service()
        svc.untag_resource("arn", ["key_key"])
        result = svc.list_tags_for_resource("arn")
        assert result == {"Tags": []}

    def test_field_name_override(self, tagging_service):
        svc = tagging_service(key_field="keY", value_field="valuE")
        tags = [{"keY": "my", "valuE": "congratulations"}]
        svc.tag_resource("arn", tags)
        assert svc.list_tags_for_resource("arn") == {
            "Tags": [{"keY": "my", "valuE": "congratulations"}]
        }
