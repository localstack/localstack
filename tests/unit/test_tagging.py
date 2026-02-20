import pytest

from localstack.utils.tagging import TaggingService
from localstack.utils.strings import short_uid
from localstack.utils.tagging import Tags


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

@pytest.fixture
def mock_arn():
    return f"arn-{short_uid()}"


@pytest.fixture
def tags_collection():
    return Tags()

class TestTagsCollection:
    def test_update_tags(self, tags_collection, mock_arn):
        # Ensure the tags which existed / didn't exist before are updated accordingly.
        tags_collection.update_tags(mock_arn, {"Environment": "Production", "Foo": "Bar"})
        tags = tags_collection.get_tags(mock_arn)
        assert "Foo" in tags
        assert tags["Foo"] == "Bar"
        assert tags["Environment"] == "Production"

    def test_get_tags(self, tags_collection, mock_arn):
        non_existent_resource_tags = tags_collection.get_tags("bad-arn")
        assert len(non_existent_resource_tags) == 0

    def test_delete_tags(self, tags_collection, mock_arn):
        tags_collection.update_tags(mock_arn, {"Foo": "Bar"})

        # Test deleting the same key twice even when it's not in the tag mapping. This should not raise.
        for _ in range(2):
            tags_collection.delete_tags(mock_arn, ["Environment"])
            tags = tags_collection.get_tags(mock_arn)
            assert "Foo" in tags
            assert len(tags) == 1

        tags_collection.delete_tags(mock_arn, ["Foo"])
        tags = tags_collection.get_tags(mock_arn)
        assert len(tags) == 0

        # This operation shouldn't raise if the ARN is not in the tagging store.
        non_existent_arn = f"non-existent-{short_uid()}"
        tags_collection.delete_tags(non_existent_arn, ["Foo"])
        tags = tags_collection.get_tags(non_existent_arn)
        assert len(tags) == 0

    def test_delete_all_tags(self, tags_collection, mock_arn):
        tags_collection.update_tags(mock_arn, {"Foo": "Bar", "Environment": "Testing"})
        tags = tags_collection.get_tags(mock_arn)
        assert len(tags) == 2

        tags_collection.delete_all_tags(mock_arn)
        updated_tags = tags_collection.get_tags(mock_arn)
        assert len(updated_tags) == 0

        # Delete all tags should not raise if the ARN is not in the store
        non_existent_arn = f"non-existent-{short_uid()}"
        tags_collection.delete_all_tags(non_existent_arn)
        tags = tags_collection.get_tags(non_existent_arn)
        assert len(tags) == 0