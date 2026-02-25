from localstack.utils import tagging


def test_convert_tag_list_to_dictionary():
    tags_list = [{"Key": "key", "Value": "value"}]
    assert tagging.tag_list_to_map(tags_list) == {"key": "value"}


def test_convert_tag_dictionary_to_list():
    tags_dict = {"key": "value"}
    assert tagging.tag_map_to_list(tags_dict) == [{"Key": "key", "Value": "value"}]
