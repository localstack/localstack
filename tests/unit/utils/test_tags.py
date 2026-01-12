from localstack.utils.aws import tags


def test_convert_tag_list_to_dictionary():
    tags_list = [{"Key": "key", "Value": "value"}]
    assert tags.tag_list_to_dict(tags_list) == {"key": "value"}


def test_convert_tag_dictionary_to_list():
    tags_dict = {"key": "value"}
    assert tags.tag_dict_to_list(tags_dict) == [{"Key": "key", "Value": "value"}]
