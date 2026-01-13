from typing import TypedDict


class Tag(TypedDict):
    Key: str
    Value: str


def tag_list_to_dict(tag_list: list[Tag]) -> dict[str, str]:
    """
    Converts a list of Tag objects into a dictionary, mapping each tag's
    "Key" to its "Value". This utility function is useful for transforming
    structured tag key-value pairs into a more accessible dictionary format.

    >>>assert tag_list_to_dict([{"Key": "key", "Value": "value"}]) == {"key": "value"}

    :param tag_list: A list of Tag objects where each tag contains a "Key"
        and a "Value" pair.
    :type tag_list: list[Tag]
    :return: A dictionary where each key corresponds to a tag's "Key" and
        each value corresponds to a tag's "Value".
    :rtype: dict[str, str]
    """
    return {tag["Key"]: tag["Value"] for tag in tag_list}


def tag_dict_to_list(tag_dict: dict[str, str]) -> list[Tag]:
    """
    Converts a dictionary of tags into a list of Tag objects formatted as dictionaries containing
    'Key' and 'Value'.

    This function takes a dictionary where keys and values represent tag names and their corresponding
    values, and transforms it into a list of dictionaries where each dictionary represents a tag with
    a 'Key' and a 'Value'.

    >>>assert tag_dict_to_list({"key": "value"}) == [{"Key": "key", "Value": "value"}]

    :param tag_dict: A dictionary where keys represent tag names and values represent tag values.
    :type tag_dict: dict[str, str]
    :return: A list of dictionaries where each dictionary contains 'Key' and 'Value' representing
        a tag.
    :rtype: list[Tag]
    """
    return [{"Key": key, "Value": value} for key, value in tag_dict.items()]
