"""
Shared tag management utilities for Step Functions resources (state machines and activities).

This module provides a common TagManager class used to handle tag operations
across different Step Functions resource types.
"""
from collections import OrderedDict
from typing import Final

from localstack.aws.api.stepfunctions import Tag, TagKeyList, TagList, ValidationException


class TagManager:
    """
    Manages tags for Step Functions resources (state machines and activities).

    Provides methods to add, remove, and list tags while enforcing AWS tag validation rules.
    Tags are stored in an OrderedDict to maintain insertion order.
    """
    _tags: Final[dict[str, str | None]]

    def __init__(self):
        self._tags = OrderedDict()

    @staticmethod
    def _validate_key_value(key: str) -> None:
        """
        Validate that a tag key is not empty.

        :param key: The tag key to validate
        :raises ValidationException: If key is empty or None
        """
        if not key:
            raise ValidationException()

    @staticmethod
    def _validate_tag_value(value: str) -> None:
        """
        Validate that a tag value is not None.

        :param value: The tag value to validate
        :raises ValidationException: If value is None
        """
        if value is None:
            raise ValidationException()

    def add_all(self, tags: TagList) -> None:
        """
        Add multiple tags to the resource.

        If a tag key already exists, its value will be updated.

        :param tags: List of Tag objects to add
        :raises ValidationException: If any tag key or value is invalid
        """
        for tag in tags:
            tag_key = tag["key"]
            tag_value = tag["value"]
            self._validate_key_value(key=tag_key)
            self._validate_tag_value(value=tag_value)
            self._tags[tag_key] = tag_value

    def remove_all(self, keys: TagKeyList):
        """
        Remove multiple tags from the resource by their keys.

        If a key doesn't exist, it is silently ignored.

        :param keys: List of tag keys to remove
        :raises ValidationException: If any key is invalid
        """
        for key in keys:
            self._validate_key_value(key=key)
            self._tags.pop(key, None)

    def to_tag_list(self) -> TagList:
        """
        Convert internal tag storage to AWS TagList format.

        :return: List of Tag objects suitable for API responses
        """
        tag_list = []
        for key, value in self._tags.items():
            tag_list.append(Tag(key=key, value=value))
        return tag_list
