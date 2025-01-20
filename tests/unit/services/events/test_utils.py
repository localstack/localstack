import re

import pytest

from localstack.services.events.utils import is_nested_in_string


@pytest.mark.parametrize(
    "template, expected",
    [
        # Basic cases
        ('"users-service/users/<userId>"', True),
        ('"<userId>"', True),
        # Edge cases with commas and braces
        ('{"path": "users/<userId>", "id": <userId>}', True),
        ('{"id": <userId>}', False),
        # Multiple placeholders
        ('"users/<userId>/profile/<type>"', True),
        # Nested JSON structures
        ('{"data": {"path": "users/<userId>"}}', True),
        ('{"data": <userId>}', False),
        ('{"data": "<userId>"}', True),
    ],
)
def test_is_nested_in_string(template, expected):
    pattern = re.compile(r"<.*?>")
    match = pattern.search(template)
    assert is_nested_in_string(template, match) == expected
