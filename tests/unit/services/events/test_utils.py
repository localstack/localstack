import re

import pytest

from localstack.services.events.utils import is_nested_in_string


@pytest.mark.parametrize(
    "template, match, expected",
    [
        # Basic cases
        ('"users-service/users/<userId>"', "<userId>", True),
        ("<userId>", "<userId>", False),
        # Edge cases with commas and braces
        ('{"path": "users/<userId>", "id": <userId>}', "<userId>", True),
        ('{"id": <userId>}', "<userId>", False),
        # Multiple placeholders
        ('"users/<userId>/profile/<type>"', "<userId>", True),
        ('"users/<userId>/profile/<type>"', "<type>", True),
        # Nested JSON structures
        ('{"data": {"path": "users/<userId>"}}', "<userId>", True),
        ('{"data": <userId>}', "<userId>", False),
    ],
)
def test_is_nested_in_string(template, match, expected):
    pattern = re.compile(r"<.*?>")
    match = pattern.search(template, match)
    assert is_nested_in_string(template, match) == expected
