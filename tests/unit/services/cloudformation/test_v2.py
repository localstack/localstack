import pytest

from localstack.services.cloudformation.engine.v2.change_set_model_static_preproc import (
    UnComputable,
    is_computable,
)


class TestIsComputable:
    @pytest.mark.parametrize(
        "value,expected",
        [
            # primitives
            (UnComputable, False),
            ("test", True),
            (1, True),
            # lists
            ([], True),
            ([1], True),
            ([UnComputable], False),
            ([":", UnComputable], False),
            ([[[UnComputable]], 2], False),
            # dictionaries
            ({}, True),
            ({"a": "b"}, True),
            ({"a": UnComputable}, False),
            ({"a": {"b": UnComputable}}, False),
            # combinations of compounds
            ({"a": [1, 2, 3]}, True),
            ({"a": [1, 2, UnComputable]}, False),
            # sets
            (set(), True),
            ({1, 2}, True),
            ({1, UnComputable}, False),
        ],
    )
    def test_is_computable(self, value, expected):
        assert is_computable(value) == expected, f"is_computable({value}) != {expected}"
