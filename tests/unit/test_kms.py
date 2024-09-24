import pytest

from localstack.services.kms.utils import validate_alias_name


def test_alias_name_validator():
    with pytest.raises(Exception):
        validate_alias_name("test-alias")
