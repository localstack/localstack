from localstack.services.lambda_.api_utils import (
    RUNTIMES,
    is_qualifier_expression,
    qualifier_is_alias,
    qualifier_is_version,
)
from localstack.services.lambda_.invocation.lambda_models import IMAGE_MAPPING


class TestApiUtils:
    def test_check_runtime(self):
        """
        Make sure that the list of runtimes to test at least contains all mapped runtime images.
        This is a test which ensures that runtimes considered for validation do not diverge from the supported runtimes.
        See #9020 for more details.
        """
        assert set(RUNTIMES) == set(IMAGE_MAPPING.keys())

    def test_is_qualifier_expression(self):
        assert is_qualifier_expression("abczABCZ")
        assert is_qualifier_expression("a01239")
        assert is_qualifier_expression("1numeric")
        assert is_qualifier_expression("-")
        assert is_qualifier_expression("_")
        assert is_qualifier_expression("valid-with-$-inside")
        assert not is_qualifier_expression("invalid-with-?-char")
        assert not is_qualifier_expression("")

    def test_qualifier_is_version(self):
        assert qualifier_is_version("0")
        assert qualifier_is_version("42")
        assert not qualifier_is_version("$LATEST")
        assert not qualifier_is_version("a77")
        assert not qualifier_is_version("77a")

    def test_qualifier_is_alias(self):
        assert qualifier_is_alias("abczABCZ")
        assert qualifier_is_alias("a01239")
        assert not qualifier_is_alias("1numeric")
        assert not qualifier_is_alias("invalid-with-$-char")
        assert not qualifier_is_alias("invalid-with-?-char")
