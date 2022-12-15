from localstack.services.awslambda.api_utils import (
    is_qualifier_expression,
    qualifier_is_alias,
    qualifier_is_version,
)


class TestApiUtils:
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
