from localstack.services.lambda_.api_utils import (
    is_qualifier_expression,
    qualifier_is_alias,
    qualifier_is_version,
)
from localstack.services.lambda_.runtimes import (
    ALL_RUNTIMES,
    IMAGE_MAPPING,
    MISSING_RUNTIMES,
    SUPPORTED_RUNTIMES,
    TESTED_RUNTIMES,
    VALID_LAYER_RUNTIMES,
    VALID_RUNTIMES,
)


class TestApiUtils:
    def test_check_runtime(self):
        """
        Ensure that we keep the runtime lists consistent. The supported runtimes through image mappings
        should not diverge from the API-validated inputs nor the tested runtimes.
        """
        # Ensure that we have image mappings for all runtimes used in LocalStack (motivated by #9020)
        assert set(ALL_RUNTIMES) == set(IMAGE_MAPPING.keys())

        # Ensure that we test all supported runtimes
        assert set(SUPPORTED_RUNTIMES) == set(
            TESTED_RUNTIMES
        ), "mismatch between supported and tested runtimes"

        # Ensure that valid runtimes (i.e., API-level validation) match the actually supported runtimes
        # HINT: Update your botocore version if this check fails
        valid_runtimes = VALID_RUNTIMES[1:-1].split(", ")
        assert set(SUPPORTED_RUNTIMES).union(MISSING_RUNTIMES) == set(
            valid_runtimes
        ), "mismatch between supported and API-valid runtimes"

        # Ensure that valid layer runtimes (includes some extra runtimes) contain the actually supported runtimes
        valid_layer_runtimes = VALID_LAYER_RUNTIMES[1:-1].split(", ")
        assert set(ALL_RUNTIMES).issubset(
            set(valid_layer_runtimes)
        ), "supported runtimes not part of compatible runtimes for layers"

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
        assert qualifier_is_alias("1numeric")
        assert qualifier_is_alias("2024-01-01")
        assert not qualifier_is_alias("20240101")
        assert not qualifier_is_alias("invalid-with-$-char")
        assert not qualifier_is_alias("invalid-with-?-char")
