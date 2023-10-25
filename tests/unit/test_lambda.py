from localstack.services.lambda_.api_utils import RUNTIMES
from localstack.services.lambda_.invocation.lambda_models import IMAGE_MAPPING


class TestLambda:
    def test_check_runtime(self):
        """
        Make sure that the list of runtimes to test at least contains all mapped runtime images.
        This is a test which ensures that runtimes considered for validation do not diverge from the supported runtimes.
        See #9020 for more details.
        """
        assert set(RUNTIMES) == set(IMAGE_MAPPING.keys())
