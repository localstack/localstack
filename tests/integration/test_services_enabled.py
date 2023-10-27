import pytest
from botocore.exceptions import ClientError

from localstack.utils.bootstrap import get_enabled_apis


class TestEnabledServices:
    @pytest.fixture(autouse=True)
    def reset_get_enabled_apis(self):
        """
        Ensures that the cache is reset on get_enabled_apis.
        :return: get_enabled_apis method with reset fixture
        """
        get_enabled_apis.cache_clear()
        yield
        get_enabled_apis.cache_clear()

    def test_enabled_services(self, monkeypatch, aws_client):
        monkeypatch.setenv("SERVICES", "s3,sqs")
        monkeypatch.setenv("STRICT_SERVICE_LOADING", "1")

        response = aws_client.s3.list_buckets()
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(ClientError) as e:
            aws_client.lambda_.list_functions()

        e.match("API action 'ListFunctions' for service 'lambda' not yet implemented")
