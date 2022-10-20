import pytest

from localstack.aws.accounts import get_default_account_id
from localstack.testing.pytest.fixtures import _client


@pytest.fixture
def client_factory():
    region_name = "eu-central-1"

    def _client_factory(service: str, aws_access_key_id: str):
        return _client(service, region_name=region_name, aws_access_key_id=aws_access_key_id)

    yield _client_factory


class TestMultiAccounts:
    def test_arbitrary_account_id_is_ignored_on_community(self, client_factory):
        sts_client = client_factory("sts", aws_access_key_id="112233445566")
        response = sts_client.get_caller_identity()
        assert response["Account"] == get_default_account_id()

    def test_invalid_access_key_id_fallback_to_default_account_id(self, client_factory):
        sts_client = client_factory("sts", aws_access_key_id="?=@#XYZ$%^&123")
        response = sts_client.get_caller_identity()
        assert response["Account"] == get_default_account_id()
