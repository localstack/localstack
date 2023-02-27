from unittest.mock import MagicMock, patch

from localstack.aws.connect import ExternalClientFactory, InternalClientFactory


class TestClientFactory:
    def test_internal_client_dto_is_registered(self):
        factory = InternalClientFactory()
        factory._session = MagicMock()

        mock = factory("sns", "eu-central-1")
        mock.meta.events.register.assert_called()

    def test_external_client_dto_is_not_registered(self):
        factory = ExternalClientFactory()
        factory._session = MagicMock()

        mock = factory.get_client(
            "sqs", "eu-central-1", aws_access_key_id="foo", aws_secret_access_key="bar"
        )
        mock.meta.events.register.assert_not_called()

    @patch.object(ExternalClientFactory, "_get_client")
    def test_external_client_credentials_loaded_from_env_if_set_to_none(self, mock, monkeypatch):
        connect_to = ExternalClientFactory(use_ssl=True)
        connect_to.get_client(
            "abc", region_name="xx-south-1", aws_access_key_id="foo", aws_secret_access_key="bar"
        )
        mock.assert_called_once_with(
            service_name="abc",
            region_name="xx-south-1",
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id="foo",
            aws_secret_access_key="bar",
            aws_session_token=None,
            config=connect_to._config,
        )

        mock.reset_mock()
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "lorem")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ipsum")

        connect_to.get_client(
            "def", region_name=None, aws_secret_access_key=None, aws_access_key_id=None
        )
        mock.assert_called_once_with(
            service_name="def",
            region_name="us-east-1",
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            config=connect_to._config,
        )
