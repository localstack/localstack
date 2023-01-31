from unittest.mock import MagicMock, patch

from werkzeug.datastructures import Headers

from localstack.aws.connect import INTERNAL_REQUEST_PARAMS_HEADER, ConnectFactory, is_internal_call


class TestConnectFactory:
    def test_is_internal_call(self):
        assert is_internal_call(dict()) is False
        assert is_internal_call({INTERNAL_REQUEST_PARAMS_HEADER: "xyz"}) is True
        headers = Headers()
        headers["x-nonsense"] = "okay"
        assert is_internal_call(headers) is False
        headers[INTERNAL_REQUEST_PARAMS_HEADER] = "{}"
        assert is_internal_call(headers) is True

    def test_internal_client_dto_is_registered(self):
        connect_to = ConnectFactory()
        connect_to._session = MagicMock()

        mock = connect_to("sns", "eu-central-1")
        mock.meta.events.register.assert_called()

    @patch.object(ConnectFactory, "_get_client")
    def test_external_client_credentials_loaded_from_env_if_set_to_none(self, mock, monkeypatch):
        connect_to = ConnectFactory(use_ssl=True)
        connect_to.get_external_client(
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

        connect_to.get_external_client(
            "def", region_name=None, aws_secret_access_key=None, aws_access_key_id=None
        )
        mock.assert_called_once_with(
            service_name="def",
            region_name=connect_to.get_region_name(),
            use_ssl=True,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id="lorem",
            aws_secret_access_key="ipsum",
            aws_session_token=None,
            config=connect_to._config,
        )
