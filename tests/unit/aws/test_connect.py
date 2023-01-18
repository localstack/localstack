from unittest.mock import patch

import pytest
from werkzeug.datastructures import Headers

from localstack.aws.connect import LOCALSTACK_DATA_HEADER, ConnectFactory, is_internal_call
from localstack.constants import INTERNAL_AWS_ACCESS_KEY_ID, INTERNAL_AWS_SECRET_ACCESS_KEY


class TestConnectFactory:
    def test_is_internal_call(self):
        assert is_internal_call(dict()) is False
        assert is_internal_call({LOCALSTACK_DATA_HEADER: "xyz"}) is True
        headers = Headers()
        headers["x-nonsense"] = "okay"
        assert is_internal_call(headers) is False
        headers[LOCALSTACK_DATA_HEADER] = "{}"
        assert is_internal_call(headers) is True

    @patch.object(ConnectFactory, "get_client")
    def test_internal_client_target_arn_region_is_used(self, mock):
        connect_to = ConnectFactory()
        connect_to(
            "sns", source_service="s3", target_arn="arn:aws:sns:xx-south-1:000000000000:lorem"
        )

        mock.assert_called_once_with(
            service_name="sns",
            region_name="xx-south-1",
            use_ssl=False,
            verify=False,
            endpoint_url="http://localhost:4566",
            aws_access_key_id=INTERNAL_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            aws_session_token=None,
            config=connect_to._config,
        )

        with pytest.raises(AssertionError) as exc:
            connect_to("sns", source_service="s3")
        exc.match("Region not set")

    @patch.object(ConnectFactory, "get_client")
    def test_internal_client_dto_is_registered(self, _):
        connect_to = ConnectFactory()

        mock = connect_to(
            "sns", source_service="s3", target_arn="arn:aws:sns:xx-south-1:000000000000:lorem"
        )
        mock.meta.events.register.assert_called_once()

    @patch.object(ConnectFactory, "get_client")
    def test_external_client_credentials_loaded_from_env_if_set_to_none(self, mock, monkeypatch):
        connect_to = ConnectFactory(use_ssl=True)
        connect_to.get_client_for_external(
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

        connect_to.get_client_for_external(
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
