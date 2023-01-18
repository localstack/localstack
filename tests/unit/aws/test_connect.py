from unittest.mock import patch

from werkzeug.datastructures import Headers

from localstack.aws.connect import LOCALSTACK_DATA_HEADER, ConnectFactory, is_internal_call
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY


def test_is_internal_call():
    assert is_internal_call(dict()) is False
    assert is_internal_call({LOCALSTACK_DATA_HEADER: "xyz"}) is True
    headers = Headers()
    headers["x-nonsense"] = "okay"
    assert is_internal_call(headers) is False
    headers[LOCALSTACK_DATA_HEADER] = "{}"
    assert is_internal_call(headers) is True


@patch.object(ConnectFactory, "get_client")
def test_target_arn_overrides_region(mock):
    connect_to = ConnectFactory(
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID, aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY
    )
    connect_to("sns", source_service="s3", target_arn="arn:aws:sns:xx-south-1:000000000000:lorem")

    mock.assert_called_once_with(
        service_name="sns",
        region_name="xx-south-1",
        use_ssl=False,
        verify=False,
        endpoint_url="http://localhost:4566",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token=None,
        config=connect_to._config,
    )


@patch.object(ConnectFactory, "get_client")
def test_localstack_data_sent_only_when_certain_attribs_set(_):
    connect_to = ConnectFactory(
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID, aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY
    )

    mock = connect_to("s3")
    mock.meta.events.register.assert_not_called()

    mock = connect_to("s3", source_service="foo")
    mock.meta.events.register.assert_called_once()
