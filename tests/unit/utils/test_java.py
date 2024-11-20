from unittest.mock import MagicMock

from localstack import config
from localstack.utils import java


def test_java_system_properties_proxy(monkeypatch):
    # Ensure various combinations of env config options are properly converted into expected sys props

    monkeypatch.setattr(config, "OUTBOUND_HTTP_PROXY", "http://lorem.com:69")
    monkeypatch.setattr(config, "OUTBOUND_HTTPS_PROXY", "")
    output = java.java_system_properties_proxy()
    assert len(output) == 2
    assert output["http.proxyHost"] == "lorem.com"
    assert output["http.proxyPort"] == "69"

    monkeypatch.setattr(config, "OUTBOUND_HTTP_PROXY", "")
    monkeypatch.setattr(config, "OUTBOUND_HTTPS_PROXY", "http://ipsum.com")
    output = java.java_system_properties_proxy()
    assert len(output) == 2
    assert output["https.proxyHost"] == "ipsum.com"
    assert output["https.proxyPort"] == "443"

    # Ensure no explicit port defaults to 80
    monkeypatch.setattr(config, "OUTBOUND_HTTP_PROXY", "http://baz.com")
    monkeypatch.setattr(config, "OUTBOUND_HTTPS_PROXY", "http://qux.com:42")
    output = java.java_system_properties_proxy()
    assert len(output) == 4
    assert output["http.proxyHost"] == "baz.com"
    assert output["http.proxyPort"] == "80"
    assert output["https.proxyHost"] == "qux.com"
    assert output["https.proxyPort"] == "42"


def test_java_system_properties_ssl(monkeypatch):
    mock = MagicMock()
    mock.return_value = "/baz/qux"
    monkeypatch.setattr(java, "build_trust_store", mock)

    # Ensure that no sys props are returned if CA bundle is not set
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)

    output = java.java_system_properties_ssl("/path/keytool", {"enable_this": "true"})
    assert output == {}
    mock.assert_not_called()

    # Ensure that expected sys props are returned when CA bundle is set
    mock.reset_mock()
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/foo/bar")

    output = java.java_system_properties_ssl("/path/to/keytool", {"disable_this": "true"})
    assert len(output) == 3
    assert output["javax.net.ssl.trustStore"] == "/baz/qux"
    assert output["javax.net.ssl.trustStorePassword"] == "localstack"
    assert output["javax.net.ssl.trustStoreType"] == "jks"
    mock.assert_called_with("/path/to/keytool", "/foo/bar", {"disable_this": "true"}, "localstack")


def test_system_properties_to_cli_args():
    assert java.system_properties_to_cli_args({}) == []
    assert java.system_properties_to_cli_args({"foo": "bar"}) == ["-Dfoo=bar"]
    assert java.system_properties_to_cli_args({"foo": "bar", "baz": "qux"}) == [
        "-Dfoo=bar",
        "-Dbaz=qux",
    ]
