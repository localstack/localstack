import pytest

from localstack import config
from localstack.services.generic_proxy import get_cert_pem_file_path


def test_custom_ssl_cert_path_is_used(monkeypatch):
    monkeypatch.setattr(config, "CUSTOM_SSL_CERT_PATH", "/custom/path/server.cert.pem")
    assert get_cert_pem_file_path() == "/custom/path/server.cert.pem"


@pytest.mark.parametrize(
    "custom_ssl_cert_path_config",
    [None, ""],
)
def test_custom_ssl_cert_path_not_used_if_not_set(monkeypatch, custom_ssl_cert_path_config):
    monkeypatch.setattr(config, "CUSTOM_SSL_CERT_PATH", custom_ssl_cert_path_config)
    # the cache folder can differ for different environments, we only check the suffix
    assert get_cert_pem_file_path().endswith("/cache/server.test.pem")
