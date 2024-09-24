from werkzeug.datastructures import Headers

from localstack import config
from localstack.aws.handlers import cors
from localstack.config import HostAndPort

# The default host depends on whether running in Docker (see config.py::default_ip) but that's good enough for testing:
default_gateway_listen = [HostAndPort(host="0.0.0.0", port=4566)]
default_gateway_listen_ext = [
    HostAndPort(host="0.0.0.0", port=4566),
    HostAndPort(host="0.0.0.0", port=443),
]


def test_allowed_cors_origins_different_ports_and_protocols(monkeypatch):
    # test allowed origins for default config (:4566)
    # GATEWAY_LISTEN binds each host-port configuration to both protocols (http and https)
    monkeypatch.setattr(config, "GATEWAY_LISTEN", default_gateway_listen)
    origins = cors._get_allowed_cors_origins()
    assert "http://localhost:4566" in origins
    assert "http://localhost.localstack.cloud:4566" in origins
    assert "http://localhost:433" not in origins
    assert "https://localhost.localstack.cloud:443" not in origins

    # test allowed origins for extended config (:4566,:443)
    monkeypatch.setattr(config, "GATEWAY_LISTEN", default_gateway_listen_ext)
    origins = cors._get_allowed_cors_origins()
    assert "http://localhost:4566" in origins
    assert "http://localhost:443" in origins
    assert "http://localhost.localstack.cloud:4566" in origins
    assert "https://localhost.localstack.cloud:443" in origins


def test_dynamic_allowed_cors_origins(monkeypatch):
    assert _origin_allowed("http://test.s3-website.localhost.localstack.cloud")
    assert _origin_allowed("https://test.s3-website.localhost.localstack.cloud")
    assert _origin_allowed("http://test.cloudfront.localhost.localstack.cloud")

    assert not _origin_allowed("https://test.appsync.localhost.localstack.cloud")
    assert not _origin_allowed("https://testcloudfront.localhost.localstack.cloud")
    assert not _origin_allowed("http://test.cloudfront.custom-domain.com")


def test_dynamic_allowed_cors_origins_different_ports(monkeypatch):
    # test dynamic allowed origins for default config (:4566)
    monkeypatch.setattr(config, "GATEWAY_LISTEN", default_gateway_listen)
    monkeypatch.setattr(cors, "_ALLOWED_INTERNAL_PORTS", cors._get_allowed_cors_ports())

    assert _origin_allowed("http://test.s3-website.localhost.localstack.cloud:4566")
    assert _origin_allowed("http://test.s3-website.localhost.localstack.cloud")
    assert _origin_allowed("https://test.s3-website.localhost.localstack.cloud:4566")
    assert _origin_allowed("https://test.s3-website.localhost.localstack.cloud")
    assert _origin_allowed("http://test.cloudfront.localhost.localstack.cloud")

    assert not _origin_allowed("https://test.cloudfront.localhost.localstack.cloud:443")
    assert not _origin_allowed("http://test.cloudfront.localhost.localstack.cloud:123")

    # test allowed origins for extended config (:4566,:443)
    monkeypatch.setattr(config, "GATEWAY_LISTEN", default_gateway_listen_ext)
    monkeypatch.setattr(cors, "_ALLOWED_INTERNAL_PORTS", cors._get_allowed_cors_ports())

    assert _origin_allowed("https://test.cloudfront.localhost.localstack.cloud:443")


def test_dynamic_allowed_cors_origins_different_domains(monkeypatch):
    # test dynamic allowed origins for default config (edge port 4566)
    monkeypatch.setattr(config, "GATEWAY_LISTEN", default_gateway_listen)
    monkeypatch.setattr(
        config,
        "LOCALSTACK_HOST",
        config.HostAndPort(host="my-custom-domain.com", port=config.GATEWAY_LISTEN[0].port),
    )

    monkeypatch.setattr(
        cors, "_ALLOWED_INTERNAL_DOMAINS", cors._get_allowed_cors_internal_domains()
    )

    assert _origin_allowed("http://test.cloudfront.my-custom-domain.com")
    assert _origin_allowed("http://test.s3-website.my-custom-domain.com:4566")

    assert not _origin_allowed("http://test.s3-website.my-wrong-domain.com")
    assert not _origin_allowed("http://test.s3-website.my-wrong-domain.com:4566")


def _origin_allowed(url) -> bool:
    headers = Headers({"Origin": url})
    return cors.CorsEnforcer.is_cors_origin_allowed(headers)
