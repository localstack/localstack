from localstack import config
from localstack.aws.handlers.cors import _get_allowed_cors_origins


def test_allowed_cors_origins_different_ports_and_protocols(monkeypatch):
    # test allowed origins for default config (edge port 4566)
    monkeypatch.setattr(config, "EDGE_PORT", 4566)
    monkeypatch.setattr(config, "EDGE_PORT_HTTP", 0)
    origins = _get_allowed_cors_origins()
    assert "http://localhost:4566" in origins
    assert "http://localhost.localstack.cloud:4566" in origins
    assert "https://localhost.localstack.cloud:443" not in origins

    # test allowed origins for extended config (HTTPS edge port 443, HTTP edge port 4566)
    monkeypatch.setattr(config, "EDGE_PORT", 443)
    monkeypatch.setattr(config, "EDGE_PORT_HTTP", 4566)
    origins = _get_allowed_cors_origins()
    assert "http://localhost:4566" in origins
    assert "http://localhost.localstack.cloud:4566" in origins
    assert "https://localhost.localstack.cloud:443" in origins
