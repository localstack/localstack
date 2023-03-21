from localstack import config
from localstack.utils.strings import short_uid
from localstack.utils.urls import HostDefinition, localstack_host


class TestSuccess:
    def test_all_defaults(self, monkeypatch):
        # do not set LOCALSTACK_HOST
        host_definition = localstack_host()

        assert host_definition == HostDefinition(
            host="localhost",
            port=4566,
        )

    def test_setting_hostname(self, monkeypatch):
        hostname = f"localstack-host-{short_uid()}"
        monkeypatch.setattr(config, "LOCALSTACK_HOST", hostname)

        host_definition = localstack_host()

        assert host_definition == HostDefinition(
            host=hostname,
            port=4566,
        )

    def test_setting_port(self, monkeypatch):
        port = 10101
        monkeypatch.setattr(config, "LOCALSTACK_HOST", f":{port}")
        host_definition = localstack_host()

        assert host_definition == HostDefinition(
            host="localhost.localstack.cloud",
            port=port,
        )

    def test_setting_both(self, monkeypatch):
        hostname = f"localstack_host-{short_uid()}"
        port = 10101
        monkeypatch.setattr(config, "LOCALSTACK_HOST", f"{hostname}:{port}")

        host_definition = localstack_host()

        assert host_definition == HostDefinition(
            host=hostname,
            port=port,
        )


class TestFailures:
    def test_invalid_port_integer(self, monkeypatch, caplog):
        port = "not a port"
        monkeypatch.setattr(config, "LOCALSTACK_HOST", f":{port}")

        host_definition = localstack_host()

        assert host_definition == HostDefinition(
            host="localhost.localstack.cloud",
            port=4566,
        )

        assert "invalid port specified" in caplog.messages[0]
