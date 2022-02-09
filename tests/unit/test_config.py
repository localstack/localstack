import os
from contextlib import contextmanager
from typing import Any, Dict

from localstack import config


@contextmanager
def temporary_env(env: Dict[str, Any]):
    old = os.environ.copy()
    try:
        os.environ.update(env)
        yield os.environ
    finally:
        os.environ.clear()
        os.environ.update(old)


class TestProviderConfig:
    def test_provider_default_value(self):
        default_value = "default_value"
        override_value = "override_value"
        provider_config = config.ServiceProviderConfig(default_value=default_value)
        assert provider_config.get_provider("ec2") == default_value
        provider_config.set_provider("ec2", override_value)
        assert provider_config.get_provider("ec2") == override_value

    def test_provider_set_if_not_exists(self):
        default_value = "default_value"
        override_value = "override_value"
        provider_config = config.ServiceProviderConfig(default_value=default_value)
        provider_config.set_provider("ec2", default_value)
        provider_config.set_provider_if_not_exists("ec2", override_value)
        assert provider_config.get_provider("ec2") == default_value

    def test_provider_config_overrides(self, monkeypatch):
        default_value = "default_value"
        override_value = "override_value"
        provider_config = config.ServiceProviderConfig(default_value=default_value)
        monkeypatch.setenv("PROVIDER_OVERRIDE_EC2", override_value)
        provider_config.load_from_environment()
        assert provider_config.get_provider("ec2") == override_value
        assert provider_config.get_provider("sqs") == default_value
        monkeypatch.setenv("PROVIDER_OVERRIDE_SQS", override_value)
        provider_config.load_from_environment()
        assert provider_config.get_provider("sqs") == override_value

    def test_bulk_set_if_not_exists(self):
        default_value = "default_value"
        custom_value = "custom_value"
        override_value = "override_value"
        override_services = ["sqs", "sns", "lambda", "ec2"]
        provider_config = config.ServiceProviderConfig(default_value=default_value)
        provider_config.set_provider("ec2", default_value)
        provider_config.set_provider("lambda", custom_value)
        provider_config.bulk_set_provider_if_not_exists(override_services, override_value)
        assert provider_config.get_provider("sqs") == override_value
        assert provider_config.get_provider("sns") == override_value
        assert provider_config.get_provider("lambda") == custom_value
        assert provider_config.get_provider("ec2") == default_value
        assert provider_config.get_provider("kinesis") == default_value


class TestParseServicePorts:
    def test_returns_default_service_ports(self):
        result = config.parse_service_ports()
        assert result == config.DEFAULT_SERVICE_PORTS

    def test_with_service_subset(self):
        with temporary_env({"SERVICES": "s3,sqs"}):
            result = config.parse_service_ports()

        assert len(result) == 2
        assert "s3" in result
        assert "sqs" in result
        assert result["s3"] == 4566
        assert result["sqs"] == 4566

    def test_custom_service_default_port(self):
        with temporary_env({"SERVICES": "foobar"}):
            result = config.parse_service_ports()

        assert len(result) == 1
        assert "foobar" not in config.DEFAULT_SERVICE_PORTS
        assert "foobar" in result
        # foobar is not a default service so it is assigned 0
        assert result["foobar"] == 0

    def test_custom_port_mapping(self):
        with temporary_env({"SERVICES": "foobar", "FOOBAR_PORT": "1234"}):
            result = config.parse_service_ports()

        assert len(result) == 1
        assert "foobar" not in config.DEFAULT_SERVICE_PORTS
        assert "foobar" in result
        assert result["foobar"] == 1234

    def test_custom_illegal_port_mapping(self):
        with temporary_env({"SERVICES": "foobar", "FOOBAR_PORT": "asdf"}):
            result = config.parse_service_ports()

        assert len(result) == 1
        assert "foobar" not in config.DEFAULT_SERVICE_PORTS
        assert "foobar" in result
        # FOOBAR_PORT cannot be parsed
        assert result["foobar"] == 0

    def test_custom_port_mapping_in_services_env(self):
        with temporary_env({"SERVICES": "foobar:1235"}):
            result = config.parse_service_ports()

        assert len(result) == 1
        assert "foobar" not in config.DEFAULT_SERVICE_PORTS
        assert "foobar" in result
        # FOOBAR_PORT cannot be parsed
        assert result["foobar"] == 1235
