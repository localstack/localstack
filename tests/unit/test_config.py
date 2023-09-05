import pytest

from localstack import config
from localstack.config import HostAndPort


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

    def test_empty_provider_config_override(self, monkeypatch):
        default_value = "default_value"
        override_value = ""
        provider_config = config.ServiceProviderConfig(default_value=default_value)
        monkeypatch.setenv("PROVIDER_OVERRIDE_S3", override_value)
        monkeypatch.setenv("PROVIDER_OVERRIDE_LAMBDA", override_value)
        provider_config.load_from_environment()
        assert provider_config.get_provider("s3") == default_value
        assert provider_config.get_provider("lambda") == default_value

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


class TestEdgeVariablesDerivedCorrectly:
    """
    Post-v2 we are deriving

    * EDGE_PORT
    * EDGE_PORT_HTTP
    * EDGE_BIND_HOST

    from GATEWAY_LISTEN. We are also ensuring the configuration behaves
    well with LOCALSTACK_HOST, i.e. if LOCALSTACK_HOST is supplied and
    GATEWAY_LISTEN is not, then we should propagate LOCALSTACK_HOST configuration
    into GATEWAY_LISTEN.

    Implementation note: monkeypatching the config module is hard, and causes
    tests run after these ones to import the wrong config. Instead, we test the
    function that populates the configuration variables.
    """

    @pytest.fixture
    def default_ip(self):
        if config.is_in_docker:
            return "0.0.0.0"
        else:
            return "127.0.0.1"

    def test_defaults(self, default_ip):
        environment = {}
        (
            ls_host,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert ls_host == "localhost.localstack.cloud:4566"
        assert gateway_listen == [HostAndPort(host=default_ip, port=4566)]
        assert edge_port == 4566
        assert edge_port_http == 0
        assert edge_bind_host == default_ip

    def test_custom_hostname(self):
        environment = {"GATEWAY_LISTEN": "192.168.0.1"}
        (
            _,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert gateway_listen == [HostAndPort(host="192.168.0.1", port=4566)]
        assert edge_port == 4566
        assert edge_port_http == 0
        assert edge_bind_host == "192.168.0.1"

    def test_custom_port(self, default_ip):
        environment = {"GATEWAY_LISTEN": ":9999"}
        (
            _,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert gateway_listen == [HostAndPort(host=default_ip, port=9999)]
        assert edge_port == 9999
        assert edge_port_http == 0
        assert edge_bind_host == default_ip

    def test_custom_host_and_port(self):
        environment = {"GATEWAY_LISTEN": "192.168.0.1:9999"}
        (
            _,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert gateway_listen == [HostAndPort(host="192.168.0.1", port=9999)]
        assert edge_port == 9999
        assert edge_port_http == 0
        assert edge_bind_host == "192.168.0.1"

    def test_localstack_host_overrides_edge_variables(self, default_ip):
        environment = {"LOCALSTACK_HOST": "hostname:9999"}
        (
            ls_host,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert ls_host == HostAndPort(host="hostname", port=9999)
        assert gateway_listen == [HostAndPort(host=default_ip, port=9999)]
        assert edge_port == 9999
        assert edge_port_http == 0
        assert edge_bind_host == default_ip

    def test_localstack_host_no_port(self, default_ip):
        environment = {"LOCALSTACK_HOST": "foobar"}
        (
            ls_host,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert ls_host == HostAndPort(host="foobar", port=4566)
        assert gateway_listen == [HostAndPort(host=default_ip, port=4566)]
        assert edge_port == 4566
        assert edge_port_http == 0
        assert edge_bind_host == default_ip

    def test_gateway_listen_multiple_addresses(self):
        environment = {"GATEWAY_LISTEN": "0.0.0.0:9999,0.0.0.0:443"}
        (
            _,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert gateway_listen == [
            HostAndPort(host="0.0.0.0", port=9999),
            HostAndPort(host="0.0.0.0", port=443),
        ]
        # take the first value
        assert edge_port == 9999
        assert edge_port_http == 0
        assert edge_bind_host == "0.0.0.0"

    def test_legacy_variables_override_if_given(self, default_ip):
        environment = {
            "EDGE_BIND_HOST": "192.168.0.1",
            "EDGE_PORT": "10101",
            "EDGE_PORT_HTTP": "20202",
        }
        (
            _,
            gateway_listen,
            edge_bind_host,
            edge_port,
            edge_port_http,
        ) = config.populate_legacy_edge_configuration(environment)

        assert gateway_listen == [
            HostAndPort(host=default_ip, port=10101),
            HostAndPort(host=default_ip, port=20202),
        ]
        assert edge_bind_host == "192.168.0.1"
        assert edge_port == 10101
        assert edge_port_http == 20202


class TestHostAndPort:
    def test_parsing_hostname_and_ip(self):
        h = config.HostAndPort.parse("0.0.0.0:1000", default_host="", default_port=0)
        assert h == HostAndPort(host="0.0.0.0", port=1000)

    def test_parsing_with_default_host(self):
        h = config.HostAndPort.parse(":1000", default_host="192.168.0.1", default_port=0)
        assert h == HostAndPort(host="192.168.0.1", port=1000)

    def test_parsing_with_default_port(self):
        h = config.HostAndPort.parse("1.2.3.4", default_host="", default_port=9876)
        assert h == HostAndPort(host="1.2.3.4", port=9876)

    def test_parsing_with_empty_host(self):
        h = config.HostAndPort.parse(":4566", default_host="", default_port=9876)
        assert h == HostAndPort(host="", port=4566)

    def test_invalid_port(self):
        with pytest.raises(ValueError) as exc_info:
            config.HostAndPort.parse("0.0.0.0:not-a-port", default_host="127.0.0.1", default_port=0)

        assert "specified port not-a-port not a number" in str(exc_info)

    @pytest.mark.parametrize("port", [-1000, -1, 2**16, 100_000])
    def test_port_out_of_range(self, port):
        with pytest.raises(ValueError) as exc_info:
            config.HostAndPort.parse(
                f"localhost:{port}", default_host="localhost", default_port=1234
            )

        assert "port out of range" in str(exc_info)
