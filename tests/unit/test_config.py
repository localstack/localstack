import string

import pytest
from hypothesis import given
from hypothesis.strategies import integers, sampled_from, text

from localstack import config

HOSTNAME_CHARACTERS = string.ascii_letters + string.digits + "-" + "."
SAMPLER = sampled_from(HOSTNAME_CHARACTERS)


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
        assert gateway_listen == f"{default_ip}:4566"
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

        assert gateway_listen == "192.168.0.1:4566"
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

        assert gateway_listen == f"{default_ip}:9999"
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

        assert gateway_listen == "192.168.0.1:9999"
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

        assert ls_host == "hostname:9999"
        assert gateway_listen == f"{default_ip}:9999"
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

        assert ls_host == "foobar:4566"
        assert gateway_listen == f"{default_ip}:4566"
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

        assert gateway_listen == "0.0.0.0:9999,0.0.0.0:443"
        # take the first value
        assert edge_port == 9999
        assert edge_port_http == 0
        assert edge_bind_host == "0.0.0.0"

    @pytest.mark.parametrize(
        "input,hosts_and_ports",
        [
            ("0.0.0.0:9999", [("0.0.0.0", 9999)]),
            (
                "0.0.0.0:9999,127.0.0.1:443",
                [
                    ("0.0.0.0", 9999),
                    ("127.0.0.1", 443),
                ],
            ),
            (
                "0.0.0.0:9999,127.0.0.1:443",
                [
                    ("0.0.0.0", 9999),
                    ("127.0.0.1", 443),
                ],
            ),
        ],
    )
    def test_gateway_listen_parsed(self, input, hosts_and_ports):
        res = config.get_gateway_listen(input)

        expected = [config.HostAndPort(host=host, port=port) for (host, port) in hosts_and_ports]
        assert res == expected

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

        assert gateway_listen == f"{default_ip}:4566"
        assert edge_bind_host == "192.168.0.1"
        assert edge_port == 10101
        assert edge_port_http == 20202

    # generate random hostnames and ports from within the following criteria:
    # - hostnames: a-zA-Z0-9-.
    # - ports: 0-65535
    @given(text(alphabet=SAMPLER, min_size=1), integers(min_value=0, max_value=2**16 - 1))
    def test_parsing_hostname_and_ip(self, hostname, port):
        """
        Use property-based testing to ensure that "well-behaved" input parses correctly
        """
        h = config.HostAndPort.parse(f"{hostname}:{port}")
        assert h.host == hostname
        assert h.port == port

    # test edge cases
    def test_empty_hostname(self):
        with pytest.raises(ValueError) as exc_info:
            config.HostAndPort.parse(f":{1000}")

        assert "could not parse hostname" in str(exc_info)

    @pytest.mark.parametrize("port", [-1000, 100_000])
    def test_negative_port(self, port):
        with pytest.raises(ValueError) as exc_info:
            config.HostAndPort.parse(f"localhost:{port}")

        assert "port out of range" in str(exc_info)
