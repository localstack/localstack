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


def ip() -> str:
    if config.is_in_docker:
        return "0.0.0.0"
    else:
        return "127.0.0.1"


class TestEdgeVariablesDerivedCorrectly:
    """
    Post-v2 we are deriving

    * EDGE_PORT

    from GATEWAY_LISTEN. We are also ensuring the configuration behaves
    well with LOCALSTACK_HOST, i.e. if LOCALSTACK_HOST is supplied and
    GATEWAY_LISTEN is not, then we should propagate LOCALSTACK_HOST configuration
    into GATEWAY_LISTEN.

    Implementation note: monkeypatching the config module is hard, and causes
    tests run after these ones to import the wrong config. Instead, we test the
    function that populates the configuration variables.
    """

    # This parameterised test forms a table of scenarios we need to cover. Each
    # input variable (gateway_listen, localstack_host) has four unique
    # combinations of inputs:
    # * default
    # * host only
    # * ip only
    # * host and ip
    # and there are two variables so 16 total tests
    @pytest.mark.parametrize(
        [
            "gateway_listen",
            "localstack_host",
            "expected_gateway_listen",
            "expected_localstack_host",
            "expected_edge_port",
        ],
        [
            ###
            (None, None, [f"{ip()}:4566"], "localhost.localstack.cloud:4566", 4566),
            ("1.1.1.1", None, ["1.1.1.1:4566"], "localhost.localstack.cloud:4566", 4566),
            (":5555", None, [f"{ip()}:5555"], "localhost.localstack.cloud:5555", 5555),
            ("1.1.1.1:5555", None, ["1.1.1.1:5555"], "localhost.localstack.cloud:5555", 5555),
            ###
            (None, "foo.bar", [f"{ip()}:4566"], "foo.bar:4566", 4566),
            ("1.1.1.1", "foo.bar", ["1.1.1.1:4566"], "foo.bar:4566", 4566),
            (":5555", "foo.bar", [f"{ip()}:5555"], "foo.bar:5555", 5555),
            ("1.1.1.1:5555", "foo.bar", ["1.1.1.1:5555"], "foo.bar:5555", 5555),
            ###
            (None, ":7777", [f"{ip()}:4566"], "localhost.localstack.cloud:7777", 4566),
            ("1.1.1.1", ":7777", ["1.1.1.1:4566"], "localhost.localstack.cloud:7777", 4566),
            (":5555", ":7777", [f"{ip()}:5555"], "localhost.localstack.cloud:7777", 5555),
            ("1.1.1.1:5555", ":7777", ["1.1.1.1:5555"], "localhost.localstack.cloud:7777", 5555),
            ###
            (None, "foo.bar:7777", [f"{ip()}:4566"], "foo.bar:7777", 4566),
            ("1.1.1.1", "foo.bar:7777", ["1.1.1.1:4566"], "foo.bar:7777", 4566),
            (":5555", "foo.bar:7777", [f"{ip()}:5555"], "foo.bar:7777", 5555),
            ("1.1.1.1:5555", "foo.bar:7777", ["1.1.1.1:5555"], "foo.bar:7777", 5555),
        ],
    )
    def test_edge_configuration(
        self,
        gateway_listen: str | None,
        localstack_host: str | None,
        expected_gateway_listen: list[str],
        expected_localstack_host: str,
        expected_edge_port: int,
    ):
        environment = {}
        if gateway_listen is not None:
            environment["GATEWAY_LISTEN"] = gateway_listen
        if localstack_host is not None:
            environment["LOCALSTACK_HOST"] = localstack_host

        (
            actual_ls_host,
            actual_gateway_listen,
            actual_edge_port,
        ) = config.populate_edge_configuration(environment)

        assert actual_ls_host == expected_localstack_host
        assert actual_gateway_listen == expected_gateway_listen
        assert actual_edge_port == expected_edge_port

    def test_gateway_listen_multiple_addresses(self):
        environment = {"GATEWAY_LISTEN": "0.0.0.0:9999,0.0.0.0:443"}
        (
            _,
            gateway_listen,
            edge_port,
        ) = config.populate_edge_configuration(environment)

        assert gateway_listen == [
            HostAndPort(host="0.0.0.0", port=9999),
            HostAndPort(host="0.0.0.0", port=443),
        ]
        # take the first value
        assert edge_port == 9999

    def test_legacy_variables_ignored_if_given(self):
        """Providing legacy variables removed in 3.0 should not affect the default configuration"""
        environment = {
            "EDGE_BIND_HOST": "192.168.0.1",
            "EDGE_PORT": "10101",
            "EDGE_PORT_HTTP": "20202",
        }
        (
            localstack_host,
            gateway_listen,
            edge_port,
        ) = config.populate_edge_configuration(environment)

        assert localstack_host == "localhost.localstack.cloud:4566"
        assert gateway_listen == [
            HostAndPort(host=ip(), port=4566),
        ]
        assert edge_port == 4566


class TestUniquePortList:
    def test_construction(self):
        ports = config.UniqueHostAndPortList(
            [
                HostAndPort("127.0.0.1", 53),
                HostAndPort("127.0.0.1", 53),
            ]
        )
        assert ports == [
            HostAndPort("127.0.0.1", 53),
        ]

    def test_add_separate_values(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("127.0.0.1", 42))
        ports.append(HostAndPort("127.0.0.1", 43))

        assert ports == [HostAndPort("127.0.0.1", 42), HostAndPort("127.0.0.1", 43)]

    def test_add_same_value(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("127.0.0.1", 42))
        ports.append(HostAndPort("127.0.0.1", 42))

        assert ports == [
            HostAndPort("127.0.0.1", 42),
        ]

    def test_add_all_interfaces_value(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("0.0.0.0", 42))
        ports.append(HostAndPort("127.0.0.1", 42))

        assert ports == [
            HostAndPort("0.0.0.0", 42),
        ]

    def test_add_all_interfaces_value_after(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("127.0.0.1", 42))
        ports.append(HostAndPort("0.0.0.0", 42))

        assert ports == [
            HostAndPort("0.0.0.0", 42),
        ]

    def test_index_access(self):
        ports = config.UniqueHostAndPortList(
            [
                HostAndPort("0.0.0.0", 42),
            ]
        )

        assert ports[0] == HostAndPort("0.0.0.0", 42)
        with pytest.raises(IndexError):
            _ = ports[10]

    def test_iteration(self):
        ports = config.UniqueHostAndPortList(
            [
                HostAndPort("127.0.0.1", 42),
                HostAndPort("127.0.0.1", 43),
            ]
        )
        n = 0
        for _ in ports:
            n += 1

        assert n == len(ports) == 2


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
