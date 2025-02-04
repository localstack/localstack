import textwrap

import pytest

from localstack import config
from localstack.config import HostAndPort, external_service_url, internal_service_url


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
    """We are deriving GATEWAY_LISTEN and LOCALSTACK_HOST from provided environment variables.

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
        ],
        [
            ###
            (None, None, [f"{ip()}:4566"], "localhost.localstack.cloud:4566"),
            ("1.1.1.1", None, ["1.1.1.1:4566"], "localhost.localstack.cloud:4566"),
            (":5555", None, [f"{ip()}:5555"], "localhost.localstack.cloud:5555"),
            ("1.1.1.1:5555", None, ["1.1.1.1:5555"], "localhost.localstack.cloud:5555"),
            ###
            (None, "foo.bar", [f"{ip()}:4566"], "foo.bar:4566"),
            ("1.1.1.1", "foo.bar", ["1.1.1.1:4566"], "foo.bar:4566"),
            (":5555", "foo.bar", [f"{ip()}:5555"], "foo.bar:5555"),
            ("1.1.1.1:5555", "foo.bar", ["1.1.1.1:5555"], "foo.bar:5555"),
            ###
            (None, ":7777", [f"{ip()}:4566"], "localhost.localstack.cloud:7777"),
            ("1.1.1.1", ":7777", ["1.1.1.1:4566"], "localhost.localstack.cloud:7777"),
            (":5555", ":7777", [f"{ip()}:5555"], "localhost.localstack.cloud:7777"),
            ("1.1.1.1:5555", ":7777", ["1.1.1.1:5555"], "localhost.localstack.cloud:7777"),
            ###
            (None, "foo.bar:7777", [f"{ip()}:4566"], "foo.bar:7777"),
            ("1.1.1.1", "foo.bar:7777", ["1.1.1.1:4566"], "foo.bar:7777"),
            (":5555", "foo.bar:7777", [f"{ip()}:5555"], "foo.bar:7777"),
            ("1.1.1.1:5555", "foo.bar:7777", ["1.1.1.1:5555"], "foo.bar:7777"),
        ],
    )
    def test_edge_configuration(
        self,
        gateway_listen: str | None,
        localstack_host: str | None,
        expected_gateway_listen: list[str],
        expected_localstack_host: str,
    ):
        environment = {}
        if gateway_listen is not None:
            environment["GATEWAY_LISTEN"] = gateway_listen
        if localstack_host is not None:
            environment["LOCALSTACK_HOST"] = localstack_host

        (
            actual_ls_host,
            actual_gateway_listen,
        ) = config.populate_edge_configuration(environment)

        assert actual_ls_host == expected_localstack_host
        assert actual_gateway_listen == expected_gateway_listen

    def test_gateway_listen_multiple_addresses(self):
        environment = {"GATEWAY_LISTEN": "0.0.0.0:9999,0.0.0.0:443"}
        (
            _,
            gateway_listen,
        ) = config.populate_edge_configuration(environment)

        assert gateway_listen == [
            HostAndPort(host="0.0.0.0", port=9999),
            HostAndPort(host="0.0.0.0", port=443),
        ]

    def test_legacy_variables_ignored_if_given(self):
        """Providing legacy variables removed in 3.0 should not affect the default configuration.
        This test can be removed around >3.1-4.0."""
        environment = {
            "EDGE_BIND_HOST": "192.168.0.1",
            "EDGE_PORT": "10101",
            "EDGE_PORT_HTTP": "20202",
        }
        (
            localstack_host,
            gateway_listen,
        ) = config.populate_edge_configuration(environment)

        assert localstack_host == "localhost.localstack.cloud:4566"
        assert gateway_listen == [
            HostAndPort(host=ip(), port=4566),
        ]


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

    def test_add_all_interfaces_value_ipv6(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("::", 42))
        ports.append(HostAndPort("::1", 42))

        assert ports == [
            HostAndPort("::", 42),
        ]

    def test_add_all_interfaces_value_mixed_ipv6_wins(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("0.0.0.0", 42))
        ports.append(HostAndPort("::", 42))
        ports.append(HostAndPort("127.0.0.1", 42))
        ports.append(HostAndPort("::1", 42))

        assert ports == [
            HostAndPort("::", 42),
        ]

    def test_add_all_interfaces_value_after(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("127.0.0.1", 42))
        ports.append(HostAndPort("0.0.0.0", 42))

        assert ports == [
            HostAndPort("0.0.0.0", 42),
        ]

    def test_add_all_interfaces_value_after_ipv6(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("::1", 42))
        ports.append(HostAndPort("::", 42))

        assert ports == [
            HostAndPort("::", 42),
        ]

    def test_add_all_interfaces_value_after_mixed_ipv6_wins(self):
        ports = config.UniqueHostAndPortList()
        ports.append(HostAndPort("::1", 42))
        ports.append(HostAndPort("127.0.0.1", 42))
        ports.append(HostAndPort("::", 42))
        ports.append(HostAndPort("0.0.0.0", 42))

        assert ports == [HostAndPort("::", 42)]

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

    def test_parsing_ipv6_with_port(self):
        h = config.HostAndPort.parse(
            "[5601:f95d:0:10:4978::2]:1000", default_host="", default_port=9876
        )
        assert h == HostAndPort(host="5601:f95d:0:10:4978::2", port=1000)

    def test_parsing_ipv6_with_default_port(self):
        h = config.HostAndPort.parse("[5601:f95d:0:10:4978::2]", default_host="", default_port=9876)
        assert h == HostAndPort(host="5601:f95d:0:10:4978::2", port=9876)

    def test_parsing_ipv6_all_interfaces_with_default_port(self):
        h = config.HostAndPort.parse("[::]", default_host="", default_port=9876)
        assert h == HostAndPort(host="::", port=9876)

    def test_parsing_ipv6_with_invalid_address(self):
        with pytest.raises(ValueError) as exc_info:
            config.HostAndPort.parse("[i-am-invalid]", default_host="", default_port=9876)

        assert "input looks like an IPv6 address" in str(exc_info)

    @pytest.mark.parametrize("port", [-1000, -1, 2**16, 100_000])
    def test_port_out_of_range(self, port):
        with pytest.raises(ValueError) as exc_info:
            config.HostAndPort.parse(
                f"localhost:{port}", default_host="localhost", default_port=1234
            )

        assert "port out of range" in str(exc_info)


class TestServiceUrlHelpers:
    @pytest.mark.parametrize(
        ["protocol", "subdomains", "host", "port", "expected_service_url"],
        [
            # Default
            (None, None, None, None, "http://localhost.localstack.cloud:4566"),
            # Customize each part with defaults
            ("https", None, None, None, "https://localhost.localstack.cloud:4566"),
            (None, "s3", None, None, "http://s3.localhost.localstack.cloud:4566"),
            (None, None, "localstack-container", None, "http://localstack-container:4566"),
            (None, None, None, 5555, "http://localhost.localstack.cloud:5555"),
            # Multiple subdomains
            (
                None,
                "abc123.execute-api.lambda",
                None,
                None,
                "http://abc123.execute-api.lambda.localhost.localstack.cloud:4566",
            ),
            # Customize everything
            (
                "https",
                "abc.execute-api",
                "localstack-container",
                5555,
                "https://abc.execute-api.localstack-container:5555",
            ),
        ],
    )
    def test_external_service_url(
        self,
        protocol: str | None,
        subdomains: str | None,
        host: str | None,
        port: int | None,
        expected_service_url: str,
    ):
        url = external_service_url(host=host, port=port, protocol=protocol, subdomains=subdomains)
        assert url == expected_service_url

    def test_internal_service_url(self):
        # defaults
        assert internal_service_url() == "http://localhost:4566"
        # subdomains
        assert (
            internal_service_url(subdomains="abc.execute-api")
            == "http://abc.execute-api.localhost:4566"
        )


class TestConfigProfiles:
    @pytest.fixture
    def profile_folder(self, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
        return tmp_path

    def test_multiple_profiles(self, profile_folder):
        profile_1_content = textwrap.dedent(
            """
        VAR1=test1
        VAR2=test2
        VAR3=test3
        """
        )
        profile_2_content = textwrap.dedent(
            """
        VAR4=test4
        """
        )
        profile_1 = profile_folder / "profile_1.env"
        profile_1.write_text(profile_1_content)
        profile_2 = profile_folder / "profile_2.env"
        profile_2.write_text(profile_2_content)

        environment = {}

        config.load_environment(profiles="profile_1,profile_2", env=environment)

        assert environment == {
            "VAR1": "test1",
            "VAR2": "test2",
            "VAR3": "test3",
            "VAR4": "test4",
        }

    def test_multiple_profiles_override_behavior(self, profile_folder):
        profile_1_content = textwrap.dedent(
            """
        VAR1=test1
        VAR2=test2
        VAR3=test3
        """
        )
        profile_2_content = textwrap.dedent(
            """
        VAR3=override3
        VAR4=test4
        """
        )
        profile_1 = profile_folder / "profile_1.env"
        profile_1.write_text(profile_1_content)
        profile_2 = profile_folder / "profile_2.env"
        profile_2.write_text(profile_2_content)

        environment = {"VAR1": "can't touch this"}

        config.load_environment(profiles="profile_1,profile_2", env=environment)

        assert environment == {
            "VAR1": "can't touch this",
            "VAR2": "test2",
            "VAR3": "override3",
            "VAR4": "test4",
        }
