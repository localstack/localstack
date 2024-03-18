import os
from contextlib import contextmanager
from typing import Any, Dict

import pytest

from localstack import constants
from localstack.utils.bootstrap import (
    Container,
    ContainerConfigurators,
    get_enabled_apis,
    get_gateway_port,
    get_preloaded_services,
)
from localstack.utils.container_utils.container_client import ContainerConfiguration, VolumeBind


@contextmanager
def temporary_env(env: Dict[str, Any]):
    old = os.environ.copy()
    try:
        os.environ.update(env)
        yield os.environ
    finally:
        os.environ.clear()
        os.environ.update(old)


class TestGetPreloadedServices:
    @pytest.fixture(autouse=True)
    def reset_get_preloaded_services(self):
        """
        Ensures that the cache is reset on get_preloaded_services.
        :return: get_preloaded_services method with reset fixture
        """
        get_preloaded_services.cache_clear()
        yield
        get_preloaded_services.cache_clear()

    def test_returns_default_service_ports(self):
        from localstack.services.plugins import SERVICE_PLUGINS

        with temporary_env({"EAGER_SERVICE_LOADING": "1"}):
            result = get_preloaded_services()

        assert result == set(SERVICE_PLUGINS.list_available())

    def test_with_service_subset(self):
        with temporary_env({"SERVICES": "s3,sns", "EAGER_SERVICE_LOADING": "1"}):
            result = get_preloaded_services()

        assert len(result) == 2
        assert "s3" in result
        assert "sns" in result

    def test_custom_service_without_port(self):
        with temporary_env({"SERVICES": "foobar", "EAGER_SERVICE_LOADING": "1"}):
            result = get_preloaded_services()

        assert len(result) == 1
        assert "foobar" in result

    def test_custom_port_mapping_in_services_env(self):
        with temporary_env({"SERVICES": "foobar:1235", "EAGER_SERVICE_LOADING": "1"}):
            result = get_preloaded_services()

        assert len(result) == 1
        assert "foobar" in result

    def test_resolve_meta(self):
        with temporary_env({"SERVICES": "es,cognito:1337", "EAGER_SERVICE_LOADING": "1"}):
            result = get_preloaded_services()

        assert len(result) == 4
        assert result == {
            # directly given
            "es",
            # a dependency of es
            "opensearch",
            # "cognito" is a composite for "cognito-idp" and "cognito-identity"
            "cognito-idp",
            "cognito-identity",
        }


class TestGetEnabledApis:
    @pytest.fixture(autouse=True)
    def reset_get_enabled_apis(self):
        """
        Ensures that the cache is reset on get_enabled_apis.
        :return: get_enabled_apis method with reset fixture
        """
        get_enabled_apis.cache_clear()
        yield
        get_enabled_apis.cache_clear()

    def test_returns_default_service_ports(self):
        from localstack.services.plugins import SERVICE_PLUGINS

        with temporary_env({"STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert result == set(SERVICE_PLUGINS.list_available())

    def test_strict_service_loading_disabled(self):
        from localstack.services.plugins import SERVICE_PLUGINS

        with temporary_env({"STRICT_SERVICE_LOADING": "0", "SERVICES": "s3,sqs"}):
            result = get_enabled_apis()

        assert result == set(SERVICE_PLUGINS.list_available())

    def test_strict_service_loading_enabled_by_default(self):
        with temporary_env({"SERVICES": "s3,sns"}):
            result = get_enabled_apis()

        assert len(result) == 2
        assert "s3" in result
        assert "sns" in result

    def test_with_service_subset(self):
        with temporary_env({"SERVICES": "s3,sns", "STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 2
        assert "s3" in result
        assert "sns" in result

    def test_custom_service_not_supported(self):
        with temporary_env({"SERVICES": "foobar", "STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert not result

    def test_custom_service_with_supported_service(self):
        with temporary_env({"SERVICES": "foobar,s3", "STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 1
        assert "s3" in result

    def test_custom_service_and_port_mapping_in_services_env_not_supported(self):
        with temporary_env({"SERVICES": "foobar:1235", "STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert not result

    def test_custom_port_mapping_with_supported_service(self):
        with temporary_env({"SERVICES": "s3:1234", "STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 1
        assert "s3" in result

    def test_resolve_meta(self):
        with temporary_env({"SERVICES": "es,lambda", "STRICT_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 5
        assert result == {
            # directly given
            "lambda",
            "es",
            # a dependency of es
            "opensearch",
            # lambda has internal dependencies on s3 and sts
            "s3",
            "sts",
        }


class TestGetGatewayPort:
    def test_fails_if_nothing_set(self):
        # error case
        with pytest.raises(ValueError):
            get_gateway_port(Container(ContainerConfiguration("")))

    def test_fails_if_not_exposed(self):
        # gateway_listen set but not exposed
        c = Container(ContainerConfiguration(""))
        c.config.env_vars["GATEWAY_LISTEN"] = ":4566"
        with pytest.raises(ValueError):
            get_gateway_port(Container(ContainerConfiguration("")))

    def test_default(self):
        # default case
        c = Container(ContainerConfiguration(""))
        c.config.ports.add(constants.DEFAULT_PORT_EDGE)
        assert get_gateway_port(c) == constants.DEFAULT_PORT_EDGE

    def test_single_mapping(self):
        # gateway_listen set and exposed to different port
        c = Container(ContainerConfiguration(""))
        c.config.env_vars["GATEWAY_LISTEN"] = ":4566"
        c.config.ports.add(5000, 4566)
        assert get_gateway_port(c) == 5000

    def test_in_port_range_mapping(self):
        # gateway_listen set and port range exposed
        c = Container(ContainerConfiguration(""))
        c.config.env_vars["GATEWAY_LISTEN"] = ":4566"
        c.config.ports.add([4000, 5000])
        assert get_gateway_port(c) == 4566

    def test_multiple_gateway_listen_ports_returns_first(self):
        # gateway_listen set to multiple values returns first case
        c = Container(ContainerConfiguration(""))
        c.config.env_vars["GATEWAY_LISTEN"] = ":5000,:443"
        c.config.ports.add(443)
        c.config.ports.add(5000)
        assert get_gateway_port(c) == 5000

    def test_multiple_gateway_listen_ports_only_one_exposed(self):
        # gateway_listen set to multiple values but first port not exposed
        c = Container(ContainerConfiguration(""))
        c.config.env_vars["GATEWAY_LISTEN"] = ":4566,:443"
        c.config.ports.add(443)
        assert get_gateway_port(c) == 443


class TestContainerConfigurators:
    def test_cli_params(self, monkeypatch):
        monkeypatch.setenv("BAR", "BAZ")

        c = ContainerConfiguration("localstack/localstack")
        ContainerConfigurators.cli_params(
            {
                "network": "my-network",
                "publish": ("4566", "5000:6000", "53:53/udp", "4510-4513:4610-4613"),
                "volume": ("foo:/tmp/foo", "/bar:/tmp/bar:ro"),
                "env": ("FOO=BAR", "BAR"),
            }
        )(c)

        assert c.network == "my-network"
        assert c.env_vars == {
            "FOO": "BAR",
            "BAR": "BAZ",
        }
        assert c.ports.to_dict() == {
            "4566/tcp": 4566,
            "4610/tcp": 4510,
            "4611/tcp": 4511,
            "4612/tcp": 4512,
            "4613/tcp": 4513,
            "53/udp": 53,
            "6000/tcp": 5000,
        }
        assert VolumeBind(host_dir="foo", container_dir="/tmp/foo", read_only=False) in c.volumes
        assert VolumeBind(host_dir="/bar", container_dir="/tmp/bar", read_only=True) in c.volumes
