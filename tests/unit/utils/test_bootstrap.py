import os
from contextlib import contextmanager
from typing import Any, Dict

import pytest

from localstack import constants
from localstack.utils.bootstrap import Container, get_enabled_apis, get_gateway_port
from localstack.utils.container_utils.container_client import ContainerConfiguration


@contextmanager
def temporary_env(env: Dict[str, Any]):
    old = os.environ.copy()
    try:
        os.environ.update(env)
        yield os.environ
    finally:
        os.environ.clear()
        os.environ.update(old)


class TestGetEnabledServices:
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

        result = get_enabled_apis()
        assert result == set(SERVICE_PLUGINS.list_available())

    def test_with_service_subset(self):
        with temporary_env({"SERVICES": "s3,sqs", "EAGER_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 2
        assert "s3" in result
        assert "sqs" in result

    def test_custom_service_without_port(self):
        with temporary_env({"SERVICES": "foobar", "EAGER_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 1
        assert "foobar" in result

    def test_custom_port_mapping_in_services_env(self):
        with temporary_env({"SERVICES": "foobar:1235", "EAGER_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

        assert len(result) == 1
        assert "foobar" in result

    def test_resolve_meta(self):
        with temporary_env({"SERVICES": "es,cognito:1337", "EAGER_SERVICE_LOADING": "1"}):
            result = get_enabled_apis()

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
