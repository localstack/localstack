import os
from contextlib import contextmanager
from typing import Any, Dict

import pytest

from localstack.utils.bootstrap import get_enabled_apis


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
