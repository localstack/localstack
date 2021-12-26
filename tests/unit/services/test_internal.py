from unittest import mock

import requests

from localstack.constants import VERSION
from localstack.services.internal import HealthResource, LocalstackResourceHandler
from localstack.services.plugins import ServiceManager, ServiceState
from localstack.services.routing import Request
from localstack.utils.testutil import proxy_server


class TestHealthResource:
    def test_put_and_get(self):
        service_manager = ServiceManager()
        service_manager.get_states = mock.MagicMock(return_value={"foo": ServiceState.AVAILABLE})

        resource = HealthResource(service_manager)

        resource.on_put(
            Request(
                "PUT",
                "/",
                b'{"features:initScripts": "initializing","features:persistence": "disabled"}',
                {},
            )
        )

        state = resource.on_get(Request("GET", "/", b"None", {}))

        assert state == {
            "features": {
                "initScripts": "initializing",
                "persistence": "disabled",
            },
            "services": {
                "foo": "available",
            },
            "version": VERSION,
        }

    def test_put_overwrite_and_get(self):
        service_manager = ServiceManager()
        service_manager.get_states = mock.MagicMock(return_value={"foo": ServiceState.AVAILABLE})

        resource = HealthResource(service_manager)

        resource.on_put(
            Request(
                "PUT",
                "/",
                b'{"features:initScripts": "initializing","features:persistence": "disabled"}',
                {},
            )
        )

        resource.on_put(Request("PUT", "/", b'{"features:initScripts": "initialized"}', {}))

        state = resource.on_get(Request("GET", "/", b"None", {}))

        assert state == {
            "features": {
                "initScripts": "initialized",
                "persistence": "disabled",
            },
            "services": {
                "foo": "available",
            },
            "version": VERSION,
        }


class TestLocalstackResourceHandlerIntegration:
    def test_health(self, monkeypatch):
        with proxy_server(LocalstackResourceHandler()) as url:
            # legacy endpoint
            response = requests.get(f"{url}/health")
            assert response.ok
            assert "services" in response.json()

            # new internal endpoint
            response = requests.get(f"{url}/_localstack/health")
            assert response.ok
            assert "services" in response.json()

    def test_cloudformation_ui(self):
        with proxy_server(LocalstackResourceHandler()) as url:
            # make sure it renders
            response = requests.get(f"{url}/_localstack/cloudformation/deploy")
            assert response.ok
            assert "</html>" in response.text, "deploy UI did not render HTML"

    def test_fallthrough(self):
        with proxy_server(LocalstackResourceHandler()) as url:
            # some other error is thrown by the proxy if there are no more listeners
            response = requests.get(f"{url}/foobar")
            assert not response.ok
            assert not response.status_code == 404

            # internal paths are 404ed
            response = requests.get(f"{url}/_localstack/foobar")
            assert not response.ok
            assert response.status_code == 404
