from unittest import mock

import requests

from localstack.constants import VERSION
from localstack.http import Request
from localstack.services.generic_proxy import ProxyListener
from localstack.services.internal import CloudFormationUi, HealthResource, LocalstackResourceHandler
from localstack.services.plugins import ServiceManager, ServiceState
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
                body=b'{"features:initScripts": "initializing","features:persistence": "disabled"}',
            )
        )

        state = resource.on_get(Request("GET", "/", body=b"None"))

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
                body=b'{"features:initScripts": "initializing","features:persistence": "disabled"}',
            )
        )

        resource.on_put(Request("PUT", "/", body=b'{"features:initScripts": "initialized"}'))

        state = resource.on_get(Request("GET", "/", body=b"None"))

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


class TestCloudFormationUiResource:
    def test_get(self):
        resource = CloudFormationUi()
        response = resource.on_get(Request("GET", "/", body=b"None"))
        assert response.status == "200 OK"
        assert "</html>" in response.get_data(as_text=True), "deploy UI did not render HTML"
        assert "text/html" in response.headers.get("content-type", "")


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

    def test_fallthrough(self):
        class RaiseError(ProxyListener):
            def forward_request(self, method, path, data, headers):
                raise ValueError("this error is expected")

        with proxy_server([LocalstackResourceHandler(), RaiseError()]) as url:
            # the RaiseError handler is called since this is not a /_localstack resource
            response = requests.get(f"{url}/foobar")
            assert not response.ok
            assert response.status_code >= 500

            # internal paths are 404ed
            response = requests.get(f"{url}/_localstack/foobar")
            assert not response.ok
            assert response.status_code == 404
