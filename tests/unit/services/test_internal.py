from unittest import mock

from localstack.constants import VERSION
from localstack.http import Request
from localstack.services.internal import HealthResource
from localstack.services.plugins import ServiceManager, ServiceState


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
        # edition may return a different value depending on how the tests are run
        state.pop("edition", None)

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
        state.pop("edition", None)

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
