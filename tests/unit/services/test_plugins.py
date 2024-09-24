import threading
from queue import Queue

from localstack.services.plugins import ServicePluginManager
from localstack.services.sqs.provider import SqsProvider


class TestServicePluginManager:
    def test_get_service_calls_init_hook_once(self, monkeypatch):
        manager = ServicePluginManager()

        calls_to_on_after_init = []

        def _on_after_init(_self):
            calls_to_on_after_init.append(_self)

        monkeypatch.setattr(SqsProvider, "on_after_init", _on_after_init)

        s1 = manager.get_service("sqs")
        s2 = manager.get_service("sqs")

        assert s1 is s2, "instantiated two different services"
        assert len(calls_to_on_after_init) == 1, "on_after_init should be called once"

    def test_concurrent_get_service_calls_init_hook_once(self, monkeypatch):
        manager = ServicePluginManager()

        calls_to_get_service = Queue()
        calls_to_on_after_init = []

        def _call_get_service():
            service = manager.get_service("sqs")
            calls_to_get_service.put(service)

        def _on_after_init(_self):
            calls_to_on_after_init.append(_self)

        monkeypatch.setattr(SqsProvider, "on_after_init", _on_after_init)

        threading.Thread(target=_call_get_service).start()
        threading.Thread(target=_call_get_service).start()

        s1 = calls_to_get_service.get()
        s2 = calls_to_get_service.get()

        assert s1 is s2, "instantiated two different services"
        assert len(calls_to_on_after_init) == 1, "on_after_init should be called once"

    def test_nested_concurrent_get_service_calls_init_hook_once(self, monkeypatch):
        manager = ServicePluginManager()

        calls_to_get_service = Queue()
        calls_to_on_after_init = []

        def _call_get_service():
            service = manager.get_service("sqs")
            calls_to_get_service.put(service)

        def _on_after_init(_self):
            calls_to_on_after_init.append(_self)
            threading.Thread(target=_call_get_service).start()

        monkeypatch.setattr(SqsProvider, "on_after_init", _on_after_init)

        threading.Thread(target=_call_get_service).start()

        s1 = calls_to_get_service.get()
        s2 = calls_to_get_service.get()

        assert s1 is s2, "instantiated two different services"
        assert len(calls_to_on_after_init) == 1, "on_after_init should be called once"
