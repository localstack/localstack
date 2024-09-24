import pytest
from moto.core.base_backend import BackendDict, BaseBackend
from moto.sns import models as sns_models

from localstack.services.sqs import models as sqs_models
from localstack.state.inspect import ReflectionStateLocator, ServiceBackendCollectorVisitor


@pytest.fixture()
def sample_backend_dict() -> BackendDict:
    class SampleBackend(BaseBackend):
        def __init__(self, region_name, account_id):
            super().__init__(region_name, account_id)
            self.attributes = {}

    return BackendDict(SampleBackend, "sns")


class TestReflectionStateLocator:
    def test_collect_store(self, sample_stores, monkeypatch):
        """Ensures that the visitor can effectively collect store backend"""
        account = "696969696969"
        eu_region = "eu-central-1"

        store = sample_stores[account][eu_region]
        monkeypatch.setattr(sqs_models, "sqs_stores", sample_stores)

        visitor = ServiceBackendCollectorVisitor()
        state_manager = ReflectionStateLocator(service="sqs")
        state_manager.accept_state_visitor(visitor=visitor)
        backends = visitor.collect()

        store_backend = backends.get("localstack")
        assert store_backend

        oracle = {account: {eu_region: store}}
        assert store_backend == oracle

    def test_collect_backend_dict(self, sample_backend_dict, monkeypatch):
        """Ensures that the visitor can effectively collect backend dict backends"""

        account = "696969696969"
        eu_region = "eu-central-1"

        store = sample_backend_dict[account][eu_region]
        store.attributes = {"key": "value"}

        monkeypatch.setattr(sns_models, "sns_backends", sample_backend_dict)

        visitor = ServiceBackendCollectorVisitor()
        state_manager = ReflectionStateLocator(service="sns")
        state_manager.accept_state_visitor(visitor=visitor)
        backends = visitor.collect()

        store_backend = backends.get("moto")
        assert store_backend
        assert store_backend[account][eu_region] == store
