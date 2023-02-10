from localstack.services.stores import BaseStore
from tests.store_police import StorePolice


class TestStorePolice:
    def test_store_police(self, sns_create_topic):
        store_police = StorePolice("sns")
        sns_create_topic()
        check = store_police.control()
        assert check.ok

    def test_store_police_failing(self, monkeypatch):
        class SampleStore(BaseStore):
            # store with unpickable state
            def __init__(self):
                def _gen():
                    for _i in range(10):
                        yield _i

                self.attribute = _gen()

        def _yield_fake_generator(*args):
            yield "localstack", SampleStore()

        try:
            store_police = StorePolice("fake")
            monkeypatch.setattr(StorePolice, "yield_backends", _yield_fake_generator)

            check = store_police.control()

            assert not check.ok
            assert check.why
        finally:
            monkeypatch.undo()
