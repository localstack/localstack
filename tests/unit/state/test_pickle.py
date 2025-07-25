import sys
from queue import PriorityQueue

import pytest

from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute
from localstack.state import pickle
from localstack.state.json import JsonDecoder, JsonEncoder
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME


def test_pickle_priority_queue(patch_default_encoder):
    obj = PriorityQueue()
    obj.put(2)
    obj.put(1)
    obj.put(3)

    obj = pickle.loads(pickle.dumps(obj))

    assert obj.get_nowait() == 1
    assert obj.get_nowait() == 2
    assert obj.get_nowait() == 3


class ClassWithGenerator:
    n: int

    def __init__(self, n: int):
        self.n = n
        self.gen = self._count()

    def _count(self):
        for i in range(self.n):
            yield i


class SubclassWithGenerator(ClassWithGenerator):
    pass


def test_pickle_generators_doesnt_work():
    with pytest.raises(TypeError):
        pickle.dumps(ClassWithGenerator(0))


def test_reducer():
    @pickle.reducer(ClassWithGenerator)
    def reduce(obj: ClassWithGenerator):
        return (obj.n,)

    cwg = pickle.loads(pickle.dumps(ClassWithGenerator(2)))
    assert next(cwg.gen) == 0
    assert next(cwg.gen) == 1

    with pytest.raises(TypeError):
        pickle.dumps(SubclassWithGenerator(0))

    pickle.remove_dispatch_entry(ClassWithGenerator)

    with pytest.raises(TypeError):
        pickle.dumps(ClassWithGenerator(0))


def test_remove_dispatch_entry_on_non_existing_entry_does_noting():
    pickle.remove_dispatch_entry(ClassWithGenerator)
    pickle.remove_dispatch_entry(ClassWithGenerator)


def test_reducer_with_subclasses():
    @pickle.reducer(ClassWithGenerator, subclasses=True)
    def reduce(obj: ClassWithGenerator):
        return (obj.n,)

    cwg = pickle.loads(pickle.dumps(ClassWithGenerator(2)))
    assert next(cwg.gen) == 0
    assert next(cwg.gen) == 1

    cwg = pickle.loads(pickle.dumps(SubclassWithGenerator(2)))
    assert next(cwg.gen) == 0
    assert next(cwg.gen) == 1

    pickle.remove_dispatch_entry(ClassWithGenerator)

    with pytest.raises(TypeError):
        pickle.dumps(ClassWithGenerator(0))

    with pytest.raises(TypeError):
        pickle.dumps(SubclassWithGenerator(0))


class CustomObjectStateReducer(pickle.ObjectStateReducer):
    cls = ClassWithGenerator

    def prepare(self, obj, state):
        del state["gen"]

    def restore(self, obj, state):
        state["gen"] = obj._count()


def test_object_state_reducer():
    pickle.register()(CustomObjectStateReducer)

    cwg = pickle.loads(pickle.dumps(ClassWithGenerator(2)))
    assert next(cwg.gen) == 0
    assert next(cwg.gen) == 1

    pickle.remove_dispatch_entry(ClassWithGenerator)

    with pytest.raises(TypeError):
        pickle.dumps(ClassWithGenerator(0))


class Attribute:
    def __init__(self, value: str):
        self.value = value


class NewAttribute:
    def __init__(self, value: str):
        self.value = value


class DummyStore(BaseStore):
    strings: dict[str, str] = CrossRegionAttribute(default=dict)
    attributes: dict[str, Attribute] = CrossRegionAttribute(default=dict)


@pytest.mark.skip("This is what we need to solve")
def test_json_pickle_evolution():
    store = AccountRegionBundle("sqs", DummyStore, validate=False)
    store[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME].strings["foo"] = "baz"
    store[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME].attributes["foo"] = Attribute("baz")

    blob = pickle.dumps(store, encoder=JsonEncoder())

    # simulate class evolution by removing the class from the scope and changing the store annotations
    module = sys.modules[__name__]
    if hasattr(module, "Attribute"):
        delattr(module, "Attribute")
    DummyStore.__annotations__["attributes"] = dict[str, NewAttribute]
    obj = pickle.loads(blob, decoder=JsonDecoder())

    assert obj[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME].strings["foo"] == "baz"
    assert obj[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME].attributes["foo"].value == "baz"
