from queue import PriorityQueue

import pytest

from localstack.state import pickle


def test_pickle_priority_queue():
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
