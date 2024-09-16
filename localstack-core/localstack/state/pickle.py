"""
A small wrapper around dill that integrates with our state API, and allows registering custom serializer methods for
class hierarchies.

For your convenience, you can simply call ``dumps`` or ``loads`` as you would pickle or dill::

    from localstack.state import pickle
    foo = pickle.loads(pickle.dumps(Foo()))


You can register custom state serializers and deserializers to dill's dispatch table, but can also apply them to the
entire subclass hierarchy::

    @register(PriorityQueue, subclasses=True)
    def my_queue_pickler(pickler, obj):
        pickler.save_reduce(_recreate, (type(obj), obj.queue,), obj=obj)

    def _recreate(obj_type, obj_queue):
        # this method will be called when the object is de-serialized. you won't be able to reach it with the
        # debugger though, it's saved into the pickle! Make sure it's outside the actual reduce hook, otherwise a new
        # function is created every time for every serialized object of that type.

        q = obj_type()
        q.queue = obj_queue
        return q

To learn more about this mechanism, read https://docs.python.org/3/library/copyreg.html and
https://dill.readthedocs.io/en/latest/index.html?highlight=register#dill.Pickler.dispatch.
"""

import inspect
from typing import Any, BinaryIO, Callable, Generic, Type, TypeVar

import dill
from dill._dill import MetaCatchingDict

from .core import Decoder, Encoder

_T = TypeVar("_T")

PythonPickler = Any
"""Type placeholder for pickle._Pickler (which has for instance the save_reduce method)"""


def register(cls: Type = None, subclasses: bool = False):
    """
    Decorator to register a custom type or type tree into the dill pickling dispatcher table.

    :param cls: the type
    :param subclasses: whether to dispatch all subclasses to this function as well
    :return:
    """

    def _wrapper(fn: Any | Callable[[PythonPickler, Any], None]):
        if inspect.isclass(fn) and issubclass(fn, ObjectStateReducer):
            if cls is not None:
                raise ValueError("superfluous cls attribute for registering classes")
            obj = fn.create()
            add_dispatch_entry(obj.cls, obj._pickle, subclasses)
        elif callable(fn):
            add_dispatch_entry(cls, fn, subclasses=subclasses)
        else:
            raise ValueError("cannot register %s" % fn)

        return fn

    return _wrapper


def reducer(cls: Type, restore: Callable = None, subclasses: bool = False):
    """
    Convenience decorator to simplify the following pattern::

        def _create_something(attr1, attr2):
            return Something(attr1, attr2)

        @register(Something)
        def pickle_something(pickler, obj):
            attr1 = obj.attr1
            attr2 = obj.attr2
            return pickler.save_reduce(_create_something, (attr1, attr2), obj=obj)

    into::

        def _create_something(attr1, attr2):
            return Something(attr1, attr2)

        @reducer(Something, _create_something)
        def pickle_something(pickler, obj):
            return obj.attr1, obj.attr2

    in some cases, if your constructor matches the arguments you return, into::

        @reducer(Something)
        def pickle_something(pickler, obj):
            return obj.attr1, obj.attr2

    Note that this option creates larger pickles than the previous option, since this option also needs to store the
    ``Something`` class into the pickle.

    :param cls:
    :param restore:
    :param subclasses:
    :return:
    """

    def _wrapper(fn):
        def _reducer(pickler, obj):
            return pickler.save_reduce(restore or cls, fn(obj), obj=obj)

        add_dispatch_entry(cls, _reducer, subclasses)
        return fn

    return _wrapper


def add_dispatch_entry(
    cls: Type, fn: Callable[[PythonPickler, Any], None], subclasses: bool = False
):
    Pickler.dispatch_overwrite[cls] = fn
    if subclasses:
        Pickler.match_subclasses_of.add(cls)


def remove_dispatch_entry(cls: Type):
    try:
        del Pickler.dispatch_overwrite[cls]
    except KeyError:
        pass

    try:
        Pickler.match_subclasses_of.remove(cls)
    except KeyError:
        pass


def dumps(obj: Any) -> bytes:
    """
    Pickle an object into bytes using a ``PickleEncoder``.

    :param obj: the object to pickle
    :return: the pickled object
    """
    return PickleEncoder().encodes(obj)


def dump(obj: Any, file: BinaryIO):
    """
    Pickle an object into a buffer using a ``PickleEncoder``.

    :param obj: the object to pickle
    :param file: the IO buffer
    """
    return PickleEncoder().encode(obj, file)


def loads(data: bytes) -> Any:
    """
    Unpickle am object from bytes using a ``PickleDecoder``.

    :param data: the pickled object
    :return: the unpickled object
    """
    return PickleDecoder().decodes(data)


def load(file: BinaryIO) -> Any:
    """
    Unpickle am object from a buffer using a ``PickleDecoder``.

    :param file: the buffer containing the pickled object
    :return: the unpickled object
    """
    return PickleDecoder().decode(file)


class _SuperclassMatchingTypeDict(MetaCatchingDict):
    """
    A special dictionary where keys are types, and keys are also optionally matched on their subclasses. Types where
    subclass matching should happen can be registered through the ``dispatch_subclasses_of`` property. Example::

        d = _SuperclassMatchingTypeDict()
        d[dict] = "a dict"
        d[defaultdict] # raises key error
        d.match_subclasses_of.add(dict)
        d[defaultdict] # returns "a dict"

    """

    def __init__(self, seq=None, match_subclasses_of: set[Type] = None):
        if seq is not None:
            super().__init__(seq)
        else:
            super().__init__()

        self.match_subclasses_of = match_subclasses_of or set()

    def __missing__(self, key):
        for c in key.__mro__[1:]:
            # traverse the superclasses upwards until a dispatcher is found
            if c not in self.match_subclasses_of:
                continue

            if fn := super().get(c):
                return fn

        return super().__missing__(key)


class Pickler(dill.Pickler):
    """
    Custom dill pickler that considers dispatchers and subclass dispatchers registered via ``register``.
    """

    match_subclasses_of: set[Type] = set()
    dispatch_overwrite: dict[Type, Callable] = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # create the dispatch table (inherit the dill dispatchers)
        dispatch = _SuperclassMatchingTypeDict(dill.Pickler.dispatch.copy())
        dispatch.update(Pickler.dispatch_overwrite.copy())  # makes sure ours take precedence
        dispatch.match_subclasses_of.update(Pickler.match_subclasses_of.copy())
        self.dispatch = dispatch


class PickleEncoder(Encoder):
    """
    An Encoder that use a dill pickling under the hood, and by default uses the custom ``Pickler`` that can be
    extended with custom serializers.
    """

    pickler_class: Type[dill.Pickler]

    def __init__(self, pickler_class: Type[dill.Pickler] = None):
        self.pickler_class = pickler_class or Pickler

    def encode(self, obj: Any, file: BinaryIO):
        return self.pickler_class(file).dump(obj)


class PickleDecoder(Decoder):
    """
    A Decoder that use a dill pickling under the hood, and by default uses the custom ``Unpickler`` that can be
    extended with custom serializers.
    """

    unpickler_class: Type[dill.Unpickler]

    def __init__(self, unpickler_class: Type[dill.Unpickler] = None):
        self.unpickler_class = unpickler_class or dill.Unpickler

    def decode(self, file: BinaryIO) -> Any:
        return self.unpickler_class(file).load()


class ObjectStateReducer(Generic[_T]):
    """
    A generalization of the following pattern::

        def _create_something(cls: Type, state: dict):
            obj = cls.__new__(self.cls)

            # do stuff on the state (perhaps re-create some attributes)
            state["this_one_doesnt_serialize"] = restore(state["this_one_serialized"])

            obj.__dict__.update(state)
            return obj

        @register(Something)
        def pickle_something(pickler, obj):
            state = obj.__dict__.copy()
            state.pop("this_one_doesnt_serialize")
            return pickler.save_reduce(_create_something, (state,), obj=obj)


    With the ObjectStateReducer, this can now be expressed as:

        @register()
        class SomethingPickler(ObjectStatePickler):
            cls = Something

            def prepare(state: dict):
                state.pop("this_one_doesnt_serialize")

            def restore(state: dict):
                state["this_one_doesnt_serialize"] = restore(state["this_one_serialized"])
    """

    cls: _T

    @classmethod
    def create(cls):
        return cls()

    def register(self, subclasses=False):
        """
        Registers this ObjectStateReducer's reducer function. See ``pickle.register``.
        """
        add_dispatch_entry(self.cls, self._pickle, subclasses=subclasses)

    def _pickle(self, pickler, obj: _T):
        state = self.get_state(obj)
        self.prepare(obj, state)
        return pickler.save_reduce(self._unpickle, (state,), obj=obj)

    def _unpickle(self, state: dict) -> dict:
        obj = self.cls.__new__(self.cls)
        self.restore(obj, state)
        self.set_state(obj, state)
        return obj

    def get_state(self, obj: _T) -> Any:
        """
        Return the objects state. Can be overwritten by subclasses to return custom state.

        :param obj: the object
        :return: the unprepared state
        """
        return obj.__dict__.copy()

    def set_state(self, obj: _T, state: Any):
        """
        Set the state of the object. Can be overwritten by subclasses to set custom state.

        :param obj: the object
        :param state: the restored object state.
        """
        obj.__dict__.update(state)

    def prepare(self, obj: _T, state: Any):
        """
        Can be overwritten by subclasses to prepare the object state for pickling.

        :param obj: the object
        :param state: the object state to serialize
        """
        pass

    def restore(self, obj: _T, state: Any):
        """
        Can be overwritten by subclasses to modify the object state to restore any previously removed attributes.

        :param obj: the object
        :param state: the object's state to restore
        """
        pass
