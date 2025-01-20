import functools
import re
import threading
from typing import Any, Callable, Dict, Generic, List, Optional, Set, Type, TypeVar, Union

from .collections import ensure_list
from .strings import first_char_to_lower, first_char_to_upper

ComplexType = Union[List, Dict, object]

_T = TypeVar("_T")


class Value(Generic[_T]):
    """
    Simple value container.
    """

    value: Optional[_T]

    def __init__(self, value: _T = None) -> None:
        self.value = value

    def clear(self):
        self.value = None

    def set(self, value: _T):
        self.value = value

    def is_set(self) -> bool:
        return self.value is not None

    def get(self) -> Optional[_T]:
        return self.value

    def __bool__(self):
        return True if self.value else False


class ArbitraryAccessObj:
    """Dummy object that can be arbitrarily accessed - any attributes, as a callable, item assignment, ..."""

    def __init__(self, name=None):
        self.name = name

    def __getattr__(self, name, *args, **kwargs):
        return ArbitraryAccessObj(name)

    def __call__(self, *args, **kwargs):
        if self.name in ["items", "keys", "values"] and not args and not kwargs:
            return []
        return ArbitraryAccessObj()

    def __getitem__(self, *args, **kwargs):
        return ArbitraryAccessObj()

    def __setitem__(self, *args, **kwargs):
        return ArbitraryAccessObj()


class Mock:
    """Dummy class that can be used for mocking custom attributes."""

    pass


class ObjectIdHashComparator:
    """Simple wrapper class that allows us to create a hashset using the object id(..) as the entries' hash value"""

    def __init__(self, obj):
        self.obj = obj
        self._hash = id(obj)

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        # assumption here is that we're comparing only against ObjectIdHash instances!
        return self.obj == other.obj


class SubtypesInstanceManager:
    """Simple instance manager base class that scans the subclasses of a base type for concrete named
    implementations, and lazily creates and returns (singleton) instances on demand."""

    _instances: Dict[str, "SubtypesInstanceManager"]

    @classmethod
    def get(cls, subtype_name: str, raise_if_missing: bool = True):
        instances = cls.instances()
        base_type = cls.get_base_type()
        instance = instances.get(subtype_name)
        if instance is None:
            # lazily load subtype instance (required if new plugins are dynamically loaded at runtime)
            for clazz in get_all_subclasses(base_type):
                impl_name = clazz.impl_name()
                if impl_name not in instances and subtype_name == impl_name:
                    instances[impl_name] = clazz()
            instance = instances.get(subtype_name)
        if not instance and raise_if_missing:
            raise NotImplementedError(
                f"Unable to find implementation named '{subtype_name}' for base type {base_type}"
            )
        return instance

    @classmethod
    def instances(cls) -> Dict[str, "SubtypesInstanceManager"]:
        base_type = cls.get_base_type()
        if not hasattr(base_type, "_instances"):
            base_type._instances = {}
        return base_type._instances

    @staticmethod
    def impl_name() -> str:
        """Name of this concrete subtype - to be implemented by subclasses."""
        raise NotImplementedError

    @classmethod
    def get_base_type(cls) -> Type:
        """Get the base class for which instances are being managed - can be customized by subtypes."""
        return cls


# this requires that all subclasses have been imported before(!)
def get_all_subclasses(clazz: Type) -> Set[Type]:
    """Recursively get all subclasses of the given class."""
    result = set()
    subs = clazz.__subclasses__()
    for sub in subs:
        result.add(sub)
        result.update(get_all_subclasses(sub))
    return result


def fully_qualified_class_name(klass: Type) -> str:
    return f"{klass.__module__}.{klass.__name__}"


def not_none_or(value: Optional[Any], alternative: Any) -> Any:
    """Return 'value' if it is not None, or 'alternative' otherwise."""
    return value if value is not None else alternative


def recurse_object(obj: ComplexType, func: Callable, path: str = "") -> ComplexType:
    """Recursively apply `func` to `obj` (might be a list, dict, or other object)."""
    obj = func(obj, path=path)
    if isinstance(obj, list):
        for i in range(len(obj)):
            tmp_path = f"{path or '.'}[{i}]"
            obj[i] = recurse_object(obj[i], func, tmp_path)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            tmp_path = f"{f'{path}.' if path else ''}{k}"
            obj[k] = recurse_object(v, func, tmp_path)
    return obj


def keys_to(
    obj: ComplexType, op: Callable[[str], str], skip_children_of: List[str] = None
) -> ComplexType:
    """Recursively changes all dict keys to apply op. Skip children
    of any elements whose names are contained in skip_children_of (e.g., ['Tags'])"""
    skip_children_of = ensure_list(skip_children_of or [])

    def fix_keys(o, path="", **kwargs):
        if any(re.match(r"(^|.*\.)%s($|[.\[].*)" % k, path) for k in skip_children_of):
            return o
        if isinstance(o, dict):
            for k, v in dict(o).items():
                o.pop(k)
                o[op(k)] = v
        return o

    result = recurse_object(obj, fix_keys)
    return result


def keys_to_lower(obj: ComplexType, skip_children_of: List[str] = None) -> ComplexType:
    return keys_to(obj, first_char_to_lower, skip_children_of)


def keys_to_upper(obj: ComplexType, skip_children_of: List[str] = None) -> ComplexType:
    return keys_to(obj, first_char_to_upper, skip_children_of)


def singleton_factory(factory: Callable[[], _T]) -> Callable[[], _T]:
    """
    Decorator for methods that create a particular value once and then return the same value in a thread safe way.

    :param factory: the method to decorate
    :return: a threadsafe singleton factory
    """
    lock = threading.RLock()
    instance: Value[_T] = Value()

    @functools.wraps(factory)
    def _singleton_factory() -> _T:
        if instance.is_set():
            return instance.get()

        with lock:
            if not instance:
                instance.set(factory())

            return instance.get()

    _singleton_factory.clear = instance.clear

    return _singleton_factory


def get_value_from_path(data, path):
    keys = path.split(".")
    try:
        result = functools.reduce(dict.__getitem__, keys, data)
        return result
    except KeyError:
        # Handle the case where the path is not valid for the given dictionary
        return None


def set_value_at_path(data, path, new_value):
    keys = path.split(".")
    last_key = keys[-1]

    # Traverse the dictionary to the second-to-last level
    nested_dict = functools.reduce(dict.__getitem__, keys[:-1], data)

    try:
        # Set the new value
        nested_dict[last_key] = new_value
    except KeyError:
        # Handle the case where the path is not valid for the given dictionary
        raise ValueError(f"Invalid path: {path}")
