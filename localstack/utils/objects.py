import re
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union

from .collections import ensure_list
from .strings import first_char_to_lower

ComplexType = Union[List, Dict, object]


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
                if impl_name not in instances:
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
            tmp_path = "%s[%s]" % (path or ".", i)
            obj[i] = recurse_object(obj[i], func, tmp_path)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            tmp_path = "%s%s" % (f"{path}." if path else "", k)
            obj[k] = recurse_object(v, func, tmp_path)
    return obj


def keys_to_lower(obj: ComplexType, skip_children_of: List[str] = None) -> ComplexType:
    """Recursively changes all dict keys to first character lowercase. Skip children
    of any elements whose names are contained in skip_children_of (e.g., ['Tags'])"""
    skip_children_of = ensure_list(skip_children_of or [])

    def fix_keys(o, path="", **kwargs):
        if any(re.match(r"(^|.*\.)%s($|[.\[].*)" % k, path) for k in skip_children_of):
            return o
        if isinstance(o, dict):
            for k, v in dict(o).items():
                o.pop(k)
                o[first_char_to_lower(k)] = v
        return o

    result = recurse_object(obj, fix_keys)
    return result
