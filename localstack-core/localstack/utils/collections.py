"""
This package provides custom collection types, as well as tools to analyze
and manipulate python collection (dicts, list, sets).
"""

import logging
import re
from collections.abc import Mapping
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sized,
    Tuple,
    Type,
    TypedDict,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
)

import cachetools
import jsonpath_ng

LOG = logging.getLogger(__name__)

# default regex to match an item in a comma-separated list string
DEFAULT_REGEX_LIST_ITEM = r"[\w-]+"


class AccessTrackingDict(dict):
    """
    Simple utility class that can be used to track (write) accesses to a dict's attributes.
    Note: could also be written as a proxy, to preserve the identity of "wrapped" - for now, it
          simply duplicates the entries of "wrapped" in the constructor, for simplicity.
    """

    def __init__(self, wrapped, callback: Callable[[Dict, str, List, Dict], Any] = None):
        super().__init__(wrapped)
        self.callback = callback

    def __setitem__(self, key, value):
        self.callback and self.callback(self, "__setitem__", [key, value], {})
        return super().__setitem__(key, value)


class DelSafeDict(dict):
    """Useful when applying jsonpatch. Use it as follows:

    obj.__dict__ = DelSafeDict(obj.__dict__)
    apply_patch(obj.__dict__, patch)
    """

    def __delitem__(self, key, *args, **kwargs):
        self[key] = None


class ImmutableList(tuple):
    """
    Wrapper class to create an immutable view of a given list or sequence.
    Note: Currently, this is simply a wrapper around `tuple` - could be replaced with
    custom implementations over time, if needed.
    """


class HashableList(ImmutableList):
    """Hashable, immutable list wrapper that can be used with dicts or hash sets."""

    def __hash__(self):
        return sum(hash(i) for i in self)


class ImmutableDict(Mapping):
    """Wrapper class to create an immutable view of a given list or sequence."""

    def __init__(self, seq=None, **kwargs):
        self._dict = dict(seq, **kwargs)

    def __len__(self) -> int:
        return self._dict.__len__()

    def __iter__(self) -> Iterator:
        return self._dict.__iter__()

    def __getitem__(self, key):
        return self._dict.__getitem__(key)

    def __eq__(self, other):
        return self._dict.__eq__(other._dict if isinstance(other, ImmutableDict) else other)

    def __str__(self):
        return self._dict.__str__()


class HashableJsonDict(ImmutableDict):
    """
    Simple dict wrapper that can be used with dicts or hash sets. Note: the assumption is that the dict
    can be JSON-encoded (i.e., must be acyclic and contain only lists/dicts and simple types)
    """

    def __hash__(self):
        from localstack.utils.json import canonical_json

        return hash(canonical_json(self._dict))


_ListType = TypeVar("_ListType")


class PaginatedList(List[_ListType]):
    """List which can be paginated and filtered. For usage in AWS APIs with paginated responses"""

    DEFAULT_PAGE_SIZE = 50

    def get_page(
        self,
        token_generator: Callable[[_ListType], str],
        next_token: str = None,
        page_size: int = None,
        filter_function: Callable[[_ListType], bool] = None,
    ) -> Tuple[List[_ListType], Optional[str]]:
        if filter_function is not None:
            result_list = list(filter(filter_function, self))
        else:
            result_list = self

        if page_size is None:
            page_size = self.DEFAULT_PAGE_SIZE

        if len(result_list) <= page_size:
            return result_list, None

        start_idx = 0

        try:
            start_item = next(item for item in result_list if token_generator(item) == next_token)
            start_idx = result_list.index(start_item)
        except StopIteration:
            pass

        if start_idx + page_size < len(result_list):
            next_token = token_generator(result_list[start_idx + page_size])
        else:
            next_token = None

        return result_list[start_idx : start_idx + page_size], next_token


class CustomExpiryTTLCache(cachetools.TTLCache):
    """TTLCache that allows to set custom expiry times for individual keys."""

    def set_expiry(self, key: Any, ttl: Union[float, int]) -> float:
        """Set the expiry of the given key in a TTLCache to (<current_time> + <ttl>)"""
        with self.timer as time:
            # note: need to access the internal dunder API here
            self._TTLCache__getlink(key).expires = expiry = time + ttl
            return expiry


def get_safe(dictionary, path, default_value=None):
    """
    Performs a safe navigation on a Dictionary object and
    returns the result or default value (if specified).
    The function follows a common AWS path resolution pattern "$.a.b.c".

    :type dictionary: dict
    :param dictionary: Dict to perform safe navigation.

    :type path: list|str
    :param path: List or dot-separated string containing the path of an attribute,
                 starting from the root node "$".

    :type default_value: any
    :param default_value: Default value to return in case resolved value is None.

    :rtype: any
    :return: Resolved value or default_value.
    """
    if not isinstance(dictionary, dict) or len(dictionary) == 0:
        return default_value

    attribute_path = path if isinstance(path, list) else path.split(".")
    if len(attribute_path) == 0 or attribute_path[0] != "$":
        raise AttributeError('Safe navigation must begin with a root node "$"')

    current_value = dictionary
    for path_node in attribute_path:
        if path_node == "$":
            continue

        if re.compile("^\\d+$").search(str(path_node)):
            path_node = int(path_node)

        if isinstance(current_value, dict) and path_node in current_value:
            current_value = current_value[path_node]
        elif isinstance(current_value, list) and path_node < len(current_value):
            current_value = current_value[path_node]
        else:
            current_value = None

    return current_value or default_value


def set_safe_mutable(dictionary, path, value):
    """
    Mutates original dict and sets the specified value under provided path.

    :type dictionary: dict
    :param dictionary: Dict to mutate.

    :type path: list|str
    :param path: List or dot-separated string containing the path of an attribute,
                 starting from the root node "$".

    :type value: any
    :param value: Value to set under specified path.

    :rtype: dict
    :return: Returns mutated dictionary.
    """
    if not isinstance(dictionary, dict):
        raise AttributeError('"dictionary" must be of type "dict"')

    attribute_path = path if isinstance(path, list) else path.split(".")
    attribute_path_len = len(attribute_path)

    if attribute_path_len == 0 or attribute_path[0] != "$":
        raise AttributeError('Dict navigation must begin with a root node "$"')

    current_pointer = dictionary
    for i in range(attribute_path_len):
        path_node = attribute_path[i]

        if path_node == "$":
            continue

        if i < attribute_path_len - 1:
            if path_node not in current_pointer:
                current_pointer[path_node] = {}
            if not isinstance(current_pointer, dict):
                raise RuntimeError(
                    'Error while deeply setting a dict value. Supplied path is not of type "dict"'
                )
        else:
            current_pointer[path_node] = value

        current_pointer = current_pointer[path_node]

    return dictionary


def pick_attributes(dictionary, paths):
    """
    Picks selected attributes a returns them as a new dictionary.
    This function works as a whitelist of attributes to keep in a new dictionary.

    :type dictionary: dict
    :param dictionary: Dict to pick attributes from.

    :type paths: list of (list or str)
    :param paths: List of lists or strings with dot-separated paths, starting from the root node "$".

    :rtype: dict
    :return: Returns whitelisted dictionary.
    """
    new_dictionary = {}

    for path in paths:
        value = get_safe(dictionary, path)

        if value is not None:
            set_safe_mutable(new_dictionary, path, value)

    return new_dictionary


def select_attributes(obj: Dict, attributes: List[str]) -> Dict:
    """Select a subset of attributes from the given dict (returns a copy)"""
    attributes = attributes if is_list_or_tuple(attributes) else [attributes]
    return {k: v for k, v in obj.items() if k in attributes}


def remove_attributes(obj: Dict, attributes: List[str], recursive: bool = False) -> Dict:
    """Remove a set of attributes from the given dict (in-place)"""
    from localstack.utils.objects import recurse_object

    if recursive:

        def _remove(o, **kwargs):
            if isinstance(o, dict):
                remove_attributes(o, attributes)
            return o

        return recurse_object(obj, _remove)

    attributes = ensure_list(attributes)
    for attr in attributes:
        obj.pop(attr, None)
    return obj


def rename_attributes(
    obj: Dict, old_to_new_attributes: Dict[str, str], in_place: bool = False
) -> Dict:
    """Rename a set of attributes in the given dict object. Second parameter is a dict that maps old to
    new attribute names. Default is to return a copy, but can also pass in_place=True."""
    if not in_place:
        obj = dict(obj)
    for old_name, new_name in old_to_new_attributes.items():
        if old_name in obj:
            obj[new_name] = obj.pop(old_name)
    return obj


def is_list_or_tuple(obj) -> bool:
    return isinstance(obj, (list, tuple))


def ensure_list(obj: Any, wrap_none=False) -> Optional[List]:
    """Wrap the given object in a list, or return the object itself if it already is a list."""
    if obj is None and not wrap_none:
        return obj
    return obj if isinstance(obj, list) else [obj]


def to_unique_items_list(inputs, comparator=None):
    """Return a list of unique items from the given input iterable.
    The comparator(item1, item2) returns True/False or an int for comparison."""

    def contained(item):
        for r in result:
            if comparator:
                cmp_res = comparator(item, r)
                if cmp_res is True or str(cmp_res) == "0":
                    return True
            elif item == r:
                return True

    result = []
    for it in inputs:
        if not contained(it):
            result.append(it)
    return result


def merge_recursive(source, destination, none_values=None, overwrite=False):
    if none_values is None:
        none_values = [None]
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge_recursive(value, node, none_values=none_values, overwrite=overwrite)
        else:
            from requests.models import CaseInsensitiveDict

            if not isinstance(destination, (dict, CaseInsensitiveDict)):
                LOG.warning(
                    "Destination for merging %s=%s is not dict: %s (%s)",
                    key,
                    value,
                    destination,
                    type(destination),
                )
            if overwrite or destination.get(key) in none_values:
                destination[key] = value
    return destination


def merge_dicts(*dicts, **kwargs):
    """Merge all dicts in `*dicts` into a single dict, and return the result. If any of the entries
    in `*dicts` is None, and `default` is specified as keyword argument, then return `default`."""
    result = {}
    for d in dicts:
        if d is None and "default" in kwargs:
            return kwargs["default"]
        if d:
            result.update(d)
    return result


def remove_none_values_from_dict(dict: Dict) -> Dict:
    return {k: v for (k, v) in dict.items() if v is not None}


def last_index_of(array, value):
    """Return the last index of `value` in the given list, or -1 if it does not exist."""
    result = -1
    for i in reversed(range(len(array))):
        entry = array[i]
        if entry == value or (callable(value) and value(entry)):
            return i
    return result


def is_sub_dict(child_dict: Dict, parent_dict: Dict) -> bool:
    """Returns whether the first dict is a sub-dict (subset) of the second dict."""
    return all(parent_dict.get(key) == val for key, val in child_dict.items())


def items_equivalent(list1, list2, comparator):
    """Returns whether two lists are equivalent (i.e., same items contained in both lists,
    irrespective of the items' order) with respect to a comparator function."""

    def contained(item):
        for _item in list2:
            if comparator(item, _item):
                return True

    if len(list1) != len(list2):
        return False
    for item in list1:
        if not contained(item):
            return False
    return True


def is_none_or_empty(obj: Union[Optional[str], Optional[list]]) -> bool:
    return (
        obj is None
        or (isinstance(obj, str) and obj.strip() == "")
        or (isinstance(obj, Sized) and len(obj) == 0)
    )


def select_from_typed_dict(typed_dict: Type[TypedDict], obj: Dict, filter: bool = False) -> Dict:
    """
    Select a subset of attributes from a dictionary based on the keys of a given `TypedDict`.
    :param typed_dict: the `TypedDict` blueprint
    :param obj: the object to filter
    :param filter: if True, remove all keys with an empty (e.g., empty string or dictionary) or `None` value
    :return: the resulting dictionary (it returns a copy)
    """
    selection = select_attributes(
        obj, [*typed_dict.__required_keys__, *typed_dict.__optional_keys__]
    )
    if filter:
        selection = {k: v for k, v in selection.items() if v}
    return selection


T = TypeVar("T", bound=Dict)


def convert_to_typed_dict(typed_dict: Type[T], obj: Dict, strict: bool = False) -> T:
    """
    Converts the given object to the given typed dict (by calling the type constructors).
    Limitations:
    - This does not work for ForwardRefs (type refs in quotes).
    - If a type is a Union, the first type is used for the conversion.
    - The conversion fails for types which cannot be instantiated with the constructor.

    :param typed_dict: to convert the given object to
    :param obj: object to convert matching keys to the types defined in the typed dict
    :param strict: True if a TypeError should be raised in case the conversion fails
    :return: obj converted to the typed dict T
    """
    result = cast(T, select_from_typed_dict(typed_dict, obj, filter=True))
    for key, key_type in typed_dict.__annotations__.items():
        if key in result:
            # If it's a Union, or optional, we extract the first type argument
            if get_origin(key_type) in [Union, Optional]:
                key_type = get_args(key_type)[0]
            # Use duck-typing to check if the dict is a typed dict
            if hasattr(key_type, "__required_keys__") and hasattr(key_type, "__optional_keys__"):
                result[key] = convert_to_typed_dict(key_type, result[key])
            else:
                # Otherwise, we call the type's constructor (on a best-effort basis)
                try:
                    result[key] = key_type(result[key])
                except TypeError as e:
                    if strict:
                        raise e
                    else:
                        LOG.debug("Could not convert %s to %s.", key, key_type)
    return result


def dict_multi_values(elements: Union[List, Dict]) -> Dict[str, List[Any]]:
    """
    Return a dictionary with the original keys from the list of dictionary and the
    values are the list of values of the original dictionary.
    """
    result_dict = {}
    if isinstance(elements, dict):
        for key, value in elements.items():
            if isinstance(value, list):
                result_dict[key] = value
            else:
                result_dict[key] = [value]
    elif isinstance(elements, list):
        if isinstance(elements[0], list):
            for key, value in elements:
                if key in result_dict:
                    result_dict[key].append(value)
                else:
                    result_dict[key] = [value]
        else:
            result_dict[elements[0]] = elements[1:]
    return result_dict


ItemType = TypeVar("ItemType")


def split_list_by(
    lst: Iterable[ItemType], predicate: Callable[[ItemType], bool]
) -> Tuple[List[ItemType], List[ItemType]]:
    truthy, falsy = [], []

    for item in lst:
        if predicate(item):
            truthy.append(item)
        else:
            falsy.append(item)

    return truthy, falsy


def is_comma_delimited_list(string: str, item_regex: Optional[str] = None) -> bool:
    """
    Checks if the given string is a comma-delimited list of items.
    The optional `item_regex` parameter specifies the regex pattern for each item in the list.
    """
    item_regex = item_regex or DEFAULT_REGEX_LIST_ITEM

    pattern = re.compile(rf"^\s*({item_regex})(\s*,\s*{item_regex})*\s*$")
    if pattern.match(string) is None:
        return False
    return True


def convert_in_place_at_jsonpath(params: dict, jsonpath: str, conversion_fn: Callable[[Any], Any]):
    """
    Invokes a conversion function on a dictionary nested entry at a specific jsonpath with `conversion_fn`
    """
    jp = jsonpath_ng.parse(jsonpath)
    old_value = jp.find(params)[0].value
    if not old_value:
        return
    new_value = conversion_fn(old_value)
    jp.update(params, new_value)
