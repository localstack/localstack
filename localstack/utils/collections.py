"""This package provides custom collection types, as well as tools to analyze and manipulate python collection (
dicts, list, sets). """

import logging
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sized, Tuple, Type, TypeVar, Union

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


LOG = logging.getLogger(__name__)


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


class HashableList(list):
    """Hashable list class that can be used with dicts or hashsets."""

    def __hash__(self):
        result = 0
        for i in self:
            result += hash(i)
        return result


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
    attributes = attributes if is_list_or_tuple(attributes) else [attributes]
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


def select_from_typed_dict(typed_dict: Type[TypedDict], obj: Dict):
    """Select a subset of attributes from a dictionary based on the keys of a given `TypedDict`"""
    return select_attributes(obj, [*typed_dict.__required_keys__, *typed_dict.__optional_keys__])
