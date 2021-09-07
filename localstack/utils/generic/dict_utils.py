import re
from typing import Any, Callable, Dict, List


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
