from typing import Any, Dict


def recursive_remove_none_values_from_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively removes keys with non values from a dictionary.
    """
    if not isinstance(d, dict):
        return d

    clean_dict = {}
    for key, value in d.items():
        if value is None:
            continue
        if isinstance(value, list):
            nested_list = [recursive_remove_none_values_from_dict(item) for item in value]
            nested_list = [item for item in nested_list if item]
            if nested_list:
                clean_dict[key] = nested_list
        elif isinstance(value, dict):
            nested_dict = recursive_remove_none_values_from_dict(value)
            if nested_dict:
                clean_dict[key] = nested_dict
        else:
            clean_dict[key] = value
    return clean_dict
