"""
A set of utils for use in resource providers.

Avoid any imports to localstack here and keep external imports to a minimum!
This is because we want to be able to package a resource provider without including localstack code.
"""

import builtins
import json
import re
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Callable, List, Optional

from botocore.model import Shape, StructureShape


def generate_default_name(stack_name: str, logical_resource_id: str):
    random_id_part = str(uuid.uuid4())[0:8]
    resource_id_part = logical_resource_id[:24]
    stack_name_part = stack_name[: 63 - 2 - (len(random_id_part) + len(resource_id_part))]
    return f"{stack_name_part}-{resource_id_part}-{random_id_part}"


def generate_default_name_without_stack(logical_resource_id: str):
    random_id_part = str(uuid.uuid4())[0:8]
    resource_id_part = logical_resource_id[: 63 - 1 - len(random_id_part)]
    return f"{resource_id_part}-{random_id_part}"


# ========= Helpers for boto calls ==========
# (equivalent to the old ones in deployment_utils.py)


def deselect_attributes(model: dict, params: list[str]) -> dict:
    return {k: v for k, v in model.items() if k not in params}


def select_attributes(model: dict, params: list[str]) -> dict:
    return {k: v for k, v in model.items() if k in params}


def keys_lower(model: dict) -> dict:
    return {k.lower(): v for k, v in model.items()}


def convert_pascalcase_to_lower_camelcase(item: str) -> str:
    if len(item) <= 1:
        return item.lower()
    else:
        return f"{item[0].lower()}{item[1:]}"


def convert_lower_camelcase_to_pascalcase(item: str) -> str:
    if len(item) <= 1:
        return item.upper()
    else:
        return f"{item[0].upper()}{item[1:]}"


def _recurse_properties(obj: dict | list, fn: Callable) -> dict | list:
    obj = fn(obj)
    if isinstance(obj, dict):
        return {k: _recurse_properties(v, fn) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_recurse_properties(v, fn) for v in obj]
    else:
        return obj


def recurse_properties(properties: dict, fn: Callable) -> dict:
    return _recurse_properties(deepcopy(properties), fn)


def keys_pascalcase_to_lower_camelcase(model: dict) -> dict:
    """Recursively change any dicts keys to lower camelcase"""

    def _keys_pascalcase_to_lower_camelcase(obj):
        if isinstance(obj, dict):
            return {convert_pascalcase_to_lower_camelcase(k): v for k, v in obj.items()}
        else:
            return obj

    return _recurse_properties(model, _keys_pascalcase_to_lower_camelcase)


def keys_lower_camelcase_to_pascalcase(model: dict) -> dict:
    """Recursively change any dicts keys to PascalCase"""

    def _keys_lower_camelcase_to_pascalcase(obj):
        if isinstance(obj, dict):
            return {convert_lower_camelcase_to_pascalcase(k): v for k, v in obj.items()}
        else:
            return obj

    return _recurse_properties(model, _keys_lower_camelcase_to_pascalcase)


def transform_list_to_dict(param, key_attr_name="Key", value_attr_name="Value"):
    result = {}
    for entry in param:
        key = entry[key_attr_name]
        value = entry[value_attr_name]
        result[key] = value
    return result


def remove_none_values(obj):
    """Remove None values (recursively) in the given object."""
    if isinstance(obj, dict):
        return {k: remove_none_values(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [o for o in obj if o is not None]
    else:
        return obj


# FIXME: this shouldn't be necessary in the future
param_validation = re.compile(
    r"Invalid type for parameter (?P<param>[\w.]+), value: (?P<value>\w+), type: <class '(?P<wrong_class>\w+)'>, valid types: <class '(?P<valid_class>\w+)'>"
)


def get_nested(obj: dict, path: str):
    parts = path.split(".")
    result = obj
    for p in parts[:-1]:
        result = result.get(p, {})
    return result.get(parts[-1])


def set_nested(obj: dict, path: str, value):
    parts = path.split(".")
    result = obj
    for p in parts[:-1]:
        result = result.get(p, {})
    result[parts[-1]] = value


def fix_boto_parameters_based_on_report(original_params: dict, report: str) -> dict:
    """
    Fix invalid type parameter validation errors in boto request parameters

    :param original_params: original boto request parameters that lead to the parameter validation error
    :param report: error report from botocore ParamValidator
    :return: a copy of original_params with all values replaced by their correctly cast ones
    """
    params = deepcopy(original_params)
    for found in param_validation.findall(report):
        param_name, value, wrong_class, valid_class = found
        cast_class = getattr(builtins, valid_class)
        old_value = get_nested(params, param_name)

        if cast_class == bool and str(old_value).lower() in ["true", "false"]:
            new_value = str(old_value).lower() == "true"
        else:
            new_value = cast_class(old_value)
        set_nested(params, param_name, new_value)
    return params


def convert_request_kwargs(parameters: dict, input_shape: StructureShape) -> dict:
    """
    Transform a dict of request kwargs for a boto3 request by making sure the keys in the structure recursively conform to the specified input shape.
    :param parameters: the kwargs that would be passed to the boto3 client call, e.g. boto3.client("s3").create_bucket(**parameters)
    :param input_shape: The botocore input shape of the operation that you want to call later with the fixed inputs
    :return: a transformed dictionary with the correct casing recursively applied
    """

    def get_fixed_key(key: str, members: dict[str, Shape]) -> str:
        """return the case-insensitively matched key from the shape or default to the current key"""
        for k in members:
            if k.lower() == key.lower():
                return k
        return key

    def transform_value(value, member_shape):
        if isinstance(value, dict) and hasattr(member_shape, "members"):
            return convert_request_kwargs(value, member_shape)
        elif isinstance(value, list) and hasattr(member_shape, "member"):
            return [transform_value(item, member_shape.member) for item in value]

        # fix the typing of the value
        match member_shape.type_name:
            case "string":
                return str(value)
            case "integer" | "long":
                return int(value)
            case "boolean":
                if isinstance(value, bool):
                    return value
                return True if value.lower() == "true" else False
            case _:
                return value

    transformed_dict = {}
    for key, value in parameters.items():
        correct_key = get_fixed_key(key, input_shape.members)
        member_shape = input_shape.members.get(correct_key)

        if member_shape is None:
            continue  # skipping this entry, so it's not included in the transformed dict
        elif isinstance(value, dict) and hasattr(member_shape, "members"):
            transformed_dict[correct_key] = convert_request_kwargs(value, member_shape)
        elif isinstance(value, list) and hasattr(member_shape, "member"):
            transformed_dict[correct_key] = [
                transform_value(item, member_shape.member) for item in value
            ]
        else:
            transformed_dict[correct_key] = transform_value(value, member_shape)

    return transformed_dict


def convert_values_to_numbers(input_dict: dict, keys_to_skip: Optional[List[str]] = None):
    """
    Recursively converts all string values that represent valid integers
    in a dictionary (including nested dictionaries and lists) to integers.

    Example:
    original_dict = {'Gid': '1322', 'SecondaryGids': ['1344', '1452'], 'Uid': '13234'}
    output_dict = {'Gid': 1322, 'SecondaryGids': [1344, 1452], 'Uid': 13234}

    :param input_dict input dict with values to convert
    :param keys_to_skip keys to which values are not meant to be converted
    :return output_dict
    """

    keys_to_skip = keys_to_skip or []

    def recursive_convert(obj):
        if isinstance(obj, dict):
            return {
                key: recursive_convert(value) if key not in keys_to_skip else value
                for key, value in obj.items()
            }
        elif isinstance(obj, list):
            return [recursive_convert(item) for item in obj]
        elif isinstance(obj, str) and obj.isdigit():
            return int(obj)
        else:
            return obj

    return recursive_convert(input_dict)


#  LocalStack specific utilities
def get_schema_path(file_path: Path) -> dict:
    file_name_base = file_path.name.removesuffix(".py").removesuffix(".py.enc")
    with Path(file_path).parent.joinpath(f"{file_name_base}.schema.json").open() as fd:
        return json.load(fd)
