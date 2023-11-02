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


#  LocalStack specific utilities
def get_schema_path(file_path: Path) -> Path:
    file_name_base = file_path.name.removesuffix(".py").removesuffix(".py.enc")
    with Path(file_path).parent.joinpath(f"{file_name_base}.schema.json").open() as fd:
        return json.load(fd)
