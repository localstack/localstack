import builtins
import json
import re
from copy import deepcopy
from typing import Callable

from localstack.utils import common
from localstack.utils.common import select_attributes, short_uid

# placeholders
PLACEHOLDER_AWS_NO_VALUE = "__aws_no_value__"


def dump_json_params(param_func=None, *param_names):
    def replace(params, **kwargs):
        result = param_func(params, **kwargs) if param_func else params
        for name in param_names:
            if isinstance(result.get(name), (dict, list)):
                # Fix for https://github.com/localstack/localstack/issues/2022
                # Convert any date instances to date strings, etc, Version: "2012-10-17"
                param_value = common.json_safe(result[name])
                result[name] = json.dumps(param_value)
        return result

    return replace


def param_defaults(param_func, defaults):
    def replace(params, **kwargs):
        result = param_func(params, **kwargs)
        for key, value in defaults.items():
            if result.get(key) in ["", None]:
                result[key] = value
        return result

    return replace


def remove_none_values(params):
    """Remove None values and AWS::NoValue placeholders (recursively) in the given object."""

    def remove_nones(o, **kwargs):
        if isinstance(o, dict):
            for k, v in dict(o).items():
                if v in [None, PLACEHOLDER_AWS_NO_VALUE]:
                    o.pop(k)
        if isinstance(o, list):
            common.run_safe(o.remove, None)
            common.run_safe(o.remove, PLACEHOLDER_AWS_NO_VALUE)
        return o

    result = common.recurse_object(params, remove_nones)
    return result


def params_list_to_dict(param_name, key_attr_name="Key", value_attr_name="Value"):
    def do_replace(params, **kwargs):
        result = {}
        for entry in params.get(param_name, []):
            key = entry[key_attr_name]
            value = entry[value_attr_name]
            result[key] = value
        return result

    return do_replace


def lambda_keys_to_lower(key=None):
    return lambda params, **kwargs: common.keys_to_lower(params.get(key) if key else params)


def merge_parameters(func1, func2):
    return lambda params, **kwargs: common.merge_dicts(
        func1(params, **kwargs), func2(params, **kwargs)
    )


def str_or_none(o):
    return o if o is None else json.dumps(o) if isinstance(o, (dict, list)) else str(o)


def params_dict_to_list(param_name, key_attr_name="Key", value_attr_name="Value", wrapper=None):
    def do_replace(params, **kwargs):
        result = []
        for key, value in params.get(param_name, {}).items():
            result.append({key_attr_name: key, value_attr_name: value})
        if wrapper:
            result = {wrapper: result}
        return result

    return do_replace


def params_select_attributes(*attrs):
    def do_select(params, **kwargs):
        result = {}
        for attr in attrs:
            if params.get(attr) is not None:
                result[attr] = str_or_none(params.get(attr))
        return result

    return do_select


def param_json_to_str(name):
    def _convert(params, **kwargs):
        result = params.get(name)
        if result:
            result = json.dumps(result)
        return result

    return _convert


def lambda_select_params(*selected):
    # TODO: remove and merge with function below
    return select_parameters(*selected)


def select_parameters(*param_names):
    return lambda params, **kwargs: select_attributes(params, param_names)


def is_none_or_empty_value(value):
    return not value or value == PLACEHOLDER_AWS_NO_VALUE


def generate_default_name(stack_name: str, logical_resource_id: str):
    random_id_part = short_uid()
    resource_id_part = logical_resource_id[:24]
    stack_name_part = stack_name[: 63 - 2 - (len(random_id_part) + len(resource_id_part))]
    return f"{stack_name_part}-{resource_id_part}-{random_id_part}"


def generate_default_name_without_stack(logical_resource_id: str):
    random_id_part = short_uid()
    resource_id_part = logical_resource_id[: 63 - 1 - len(random_id_part)]
    return f"{resource_id_part}-{random_id_part}"


def pre_create_default_name(key: str) -> Callable[[str, dict, str, dict, str], None]:
    def _pre_create_default_name(
        resource_id: str, resources: dict, resource_type: str, func: dict, stack_name: str
    ):
        resource = resources[resource_id]
        props = resource["Properties"]
        if not props.get(key):
            props[key] = generate_default_name(stack_name, resource_id)

    return _pre_create_default_name


# Utils for parameter conversion

# TODO: handling of multiple valid types
param_validation = re.compile(
    r"Invalid type for parameter (?P<param>\w+), value: (?P<value>\w+), type: <class '(?P<wrong_class>\w+)'>, valid types: <class '(?P<valid_class>\w+)'>"
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

        new_value = None
        if cast_class == bool and str(old_value).lower() in ["true", "false"]:
            new_value = str(old_value).lower() == "true"
        else:
            new_value = cast_class(old_value)
        set_nested(params, param_name, new_value)
    return params
