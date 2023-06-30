import builtins
import json
import logging
import re
from copy import deepcopy
from typing import Callable, List

from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.common import select_attributes, short_uid
from localstack.utils.functions import run_safe
from localstack.utils.json import json_safe
from localstack.utils.objects import recurse_object
from localstack.utils.strings import is_string

# placeholders
PLACEHOLDER_AWS_NO_VALUE = "__aws_no_value__"

LOG = logging.getLogger(__name__)


def dump_json_params(param_func=None, *param_names):
    def replace(params, logical_resource_id, *args, **kwargs):
        result = param_func(params, logical_resource_id, *args, **kwargs) if param_func else params
        for name in param_names:
            if isinstance(result.get(name), (dict, list)):
                # Fix for https://github.com/localstack/localstack/issues/2022
                # Convert any date instances to date strings, etc, Version: "2012-10-17"
                param_value = common.json_safe(result[name])
                result[name] = json.dumps(param_value)
        return result

    return replace


# TODO: remove
def param_defaults(param_func, defaults):
    def replace(properties: dict, logical_resource_id: str, *args, **kwargs):
        result = param_func(properties, logical_resource_id, *args, **kwargs)
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
    def do_replace(params, logical_resource_id, *args, **kwargs):
        result = {}
        for entry in params.get(param_name, []):
            key = entry[key_attr_name]
            value = entry[value_attr_name]
            result[key] = value
        return result

    return do_replace


def lambda_keys_to_lower(key=None, skip_children_of: List[str] = None):
    return lambda params, logical_resource_id, *args, **kwargs: common.keys_to_lower(
        obj=(params.get(key) if key else params), skip_children_of=skip_children_of
    )


def merge_parameters(func1, func2):
    return lambda properties, logical_resource_id, *args, **kwargs: common.merge_dicts(
        func1(properties, logical_resource_id, *args, **kwargs),
        func2(properties, logical_resource_id, *args, **kwargs),
    )


def str_or_none(o):
    return o if o is None else json.dumps(o) if isinstance(o, (dict, list)) else str(o)


def params_dict_to_list(param_name, key_attr_name="Key", value_attr_name="Value", wrapper=None):
    def do_replace(params, logical_resource_id, *args, **kwargs):
        result = []
        for key, value in params.get(param_name, {}).items():
            result.append({key_attr_name: key, value_attr_name: value})
        if wrapper:
            result = {wrapper: result}
        return result

    return do_replace


# TODO: remove
def params_select_attributes(*attrs):
    def do_select(params, logical_resource_id, *args, **kwargs):
        result = {}
        for attr in attrs:
            if params.get(attr) is not None:
                result[attr] = str_or_none(params.get(attr))
        return result

    return do_select


def param_json_to_str(name):
    def _convert(params, logical_resource_id, *args, **kwargs):
        result = params.get(name)
        if result:
            result = json.dumps(result)
        return result

    return _convert


def lambda_select_params(*selected):
    # TODO: remove and merge with function below
    return select_parameters(*selected)


def select_parameters(*param_names):
    return lambda properties, logical_resource_id, *args, **kwargs: select_attributes(
        properties, param_names
    )


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

        if cast_class == bool and str(old_value).lower() in ["true", "false"]:
            new_value = str(old_value).lower() == "true"
        else:
            new_value = cast_class(old_value)
        set_nested(params, param_name, new_value)
    return params


def fix_account_id_in_arns(params: dict) -> dict:
    def fix_ids(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if is_string(v, exclude_binary=True):
                    o[k] = aws_stack.fix_account_id_in_arns(v)
        elif is_string(o, exclude_binary=True):
            o = aws_stack.fix_account_id_in_arns(o)
        return o

    result = recurse_object(params, fix_ids)
    return result


def convert_data_types(type_conversions: dict[str, Callable], params: dict) -> dict:
    """Convert data types in the "params" object, with the type defs
    specified in the 'types' attribute of "func_details"."""
    attr_names = type_conversions.keys() or []

    def cast(_obj, _type):
        if _type == bool:
            return _obj in ["True", "true", True]
        if _type == str:
            if isinstance(_obj, bool):
                return str(_obj).lower()
            return str(_obj)
        if _type in (int, float):
            return _type(_obj)
        return _obj

    def fix_types(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in attr_names:
                    o[k] = cast(v, type_conversions[k])
        return o

    result = recurse_object(params, fix_types)
    return result


def log_not_available_message(resource_type: str, message: str):
    LOG.warning(
        f"{message}. To find out if {resource_type} is supported in LocalStack Pro, "
        "please check out our docs at https://docs.localstack.cloud/user-guide/aws/cloudformation/#resources-pro--enterprise-edition"
    )


def dump_resource_as_json(resource: dict) -> str:
    return str(run_safe(lambda: json.dumps(json_safe(resource))) or resource)


def get_action_name_for_resource_change(res_change: str) -> str:
    return {"Add": "CREATE", "Remove": "DELETE", "Modify": "UPDATE"}.get(res_change)
