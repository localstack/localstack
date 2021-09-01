import json
import os

from localstack.constants import INSTALL_DIR_INFRA
from localstack.utils import common

# URL to "cfn-response" module which is required in some CF Lambdas
from localstack.utils.common import select_attributes

CFN_RESPONSE_MODULE_URL = (
    "https://raw.githubusercontent.com/LukeMizuhashi/cfn-response/master/index.js"
)

# placeholders
PLACEHOLDER_RESOURCE_NAME = "__resource_name__"
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
    """Remove None values recursively in the given object."""

    def remove_nones(o, **kwargs):
        if isinstance(o, dict):
            for k, v in dict(o).items():
                if v is None:
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


def get_cfn_response_mod_file():
    cfn_response_tmp_file = os.path.join(INSTALL_DIR_INFRA, "lambda.cfn-response.js")
    if not os.path.exists(cfn_response_tmp_file):
        common.download(CFN_RESPONSE_MODULE_URL, cfn_response_tmp_file)
    return cfn_response_tmp_file


def lambda_select_params(*selected):
    # TODO: remove and merge with function below
    return select_parameters(*selected)


def select_parameters(*param_names):
    return lambda params, **kwargs: select_attributes(params, param_names)
