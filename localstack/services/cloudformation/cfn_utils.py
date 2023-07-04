import json
from typing import Callable

from localstack.utils.objects import recurse_object


def rename_params(func, rename_map):
    def do_rename(params, logical_resource_id, *args, **kwargs):
        values = func(params, logical_resource_id, *args, **kwargs) if func else params
        for old_param, new_param in rename_map.items():
            values[new_param] = values.pop(old_param, None)
        return values

    return do_rename


def lambda_convert_types(func, types):
    return lambda params, logical_resource_id, *args, **kwargs: convert_types(
        func(params, *args, **kwargs), types
    )


def lambda_to_json(attr):
    return lambda params, logical_resource_id, *args, **kwargs: json.dumps(params[attr])


def lambda_rename_attributes(attrs, func=None):
    def recurse(o, path):
        if isinstance(o, dict):
            for k in list(o.keys()):
                for a in attrs.keys():
                    if k == a:
                        o[attrs[k]] = o.pop(k)
        return o

    func = func or (lambda x, logical_resource_id, *args, **kwargs: x)
    return lambda params, logical_resource_id, *args, **kwargs: recurse_object(
        func(params, logical_resource_id, *args, **kwargs), recurse
    )


def convert_types(obj, types):
    def fix_types(key, type_class):
        def recurse(o, path):
            if isinstance(o, dict):
                for k, v in dict(o).items():
                    key_path = "%s%s" % (path or ".", k)
                    if key in [k, key_path]:
                        o[k] = type_class(v)
            return o

        return recurse_object(obj, recurse)

    for key, type_class in types.items():
        fix_types(key, type_class)
    return obj


def get_tags_param(resource_type: str) -> Callable:
    """Return a tag parameters creation function for the given resource type"""

    def _param(params, logical_resource_id, *args, **kwargs):
        tags = params.get("Tags")
        if not tags:
            return None

        return [{"ResourceType": resource_type, "Tags": tags}]

    return _param
