import json

from localstack.utils.objects import recurse_object


def rename_params(func, rename_map):
    def do_rename(params, **kwargs):
        values = func(params, **kwargs) if func else params
        for old_param, new_param in rename_map.items():
            values[new_param] = values.pop(old_param, None)
        return values

    return do_rename


def lambda_add_tags(func):
    return lambda params, **kwargs: add_tags(func(params, **kwargs))


def lambda_convert_types(func, types):
    return lambda params, **kwargs: convert_types(func(params, **kwargs), types)


def lambda_to_json(attr):
    return lambda params, **kwargs: json.dumps(params[attr])


def add_tags(obj, tags=[]):
    tags = tags or []
    obj["tags"] = obj.get("tags") or []
    obj["tags"].extend(tags)
    return obj


def lambda_rename_attributes(attrs, func=None):
    def recurse(o, path):
        if isinstance(o, dict):
            for k in list(o.keys()):
                for a in attrs.keys():
                    if k == a:
                        o[attrs[k]] = o.pop(k)
        return o

    func = func or (lambda x, **kwargs: x)
    return lambda params, **kwargs: recurse_object(func(params, **kwargs), recurse)


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
