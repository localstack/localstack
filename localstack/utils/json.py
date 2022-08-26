import decimal
import json
import logging
import os
from datetime import date, datetime
from json import JSONDecodeError
from typing import Any, Union

from .numbers import is_number
from .strings import to_str
from .time import timestamp_millis

LOG = logging.getLogger(__name__)


class CustomEncoder(json.JSONEncoder):
    """Helper class to convert JSON documents with datetime, decimals, or bytes."""

    def default(self, o):
        import yaml  # leave import here, to avoid breaking our Lambda tests!

        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        if isinstance(o, (datetime, date)):
            return timestamp_millis(o)
        if isinstance(o, yaml.ScalarNode):
            if o.tag == "tag:yaml.org,2002:int":
                return int(o.value)
            if o.tag == "tag:yaml.org,2002:float":
                return float(o.value)
            if o.tag == "tag:yaml.org,2002:bool":
                return bool(o.value)
            return str(o.value)
        try:
            if isinstance(o, bytes):
                return to_str(o)
            return super(CustomEncoder, self).default(o)
        except Exception:
            return None


class BytesEncoder(json.JSONEncoder):
    """Helper class that converts JSON documents with bytes"""

    def default(self, obj):
        if isinstance(obj, bytes):
            return to_str(obj, errors="replace")
        return super().default(obj)


class FileMappedDocument(dict):
    """A dictionary that is mapped to a json document on disk.

    When the document is created, an attempt is made to load existing contents from disk. To load changes from
    concurrent writes, run load(). To save and overwrite the current document on disk, run save().
    """

    path: Union[str, os.PathLike]

    def __init__(self, path: Union[str, os.PathLike], mode=0o664):
        super().__init__()
        self.path = path
        self.mode = mode
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return

        if os.path.isdir(self.path):
            raise IsADirectoryError

        with open(self.path, "r") as fd:
            self.update(json.load(fd))

    def save(self):
        if os.path.isdir(self.path):
            raise IsADirectoryError

        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path), exist_ok=True)

        def opener(path, flags):
            _fd = os.open(path, flags, self.mode)
            os.chmod(path, mode=self.mode, follow_symlinks=True)
            return _fd

        with open(self.path, "w", opener=opener) as fd:
            json.dump(self, fd)


def clone(item):
    return json.loads(json.dumps(item))


def clone_safe(item):
    return clone(json_safe(item))


def parse_json_or_yaml(markup: str) -> Any:
    import yaml  # leave import here, to avoid breaking our Lambda tests!

    try:
        return json.loads(markup)
    except Exception:
        try:
            return clone_safe(yaml.safe_load(markup))
        except Exception:
            try:
                return clone_safe(yaml.load(markup, Loader=yaml.SafeLoader))
            except Exception:
                raise


def try_json(data: str):
    """
    Tries to deserialize the passed json input to an object if possible, otherwise returns the original input.
    :param data: string
    :return: deserialize version of input
    """
    try:
        return json.loads(to_str(data or "{}"))
    except JSONDecodeError:
        LOG.warning("failed serialize to json, fallback to original")
        return data


def json_safe(item: Any) -> Any:
    """Return a copy of the given object (e.g., dict) that is safe for JSON dumping"""
    try:
        return json.loads(json.dumps(item, cls=CustomEncoder))
    except Exception:
        item = fix_json_keys(item)
        return json.loads(json.dumps(item, cls=CustomEncoder))


def fix_json_keys(item: Any):
    """make sure the keys of a JSON are strings (not binary type or other)"""
    item_copy = item
    if isinstance(item, list):
        item_copy = []
        for i in item:
            item_copy.append(fix_json_keys(i))
    if isinstance(item, dict):
        item_copy = {}
        for k, v in item.items():
            item_copy[to_str(k)] = fix_json_keys(v)
    return item_copy


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True)


def extract_jsonpath(value, path):
    from jsonpath_rw import parse

    jsonpath_expr = parse(path)
    result = [match.value for match in jsonpath_expr.find(value)]
    result = result[0] if len(result) == 1 else result
    return result


def assign_to_path(target, path: str, value, delimiter: str = "."):
    parts = path.strip(delimiter).split(delimiter)
    path_to_parent = delimiter.join(parts[:-1])
    parent = extract_from_jsonpointer_path(target, path_to_parent, auto_create=True)
    if not isinstance(parent, dict):
        LOG.debug(
            'Unable to find parent (type %s) for path "%s" in object: %s',
            type(parent),
            path,
            target,
        )
        return
    path_end = int(parts[-1]) if is_number(parts[-1]) else parts[-1]
    parent[path_end] = value
    return target


def extract_from_jsonpointer_path(target, path: str, delimiter: str = "/", auto_create=False):
    parts = path.strip(delimiter).split(delimiter)
    for part in parts:
        path_part = int(part) if is_number(part) else part
        if isinstance(target, list) and not is_number(path_part):
            if path_part == "-":
                # special case where path is like /path/to/list/- where "/-" means "append to list"
                continue
            LOG.warning('Attempting to extract non-int index "%s" from list: %s', path_part, target)
            return None
        target_new = target[path_part] if isinstance(target, list) else target.get(path_part)
        if target_new is None:
            if not auto_create:
                return
            target[path_part] = target_new = {}
        target = target_new
    return target
