import logging
import re
from re import Pattern
from typing import Callable, Optional, Protocol

from jsonpath_ng.ext import parse

LOG = logging.getLogger(__name__)


# Types

GlobalReplacementFn = Callable[[str], str]


class TransformContext:
    _cache: dict
    replacements: list[GlobalReplacementFn]
    scoped_tokens: dict[str, int]

    def __init__(self):
        self.replacements = []
        self.scoped_tokens = {}
        self._cache = {}

    @property
    def serialized_replacements(self) -> list[GlobalReplacementFn]:  # TODO: naming
        return self.replacements

    def register_serialized_replacement(self, fn: GlobalReplacementFn):  # TODO: naming
        self.replacements.append(fn)

    def new_scope(self, scope: str) -> int:
        """retrieve new enumeration value for a given scope key (e.g. for tokens such as <fn-name:1>"""
        current_counter = self.scoped_tokens.setdefault(scope, 1)
        self.scoped_tokens[scope] += 1
        return current_counter


class Transformer(Protocol):
    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        ...


# Transformers
# TODO: unify naming (Transformers/Transformations)


class ResponseMetaDataTransformer:
    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if k == "ResponseMetadata":
                metadata = v
                http_headers = metadata.get("HTTPHeaders")
                simplified_headers = {}
                simplified_headers["content-type"] = http_headers["content-type"]

                simplified_metadata = {
                    "HTTPStatusCode": metadata.pop("HTTPStatusCode"),
                    "HTTPHeaders": simplified_headers,
                }
                input_data[k] = simplified_metadata
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)
        return input_data


class JsonpathTransformer:
    def __init__(self, jsonpath: str, replacement: str, replace_reference: bool = False) -> None:
        self.jsonpath = jsonpath
        self.replacement = replacement
        self.replace_references = replace_reference

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        pattern = parse(self.jsonpath)
        LOG.debug(f"Replacing JsonPath {self.jsonpath} in snapshot with {self.replacement}")

        if self.replace_references:
            res = pattern.find(input_data)
            for r in res:
                # TODO refactor!
                value_to_replace = r.value
                cache = ctx._cache.setdefault("regexcache", set())
                cache_key = (value_to_replace, self.replacement)
                if cache_key not in cache:
                    actual_replacement = f"<{self.replacement}:{ctx.new_scope(self.replacement)}>"
                    cache.add(cache_key)

                    def _helper(bound_result):
                        def replace_val(s):
                            LOG.debug(
                                f"Replacing {value_to_replace} in snapshot with {actual_replacement}"
                            )
                            return s.replace(bound_result, actual_replacement, -1)

                        return replace_val

                    ctx.register_serialized_replacement(_helper(value_to_replace))
        else:
            pattern.update(input_data, self.replacement)
        return input_data

    def _add_jsonpath_replacement(self, jsonpath, replacement):
        self.json_path_replacement_list.append((jsonpath, replacement))


# TODO - check if we need this - resource-name replacements in ARN could/should be done differently
class RegexMatchReplaceGroupTransformer:
    def __init__(self, regex: str | Pattern[str], group: int, replacement: str):
        self.regex = regex
        self.group = group
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        compiled_regex = re.compile(self.regex) if isinstance(self.regex, str) else self.regex

        def _replace_all(s):
            matches = compiled_regex.findall(s)
            counter = 1
            replaced = []
            for m in matches:
                original_value = m[self.group - 1]
                if original_value and original_value not in replaced:
                    repl = f"<{self.replacement}:{counter}>"
                    s = re.sub(original_value, repl, s)
                    counter += 1
                    LOG.debug(f"Replacing {original_value} in snapshot with {repl}")
                    replaced.append(original_value)
            return s

        ctx.register_serialized_replacement(_replace_all)
        return input_data


class RegexTransformer:
    def __init__(self, regex: str | Pattern[str], replacement: str):
        self.regex = regex
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        compiled_regex = re.compile(self.regex) if isinstance(self.regex, str) else self.regex
        ctx.register_serialized_replacement(lambda s: re.sub(compiled_regex, self.replacement, s))
        LOG.debug(f"Replacing regex in snapshot with {self.replacement}")
        return input_data


class GenericTransformer:
    def __init__(self, fn: Callable[[dict], dict]):
        self.fn = fn

    def transform(self, input_data: dict) -> dict:
        return self.fn(input_data)


class KeyValueBasedDirectTransformer:
    def __init__(self, match_fn: Callable[[str, str], bool], replacement: str):
        self.match_fn = match_fn
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if self.match_fn(
                k, v
            ):  # TODO: track previous replacements? any case where this is necessary?
                input_data[k] = self.replacement
            elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                for i in range(0, len(v)):
                    v[i] = self.transform(v[i], ctx=ctx)
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)

        return input_data


class KeyValueBasedReferenceTransformer:
    def __init__(self, match_fn: Callable[[str, str], Optional[str]], replacement: str):
        self.match_fn = match_fn
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                for i in range(0, len(v)):
                    v[i] = self.transform(v[i], ctx=ctx)
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)
            else:
                match_result = self.match_fn(k, v)
                if match_result:
                    cache = ctx._cache.setdefault("regexcache", set())
                    cache_key = (match_result, self.replacement)
                    if cache_key not in cache:
                        actual_replacement = (
                            f"<{self.replacement}:{ctx.new_scope(self.replacement)}>"
                        )
                        cache.add(cache_key)

                        def _helper(bound_result):
                            def replace_val(s):
                                LOG.debug(
                                    f"Replacing {bound_result} in snapshot with {actual_replacement}"
                                )
                                return s.replace(bound_result, actual_replacement, -1)

                            return replace_val

                        ctx.register_serialized_replacement(_helper(match_result))
        return input_data


def replace_camel_string_with_hyphen(input_string: str):
    return "".join(["-" + char.lower() if char.isupper() else char for char in input_string]).strip(
        "-"
    )


def create_transformer(fn: Callable[[dict], dict]) -> Transformer:
    return GenericTransformer(fn)


def key_transformer(key: str, replacement: Optional[str] = None):
    return KeyValueBasedDirectTransformer(
        lambda k, _: k == key, replacement=replacement or replace_camel_string_with_hyphen(key)
    )


def key_transformer_with_reference_replacement(key: str, replacement: Optional[str] = None):
    return KeyValueBasedReferenceTransformer(
        lambda k, v: v if k == key else None,
        replacement=replacement or replace_camel_string_with_hyphen(key),
    )


def jsonpath_transformer(jsonpath: str, replacement: str):
    return JsonpathTransformer(jsonpath=jsonpath, replacement=replacement)


def jsonpath_transformer_with_reference_replacement(jsonpath: str, replacement: str):
    return JsonpathTransformer(jsonpath=jsonpath, replacement=replacement, replace_reference=True)
