import copy
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


def _register_serialized_reference_replacement(
    transform_context: TransformContext, *, reference_value: str, replacement: str
):
    if '"' in reference_value:
        reference_value = reference_value.replace('"', '\\"')

    cache = transform_context._cache.setdefault("regexcache", set())
    cache_key = reference_value
    if cache_key not in cache:
        actual_replacement = f"<{replacement}:{transform_context.new_scope(replacement)}>"
        cache.add(cache_key)

        def _helper(bound_result, bound_replacement):
            def replace_val(s):
                LOG.debug(f"Replacing '{bound_result}' in snapshot with '{bound_replacement}'")
                return s.replace(bound_result, bound_replacement, -1)

            return replace_val

        LOG.debug(
            f"Registering reference replacement for value: '{reference_value}' -> '{actual_replacement}'"
        )
        transform_context.register_serialized_replacement(
            _helper(reference_value, actual_replacement)
        )


class Transformer(Protocol):
    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        ...


# Transformers


class ResponseMetaDataTransformer:
    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if k == "ResponseMetadata":
                metadata = v
                http_headers = metadata.get("HTTPHeaders")
                # TODO "x-amz-bucket-region"
                # TestS3.test_region_header_exists -> verifies bucket-region
                headers_to_collect = ["content_type"]
                simplified_headers = {}
                for h in headers_to_collect:
                    if http_headers.get(h):
                        simplified_headers[h] = http_headers[h]
                simplified_metadata = {
                    "HTTPHeaders": simplified_headers,
                }
                # HTTPStatusCode might be removed for marker skip_snapshot_verify
                if status_code := metadata.get("HTTPStatusCode"):
                    simplified_metadata["HTTPStatusCode"] = status_code
                input_data[k] = simplified_metadata
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)
        return input_data


class JsonpathTransformer:
    def __init__(self, jsonpath: str, replacement: str, replace_reference: bool = True) -> None:
        self.jsonpath = jsonpath
        self.replacement = replacement
        self.replace_references = replace_reference

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        pattern = parse(self.jsonpath)

        if self.replace_references:
            res = pattern.find(input_data)
            if not res:
                LOG.debug(f"No match found for JsonPath '{self.jsonpath}'")
                return input_data
            for r in res:
                value_to_replace = r.value
                _register_serialized_reference_replacement(
                    ctx, reference_value=value_to_replace, replacement=self.replacement
                )
        else:
            original = copy.deepcopy(input_data)
            pattern.update(input_data, self.replacement)
            if original != input_data:
                LOG.debug(
                    f"Replacing JsonPath '{self.jsonpath}' in snapshot with '{self.replacement}'"
                )
            else:
                LOG.debug(f"No match found for JsonPath '{self.jsonpath}'")

        return input_data

    def _add_jsonpath_replacement(self, jsonpath, replacement):
        self.json_path_replacement_list.append((jsonpath, replacement))


class RegexTransformer:
    def __init__(self, regex: str | Pattern[str], replacement: str):
        self.regex = regex
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        compiled_regex = re.compile(self.regex) if isinstance(self.regex, str) else self.regex

        def _regex_replacer_helper(pattern: Pattern[str], repl: str):
            def replace_val(s):
                result = re.sub(pattern, repl, s)
                if result != s:
                    LOG.debug(f"Replacing regex '{pattern.pattern}' with '{repl}'")
                else:
                    LOG.debug(f"No match found for regex '{pattern.pattern}'")
                return result

            return replace_val

        ctx.register_serialized_replacement(
            _regex_replacer_helper(compiled_regex, self.replacement)
        )
        LOG.debug(
            f"Registering regex pattern '{compiled_regex.pattern}' in snapshot with '{self.replacement}'"
        )
        return input_data


class KeyValueBasedTransformer:
    def __init__(
        self,
        match_fn: Callable[[str, str], Optional[str]],
        replacement: str,
        replace_reference: bool = True,
    ):
        self.match_fn = match_fn
        self.replacement = replacement
        self.replace_reference = replace_reference

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if match_result := self.match_fn(k, v):
                if self.replace_reference:
                    _register_serialized_reference_replacement(
                        ctx, reference_value=match_result, replacement=self.replacement
                    )
                else:
                    LOG.debug(
                        f"Replacing value for key '{k}' with '{self.replacement}'. (Original value: {str(v)})"
                    )
                    input_data[k] = self.replacement
            elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                for i in range(0, len(v)):
                    v[i] = self.transform(v[i], ctx=ctx)
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)

        return input_data


class GenericTransformer:
    def __init__(self, fn: Callable[[dict], dict]):
        self.fn = fn

    def transform(self, input_data: dict) -> dict:
        return self.fn(input_data)
