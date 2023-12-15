import copy
import logging
import os
import re
from datetime import datetime
from re import Pattern
from typing import Any, Callable, Optional, Protocol

from jsonpath_ng.ext import parse

SNAPSHOT_LOGGER = logging.getLogger(__name__)
SNAPSHOT_LOGGER.setLevel(logging.DEBUG if os.environ.get("DEBUG_SNAPSHOT") else logging.WARNING)

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
                SNAPSHOT_LOGGER.debug(
                    f"Replacing '{bound_result}' in snapshot with '{bound_replacement}'"
                )
                return s.replace(bound_result, bound_replacement, -1)

            return replace_val

        SNAPSHOT_LOGGER.debug(
            f"Registering reference replacement for value: '{reference_value:.200s}' -> '{actual_replacement}'"
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
                SNAPSHOT_LOGGER.debug(f"No match found for JsonPath '{self.jsonpath}'")
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
                SNAPSHOT_LOGGER.debug(
                    f"Replacing JsonPath '{self.jsonpath}' in snapshot with '{self.replacement}'"
                )
            else:
                SNAPSHOT_LOGGER.debug(f"No match found for JsonPath '{self.jsonpath}'")

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
                    SNAPSHOT_LOGGER.debug(
                        f"Replacing regex '{pattern.pattern:.200s}' with '{repl}'"
                    )
                else:
                    SNAPSHOT_LOGGER.debug(f"No match found for regex '{pattern.pattern:.200s}'")
                return result

            return replace_val

        ctx.register_serialized_replacement(
            _regex_replacer_helper(compiled_regex, self.replacement)
        )
        SNAPSHOT_LOGGER.debug(
            f"Registering regex pattern '{compiled_regex.pattern:.200s}' in snapshot with '{self.replacement}'"
        )
        return input_data


class KeyValueBasedTransformer:
    def __init__(
        self,
        match_fn: Callable[[str, Any], Optional[str]],
        replacement: str,
        replace_reference: bool = True,
    ):
        self.match_fn = match_fn
        self.replacement = replacement
        self.replace_reference = replace_reference

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if (match_result := self.match_fn(k, v)) is not None:
                if self.replace_reference:
                    _register_serialized_reference_replacement(
                        ctx, reference_value=match_result, replacement=self.replacement
                    )
                else:
                    if isinstance(v, str):
                        SNAPSHOT_LOGGER.debug(
                            f"Replacing value for key '{k}': Match result '{match_result:.200s}' with '{self.replacement}'. (Original value: {str(v)})"
                        )
                        input_data[k] = v.replace(match_result, self.replacement)
                    else:
                        SNAPSHOT_LOGGER.debug(
                            f"Replacing value for key '{k}' with '{self.replacement}'. (Original value: {str(v)})"
                        )
                        input_data[k] = self.replacement
            elif isinstance(v, list) and len(v) > 0:
                for i in range(0, len(v)):
                    if isinstance(v[i], dict):
                        v[i] = self.transform(v[i], ctx=ctx)
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)

        return input_data


class GenericTransformer:
    def __init__(self, fn: Callable[[dict, TransformContext], dict]):
        self.fn = fn

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        return self.fn(input_data, ctx)


class SortingTransformer:
    key: str
    sorting_fn: Optional[Callable[[...], Any]]

    # TODO: add support for jsonpath
    def __init__(self, key: str, sorting_fn: Optional[Callable[[...], Any]] = None):
        """Sorts a list at `key` with the given `sorting_fn` (argument for `sorted(list, key=sorting_fn)`)"""
        self.key = key
        self.sorting_fn = sorting_fn

    def _transform_dict(self, input_data: dict, ctx: TransformContext = None) -> dict:
        for k, v in input_data.items():
            if k == self.key:
                if not isinstance(v, list):
                    raise ValueError("SortingTransformer should only be applied to lists.")
                input_data[k] = sorted(self._transform(v, ctx=ctx), key=self.sorting_fn)
            else:
                input_data[k] = self._transform(v, ctx=ctx)
        return input_data

    def _transform_list(self, input_data: list, ctx: TransformContext = None) -> list:
        return list(map(lambda e: self._transform(e, ctx=ctx), input_data))

    def _transform(self, input_data: Any, ctx: TransformContext = None) -> Any:
        if isinstance(input_data, dict):
            return self._transform_dict(input_data, ctx=ctx)
        elif isinstance(input_data, list):
            return self._transform_list(input_data, ctx=ctx)
        else:
            return input_data

    def transform(self, input_data: dict, *, ctx: TransformContext = None) -> dict:
        return self._transform_dict(input_data, ctx=ctx)


class RegexMatcher:
    def __init__(self, regex: str | re.Pattern, representation: str):
        if isinstance(regex, str):
            self.regex = re.compile(regex)
        elif isinstance(regex, re.Pattern):
            self.regex = regex
        else:
            raise Exception("Invalid")

        self.representation = representation


REFERENCE_DATE = (
    "2022-07-13T13:48:01Z"  # v1.0.0 commit timestamp cf26bd9199354a9a55e0b65e312ceee4c407f6c0
)
PATTERN_ISO8601 = re.compile(
    r"(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-][01]\d:?([0-5]\d)?)"
)


class TimestampTransformer:
    matchers: list[RegexMatcher]

    def __init__(self):
        """
        Create a timestamp transformer which will replace normal datetimes with <datetime> and string timestamps with their representative format.

        The reference date which is used for replacements is "2022-07-13T13:48:01Z", the commit date for the v1.0.0 tag of localstack.
        """

        # Add your matcher here
        self.matchers = [
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z", "2022-07-13T13:48:01.000Z"
            ),  # stepfunctions internal
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}\+\d{4}", "2022-07-13T13:48:01.000+0000"
            ),  # lambda
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}\+\d{2}:\d{2}",
                "2022-07-13T13:48:01.000000+00:00",
            ),  # stepfunctions external, also cloudformation
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                "2022-07-13T13:48:01Z",
            ),  # s3
            # RegexMatcher(
            #     PATTERN_ISO8601, "generic-iso8601"
            # ),  # very generic iso8601, this should technically always be fixed so we could also think about removing it here
        ]

    def transform(self, input_data: dict, *, ctx: TransformContext = None) -> dict:
        return self._transform_dict(input_data, ctx=ctx)

    def _transform(self, input_data: Any, ctx: TransformContext = None) -> Any:
        if isinstance(input_data, dict):
            return self._transform_dict(input_data, ctx=ctx)
        elif isinstance(input_data, list):
            return self._transform_list(input_data, ctx=ctx)
        elif isinstance(input_data, datetime):
            return "<datetime>"
        elif isinstance(input_data, str):
            return self._transform_timestamp(input_data)
        return input_data

    def _transform_timestamp(self, timestamp: str) -> str:
        for matcher in self.matchers:
            if matcher.regex.match(timestamp):
                return f"<timestamp:{matcher.representation}>"
        return timestamp

    def _transform_dict(self, input_data: dict, ctx: TransformContext = None) -> dict:
        for k, v in input_data.items():
            input_data[k] = self._transform(v, ctx=ctx)
        return input_data

    def _transform_list(self, input_data: list, ctx: TransformContext = None) -> list:
        return list(map(lambda e: self._transform(e, ctx=ctx), input_data))
