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


class JsonPathTransformer:
    def __init__(self, replacements: [(str, str)]) -> None:
        assert replacements
        self.json_path_replacement_list = replacements

    def transform(self, input_data: dict) -> dict:
        self._replace_json_path_pattern(input_data)
        return input_data

    def _add_jsonpath_replacement(self, jsonpath, replacement):
        self.json_path_replacement_list.append((jsonpath, replacement))

    def _replace_pattern(
        self,
        json_path,
        replacement,
        input_data,
        verify_match=None,
    ):
        pattern = parse(json_path)
        for match in pattern.find(input_data):
            if verify_match and re.match(verify_match, match.value):
                pattern.update(input_data, replacement)
            elif not verify_match:
                pattern.update(input_data, replacement)

    def _replace_json_path_pattern(self, input_data: dict) -> dict:
        for (json_path, replace_string) in self.json_path_replacement_list:
            self._replace_pattern(
                json_path=json_path, replacement=replace_string, input_data=input_data
            )
        return input_data


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


def create_transformer(fn: Callable[[dict], dict]) -> Transformer:
    return GenericTransformer(fn)


#     def _is_date(self, value: str):
#         try:
#             # TODO seems like the date can have various formats, use this dateutil lib?
#             dateutil_parser.parse(value)
#             return True
#         except Exception:
#             return False
#
#     def transform(self, input_data: dict) -> dict:
#         self.clean_response_metadata(input_data)
#         self.replace_common_values(input_data)
#
#         # TODO move this somewhere else
#         replace_pattern = [
#             ("$..Code.Location", "<location>"),
#             ("$..CodeSha256", "<sha-256>"),  # TODO maybe calculate expected has
#             ("$..Owner.DisplayName", "<owner-name>"),
#             ("$..Owner.ID", "<owner-id>"),
#             # TODO *Name
#             ("$..FunctionName", "<function-name>"),
#             ("$..ChangeSetName", "<change-set-name>"),
#             ("$..StackName", "<stack-name>"),
#             ("$..Name", "<name>"),
#             ("$..Contents.ETag", "<etag>"),
#         ]
#         replace_pattern.extend(self.json_path_replacement_list)
#
#         # TODO
#         # self.replace_pattern(
#         #     "$..RequestID.StringValue", replacement="<uuid>", input=input, verify_match=PATTERN_UUID
#         # )
#
#         return super().transform(input)
#
#     def clean_response_metadata(self, input_data: dict):
#         metadata = input_data.get("ResponseMetadata")
#         if not metadata:
#             return
#         http_headers = metadata.get("HTTPHeaders")
#
#         simplified_headers = {}
#         simplified_headers["content-type"] = http_headers["content-type"]
#
#         simplified_metadata = {
#             "HTTPStatusCode": metadata.pop("HTTPStatusCode"),
#             "HTTPHeaders": simplified_headers,
#         }
#         input_data["ResponseMetadata"] = simplified_metadata
