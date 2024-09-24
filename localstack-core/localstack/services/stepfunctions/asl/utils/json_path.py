import json
import re
from typing import Final

from jsonpath_ng.ext import parse
from jsonpath_ng.jsonpath import Index

from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

_PATTERN_SINGLETON_ARRAY_ACCESS_OUTPUT: Final[str] = r"\[\d+\]$"


def _is_singleton_array_access(path: str) -> bool:
    # Returns true if the json path terminates with a literal singleton array access.
    return bool(re.search(_PATTERN_SINGLETON_ARRAY_ACCESS_OUTPUT, path))


def extract_json(path: str, data: json) -> json:
    input_expr = parse(path)

    matches = input_expr.find(data)
    if not matches:
        raise RuntimeError(
            f"The JSONPath {path} could not be found in the input {to_json_str(data)}"
        )

    if len(matches) > 1 or isinstance(matches[0].path, Index):
        value = [match.value for match in matches]

        # AWS StepFunctions breaks jsonpath specifications and instead
        # unpacks literal singleton array accesses.
        if _is_singleton_array_access(path=path) and len(value) == 1:
            value = value[0]
    else:
        value = matches[0].value

    return value
