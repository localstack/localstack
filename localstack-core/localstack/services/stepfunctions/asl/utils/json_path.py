import re
from typing import Any, Final, Optional

from jsonpath_ng.ext import parse
from jsonpath_ng.jsonpath import Index

from localstack.services.events.utils import to_json_str

_PATTERN_SINGLETON_ARRAY_ACCESS_OUTPUT: Final[str] = r"\[\d+\]$"


def _is_singleton_array_access(path: str) -> bool:
    # Returns true if the json path terminates with a literal singleton array access.
    return bool(re.search(_PATTERN_SINGLETON_ARRAY_ACCESS_OUTPUT, path))


class NoSuchJsonPathError(Exception):
    json_path: Final[str]
    data: Final[Any]
    _message: Optional[str]

    def __init__(self, json_path: str, data: Any):
        self.json_path = json_path
        self.data = data
        self._message = None

    @property
    def message(self) -> str:
        if self._message is None:
            data_json_str = to_json_str(self.data)
            self._message = (
                f"The JSONPath '{self.json_path}' could not be found in the input '{data_json_str}'"
            )
        return self._message

    def __str__(self):
        return self.message


def extract_json(path: str, data: Any) -> Any:
    input_expr = parse(path)

    matches = input_expr.find(data)
    if not matches:
        raise NoSuchJsonPathError(json_path=path, data=data)

    if len(matches) > 1 or isinstance(matches[0].path, Index):
        value = [match.value for match in matches]

        # AWS StepFunctions breaks jsonpath specifications and instead
        # unpacks literal singleton array accesses.
        if _is_singleton_array_access(path=path) and len(value) == 1:
            value = value[0]
    else:
        value = matches[0].value

    return value
