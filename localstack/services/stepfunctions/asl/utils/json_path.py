import json

from jsonpath_ng.ext import parse
from jsonpath_ng.jsonpath import Index

from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class JSONPathUtils:
    @staticmethod
    def extract_json(path: str, data: json) -> json:
        input_expr = parse(path)

        matches = input_expr.find(data)
        if not matches:
            raise RuntimeError(
                f"The JSONPath {path} could not be found in the input {to_json_str(data)}"
            )

        if len(matches) > 1 or isinstance(matches[0].path, Index):
            value = [match.value for match in matches]
        else:
            value = matches[0].value

        return value
