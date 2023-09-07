import json

from jsonpath_ng import parse

from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class JSONPathUtils:
    @staticmethod
    def extract_json(path: str, data: json) -> json:
        input_expr = parse(path)
        find_res = [match.value for match in input_expr.find(data)]
        if find_res == list():
            raise RuntimeError(
                f"The JSONPath '{path}' could not be found in the input '{to_json_str(data)}'"
            )
        if len(find_res) == 1:
            value = find_res[0]
        else:
            value = find_res
        return value
