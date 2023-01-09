import json

from jsonpath_ng import parse


class JSONPathUtils:
    @staticmethod
    def extract_json(path: str, data: json) -> json:
        input_expr = parse(path)
        find_res = input_expr.find(data)
        if isinstance(find_res, list):
            value = find_res[0].value
        else:
            value = find_res
        return value
