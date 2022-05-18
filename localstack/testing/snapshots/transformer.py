import json
import re
from datetime import datetime
from typing import Dict, List, Tuple

from dateutil import parser as dateutil_parser
from jsonpath_ng.ext import parse

PATTERN_ARN = re.compile(
    r"arn:(aws[a-zA-Z-]*)?:([a-zA-Z0-9-_.]+)?:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?(:[^:\\\"]+)+"
)
PATTERN_UUID = re.compile(
    r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
)
PATTERN_ISO8601 = re.compile(
    r"(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-][01]\d:?([0-5]\d)?)"
)
PATTERN_S3_URL = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}(\+[0-9]{4})?"
)
PATTERN_SQS_URL = re.compile(
    r"https?://[^/]+/\d{12}/[^/\"]+"
)  # TODO: differences here between AWS + localstack structure
PATTERN_HASH_256 = re.compile(r"^[A-Fa-f0-9]{64}$")


class Transformation:
    def __init__(self) -> None:
        super().__init__()
        self.json_path_replacement_list = []

    def transform(self, input: Dict) -> Dict:
        self._replace_json_path_pattern(input)
        return input

    def add_jsonpath_replacement(self, jsonpath, replacement):
        self.json_path_replacement_list.append((jsonpath, replacement))

    def _replace_pattern(
        self,
        json_path,
        replacement,
        input,
        verify_match=None,
    ):
        pattern = parse(json_path)
        for match in pattern.find(input):
            if verify_match and re.match(verify_match, match.value):
                pattern.update(input, replacement)
            elif not verify_match:
                pattern.update(input, replacement)

    def _replace_json_path_pattern(self, input: Dict) -> Dict:
        for (json_path, replace_string) in self.json_path_replacement_list:
            self._replace_pattern(json_path=json_path, replacement=replace_string, input=input)


class LambdaTransformer(Transformation):
    def __init__(self, json_path_replacements: List[Tuple[str, str]] = []) -> None:
        super().__init__(json_path_replacements)

    def transform(self, input: Dict) -> Dict:
        return input


class RegexTransformer(Transformation):
    def __init__(self, json_path_replacements: List[Tuple[str, str]] = []) -> None:
        super().__init__(json_path_replacements)
        self.regex_replacements = []

    def add_replace_regex_pattern(self, regex_string: str, replacement_string: str):
        self.regex_replacements.append((regex_string, replacement_string))
        # self.account_id, "1" * 12, tmp

    def transform(self, input: Dict) -> Dict:
        tmp = json.dumps(input, default=str)
        for regex, replacement in self.regex_replacements:
            result = re.sub(re.compile(regex), replacement, tmp)

        return json.loads(result)


class GenericTransformer(Transformation):
    def __init__(self, json_path_replacements: List[Tuple[str, str]] = []) -> None:
        super().__init__(json_path_replacements)

    def replace_common_values(self, input: Dict) -> Dict:
        for k, v in input.items():
            if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):  # TODO
                for i in range(0, len(v)):
                    v[i] = self.replace_common_values(v[i])
            elif isinstance(v, dict):
                input[k] = self.replace_common_values(v)
            elif isinstance(v, datetime):
                input[k] = "<date>"
            elif isinstance(v, str):
                if re.match(PATTERN_ARN, v):
                    input[k] = "<arn>"
                elif (
                    "modified" in k.lower() or "date" in k.lower() or "time" in k.lower()
                ) and self._is_date(
                    v
                ):  # TODO
                    input[k] = "<date>"
                elif k.lower().endswith("id") and re.match(PATTERN_UUID, v):
                    input[k] = "<uuid>"

        return input

    def _is_date(self, value: str):
        try:
            # TODO seems like the date can have various formats, use this dateutil lib?
            dateutil_parser.parse(value)
            return True
        except Exception:
            return False

    def transform(self, input: Dict) -> Dict:
        self.clean_response_metadata(input)
        replace_pattern = [
            ("$..Code.Location", "<location>"),
            ("$..CodeSha256", "<sha-256>"),  # TODO maybe calculate expected has
            ("$..Owner.DisplayName", "<owner-name>"),
            ("$..Owner.ID", "<owner-id>"),
            # TODO *Name
            ("$..FunctionName", "<function-name>"),
            ("$..ChangeSetName", "<change-set-name>"),
            ("$..StackName", "<stack-name>"),
            ("$..Name", "<name>"),
            ("$..Contents.ETag", "<etag>"),
        ]
        replace_pattern.extend(self.json_path_replacement_list)
        for (json_path, replace_string) in replace_pattern:
            self.replace_pattern(json_path=json_path, replacement=replace_string, input=input)

        # TODO
        # self.replace_pattern(
        #     "$..RequestID.StringValue", replacement="<uuid>", input=input, verify_match=PATTERN_UUID
        # )

        self.replace_common_values(input)
        return input

    def clean_response_metadata(self, input: Dict):
        metadata = input.get("ResponseMetadata")
        if not metadata:
            return
        http_headers = metadata.get("HTTPHeaders")

        simplified_headers = {}
        simplified_headers["content-type"] = http_headers["content-type"]

        simplified_metadata = {
            "HTTPStatusCode": metadata.pop("HTTPStatusCode"),
            "HTTPHeaders": simplified_headers,
        }
        input["ResponseMetadata"] = simplified_metadata
