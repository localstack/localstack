import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from botocore.response import StreamingBody
from deepdiff import DeepDiff
from jsonpath_ng.ext import parse

LOG = logging.getLogger(__name__)


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


class SnapshotMatchResult:
    def __init__(self, a: dict, b: dict, jsonpath_replacements: List[Tuple[str, str]] = []):
        self.a = a
        self.b = b
        for (path, replacement) in jsonpath_replacements:
            pattern = parse(path)
            if pattern.find(a):
                pattern.update(a, replacement)
            if pattern.find(b):
                pattern.update(b, replacement)
        self.result = DeepDiff(a, b, verbose_level=2)

    def __bool__(self) -> bool:
        return not self.result

    def __repr__(self):
        return self.result.pretty()


class SnapshotAssertionError(AssertionError):
    def __init__(self, msg: str, result: SnapshotMatchResult):
        self.msg = msg
        self.result = result
        super(SnapshotAssertionError, self).__init__(msg)


class Transformation:
    def replace_pattern(
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

    def replace_common_values(self, input: Dict) -> Dict:
        for k, v in input.items():
            if isinstance(v, dict):
                input[k] = self.replace_common_values(v)
            if isinstance(v, datetime):
                input[k] = "<date>"
            if isinstance(v, str):
                if re.match(PATTERN_ARN, v):
                    input[k] = "<arn>"
                if "modified" in k.lower() and re.match(PATTERN_ISO8601, v):  # TODO
                    input[k] = "<date>"
                if k.lower().endswith("id") and re.match(PATTERN_UUID, v):
                    input[k] = "<uuid>"

        return input

    def transform(self, input: Dict) -> Dict:
        self.clean_response_metadata(input)
        self.replace_pattern(
            "$..RequestID.StringValue", replacement="<uuid>", input=input, verify_match=PATTERN_UUID
        )
        self.replace_pattern("$..Code.Location", replacement="<location>", input=input)
        self.replace_pattern(
            "$..CodeSha256", replacement="<sha-256>", input=input
        )  # TODO maybe calculate expected hash?
        self.replace_common_values(input)

    def clean_response_metadata(self, input: Dict):
        metadata = input.get("ResponseMetadata")
        if not metadata:
            return
        http_headers = metadata.get("HTTPHeaders")

        simplified_headers = {}
        simplified_headers["content-type"] = http_headers["content-type"]
        # simplified_headers['content-length'] = http_headers['content-length']
        # if http_headers.get('content-md5'):
        #    simplified_headers['content-md5'] = http_headers['content-md5']

        simplified_metadata = {
            "HTTPStatusCode": metadata.pop("HTTPStatusCode"),
            "HTTPHeaders": simplified_headers,
        }
        input["ResponseMetadata"] = simplified_metadata


class SnapshotSession:
    """
    snapshot handler for a single test function with potentially multiple assertions\
    Since it technically only  modifies a subset of the underlying snapshot file,
    it assumes that a single snapshot file is only being written to sequentially
    """

    results: List[SnapshotMatchResult]
    recorded_state: Dict[str, dict]
    observed_state: Dict[str, dict]

    called_keys: Set[str]
    jsonpath_replacement: List[Tuple[str, str]]
    transformer: Transformation

    def __init__(
        self,
        *,
        file_path: str,
        scope_key: str,
        update: Optional[bool] = False,
        verify: Optional[bool] = False,
    ):
        self.verify = verify
        self.update = update
        self.file_path = file_path
        self.scope_key = scope_key
        self.called_keys = set()
        self.results = []
        self.account_id = ""

        self.observed_state = {}
        self.recorded_state = self.load_state()

        self.jsonpath_replacement = []
        self.transformer = Transformation()

    def register_account_id(self, account_id: str):
        self.account_id = account_id

    def replace_jsonpath_value(self, jsonpath: str, replacement: str):
        self.jsonpath_replacement.append((jsonpath, replacement))

    def persist_state(self) -> None:
        if self.update:
            Path(self.file_path).touch()
            # replacing sensitive information here: account-id TODO maybe others
            tmp = json.dumps(self.observed_state, default=str)
            result = re.sub(re.compile(self.account_id), "1" * 12, tmp)
            self.observed_state = json.loads(result)
            with open(self.file_path, "r+") as fd:
                try:
                    content = fd.read()
                    fd.seek(0)
                    fd.truncate()
                    full_state = json.loads(content or "{}")

                    full_state[self.scope_key] = self.observed_state
                    fd.write(json.dumps(full_state, indent=2))
                except Exception as e:
                    LOG.exception(e)

    def load_state(self) -> dict:
        try:
            with open(self.file_path, "r") as fd:
                content = fd.read()
                if content:
                    return json.loads(content).get(self.scope_key, {})
                else:
                    return {}
        except FileNotFoundError:
            return {}

    def _update(self, key: str, obj_state: dict) -> None:
        self.observed_state[key] = obj_state

    def match(self, key: str, obj: dict) -> SnapshotMatchResult:
        __tracebackhide__ = True

        if key in self.called_keys:
            raise Exception(f"Key {key} used multiple times in the same test scope")
        self.called_keys.add(key)

        obj_state = self._transform(obj)
        self.observed_state[key] = obj_state

        if self.update:
            self._update(key, obj_state)
            return SnapshotMatchResult({}, {})

        sub_state = self.recorded_state.get(key)
        if sub_state is None:
            raise Exception("Please run the test first with --snapshot-update")

        return SnapshotMatchResult(sub_state, obj_state, self.jsonpath_replacement)

    def assert_all(self) -> SnapshotMatchResult:
        """use after any assert_match calls to get a combined diff"""
        result = SnapshotMatchResult(self.recorded_state, self.observed_state)
        if not result and self.verify:
            raise SnapshotAssertionError("Parity snapshot failed", result=result)
        else:
            return result

    def _transform_dict_to_parseable_values(self, original):
        for k, v in original.items():
            if isinstance(v, Dict):
                self._transform_dict_to_parseable_values(v)
            if isinstance(v, StreamingBody):
                original[k] = v.read().decode("utf-8")
            if isinstance(v, str) and v.startswith("{"):
                try:
                    json_value = json.loads(v)
                    original[k] = json_value
                except Exception:
                    pass
                    # parsing error can be ignored

    def _transform(self, obj: dict) -> dict:
        """build a persistable state definition that can later be compared against"""
        self.transformer.transform(obj)
        self._transform_dict_to_parseable_values(obj)
        return obj
