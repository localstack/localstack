import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set, Tuple

from botocore.response import StreamingBody
from deepdiff import DeepDiff

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


class SnapshotMatchResult:
    def __init__(self, a: dict, b: dict):
        self.a = a
        self.b = b
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

    replacers: List[Tuple[Pattern[str], str]]
    skip_keys: List[Tuple[Pattern[str], str]]
    replace_values: List[Tuple[Pattern[str], str]]

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
        self.replacers = []
        self.skip_keys = []
        self.replace_values = []
        self.results = []

        self.observed_state = {}
        self.recorded_state = self.load_state()

        # registering some defaults
        self.register_replacement(PATTERN_ARN, "<arn>")
        self.register_replacement(PATTERN_UUID, "<uuid>")
        self.register_replacement(PATTERN_ISO8601, "<date>")
        # self.register_replacement(PATTERN_S3_URL, "<s3-url>")
        self.register_replacement(PATTERN_SQS_URL, "<sqs-url>")

        self.skip_key(re.compile(r"^.*Name$"), "<name>")
        self.skip_key(re.compile(r"^.*ResponseMetadata$"), "<response-metadata>")
        self.skip_key(re.compile(r"^.*Location$"), "<location>")
        self.skip_key(re.compile(r"^.*timestamp.*$", flags=re.IGNORECASE), "<timestamp>")
        self.skip_key(
            re.compile(r"^.*sha.*$", flags=re.IGNORECASE), "<sha>"
        )  # TODO: instead of skipping, make zip building reproducible

    def register_replacement(self, pattern: Pattern[str], value: str):
        self.replacers.append((pattern, value))

    def skip_key(self, pattern: Pattern[str], value: str):
        self.skip_keys.append((pattern, value))

    def replace_value(self, pattern: Pattern[str], value: str):
        self.replace_values.append((pattern, value))

    def persist_state(self) -> None:
        if self.update:
            Path(self.file_path).touch()
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

        return SnapshotMatchResult(sub_state, obj_state)

    def assert_all(self) -> SnapshotMatchResult:
        """use after any assert_match calls to get a combined diff"""
        result = SnapshotMatchResult(self.recorded_state, self.observed_state)
        if not result and self.verify:
            raise SnapshotAssertionError("Parity snapshot failed", result=result)
        else:
            return result

    def _transform(self, old: dict) -> dict:
        """build a persistable state definition that can later be compared against"""

        new_dict = {}
        for k, v in old.items():

            for (pattern, repl) in self.skip_keys:
                if pattern.match(k):
                    new_dict[k] = repl
                    break
            else:
                if isinstance(v, dict):
                    new_dict[k] = self._transform(v)
                elif isinstance(v, list):
                    # assumption: no nested lists in API calls
                    new_list = []
                    for i in v:
                        if isinstance(i, dict):
                            new_list.append(self._transform(i))
                        elif isinstance(i, str):
                            new_list.append(i)
                        else:  # assumption: has to be an int or boolean
                            new_list.append(v)
                    new_dict[k] = new_list
                elif isinstance(v, str):
                    for (pattern, repl) in self.replace_values:
                        if pattern.match(v):
                            new_dict[k] = repl
                            break
                    else:
                        new_dict[k] = v
                elif isinstance(v, StreamingBody):
                    new_dict[k] = v.read().decode("utf-8")
                elif isinstance(
                    v, datetime
                ):  # TODO: remove when structural matching is implemented
                    new_dict[k] = "<date>"
                else:
                    new_dict[k] = v

        tmp_str = json.dumps(new_dict)
        for (pattern, repl) in self.replacers:
            tmp_str = re.sub(pattern, repl, tmp_str)

        return json.loads(tmp_str)
