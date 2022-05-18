import json
import logging
from pathlib import Path
from re import Pattern
from typing import Dict, List, Optional, Set, Tuple

from botocore.response import StreamingBody
from deepdiff import DeepDiff

from localstack.testing.snapshots.transformer import (
    KeyValueBasedDirectTransformer,
    RegexTransformer,
    Transformation,
    TransformContext,
)

LOG = logging.getLogger(__name__)


class SnapshotMatchResult:
    def __init__(self, a: dict, b: dict, key: str = ""):
        self.a = a
        self.b = b
        self.result = DeepDiff(a, b, verbose_level=2)
        self.key = key

    def __bool__(self) -> bool:
        return not self.result

    def __repr__(self):
        return self.result.pretty()


class SnapshotAssertionError(AssertionError):
    def __init__(self, msg: str, result: List[SnapshotMatchResult]):
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
    jsonpath_replacement: List[Tuple[str, str]]
    transformer_list: List[Transformation]

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

        self.observed_state = {}
        self.recorded_state = self.load_state()

        self.jsonpath_replacement = []
        self.transformer_list = []

    def add_transformer(self, transformer: Transformation):
        self.transformer_list.append(transformer)

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

        return SnapshotMatchResult(sub_state, obj_state, key=key)

    def assert_all(self) -> List[SnapshotMatchResult]:
        """use after any assert_match calls to get a combined diff"""
        results = []
        for key in self.called_keys:
            a = self.recorded_state[key]
            b = self.observed_state[key]
            result = SnapshotMatchResult(a, b, key=key)

            results.append(result)

        if any(not result for result in results) and self.verify:
            raise SnapshotAssertionError("Parity snapshot failed", result=results)
        return results

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

    def _transform(self, tmp: dict) -> dict:
        """build a persistable state definition that can later be compared against"""
        self._transform_dict_to_parseable_values(tmp)
        ctx = TransformContext()

        for transformer in self.transformer_list:
            tmp = transformer.transform(tmp, ctx=ctx)

        tmp = json.dumps(tmp)
        for sr in ctx.serialized_replacements:
            tmp = sr(tmp)
        tmp = json.loads(tmp)

        return tmp

    # LEGACY API

    def register_replacement(self, pattern: Pattern[str], value: str):
        self.add_transformer(RegexTransformer(pattern, value))

    def skip_key(self, pattern: Pattern[str], value: str):
        self.add_transformer(
            KeyValueBasedDirectTransformer(lambda k, _: bool(pattern.match(k)), replacement=value)
        )

    def replace_value(self, pattern: Pattern[str], value: str):
        self.add_transformer(
            KeyValueBasedDirectTransformer(lambda _, v: bool(pattern.match(v)), replacement=value)
        )
