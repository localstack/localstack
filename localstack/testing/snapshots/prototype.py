import json
import logging
from datetime import datetime
from json import JSONDecodeError
from pathlib import Path
from re import Pattern
from typing import Dict, List, Optional

from botocore.response import StreamingBody
from deepdiff import DeepDiff

from localstack.testing.snapshots.transformer import (
    KeyValueBasedTransformer,
    RegexTransformer,
    TransformContext,
    Transformer,
)
from localstack.testing.snapshots.transformer_utility import TransformerUtility

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

    results: list[SnapshotMatchResult]
    recorded_state: dict[str, dict]  # previously persisted state
    observed_state: dict[str, dict]  # current state from match calls

    called_keys: set[str]
    transformers: list[(Transformer, int)]  # (transformer, priority)

    transform: TransformerUtility

    def __init__(
        self,
        *,
        file_path: str,
        scope_key: str,
        update: Optional[bool] = False,  # TODO: find a way to remove this
        verify: Optional[bool] = False,  # TODO: find a way to remove this
    ):
        self.verify = verify
        self.update = update
        self.file_path = file_path
        self.scope_key = scope_key

        self.called_keys = set()
        self.results = []
        self.transformers = []

        self.observed_state = {}
        self.recorded_state = self._load_state()

        self.transform = TransformerUtility

    def add_transformers_list(self, transformer_list: list[Transformer]):
        for transformer in transformer_list:
            self.transformers.append((transformer, 0))  # TODO

    def add_transformer(self, transformer: Transformer, *, priority: Optional[int] = 0):
        if isinstance(transformer, list):
            self.add_transformers_list(transformer)
        else:
            self.transformers.append((transformer, priority or 0))

    def _persist_state(self) -> None:
        if self.update:
            Path(self.file_path).touch()
            with open(self.file_path, "r+") as fd:
                try:
                    content = fd.read()
                    fd.seek(0)
                    fd.truncate()
                    full_state = json.loads(content or "{}")
                    recorded = {
                        "recorded-date": datetime.now().strftime("%d-%m-%Y, %H:%M:%S"),
                        "recorded-content": self.observed_state,
                    }
                    full_state[self.scope_key] = recorded
                    state_to_dump = json.dumps(full_state, indent=2)
                    fd.write(state_to_dump)
                except Exception as e:
                    LOG.exception(e)

    def _load_state(self) -> dict:
        try:
            with open(self.file_path, "r") as fd:
                content = fd.read()
                if content:
                    recorded = json.loads(content).get(self.scope_key, {})
                    return recorded.get("recorded-content", None)
                else:
                    return {}
        except FileNotFoundError:
            return {}

    def _update(self, key: str, obj_state: dict) -> None:
        self.observed_state[key] = obj_state

    def match(self, key: str, obj: dict) -> None:
        if key in self.called_keys:
            raise Exception(
                f"Key {key} used multiple times in the same test scope"
            )  # TODO: custom exc.

        self.called_keys.add(key)
        self.observed_state[
            key
        ] = obj  # TODO: track them separately since the transformation is now done *just* before asserting

        if not self.update and not self.recorded_state.get(key):
            raise Exception("Please run the test first with --snapshot-update")

    def _assert_all(self) -> List[SnapshotMatchResult]:
        """use after all match calls to get a combined diff"""
        results = []

        if self.update:
            self.observed_state = self._transform(self.observed_state)
            return []

        # TODO: separate these states
        a_all = self.recorded_state
        self.observed_state = b_all = self._transform(self.observed_state)

        for key in self.called_keys:
            a = a_all[key]
            b = b_all[key]
            result = SnapshotMatchResult(a, b, key=key)
            results.append(result)

        if any(not result for result in results) and self.verify:
            raise SnapshotAssertionError("Parity snapshot failed", result=results)
        return results

    def _transform_dict_to_parseable_values(self, original):
        """recursively goes through dict and tries to resolve values to strings (& parse them as json if possible)"""
        for k, v in original.items():
            if isinstance(v, Dict):
                self._transform_dict_to_parseable_values(v)
            if isinstance(v, StreamingBody):
                # update v for json parsing below
                original[k] = v = v.read().decode(
                    "utf-8"
                )  # TODO: patch boto client so this doesn't break any further read() calls

            if isinstance(v, str) and v.startswith("{"):
                try:
                    json_value = json.loads(v)
                    original[k] = json_value
                except JSONDecodeError:
                    pass  # parsing error can be ignored

    def _transform(self, tmp: dict) -> dict:
        """build a persistable state definition that can later be compared against"""
        self._transform_dict_to_parseable_values(tmp)
        ctx = TransformContext()

        for transformer, _ in sorted(self.transformers, key=lambda p: p[1]):
            tmp = transformer.transform(tmp, ctx=ctx)

        tmp = json.dumps(tmp, default=str)
        for sr in ctx.serialized_replacements:
            tmp = sr(tmp)

        assert tmp
        tmp = json.loads(tmp)

        return tmp

    # LEGACY API

    def register_replacement(self, pattern: Pattern[str], value: str):
        self.add_transformer(RegexTransformer(pattern, value))

    def skip_key(self, pattern: Pattern[str], value: str):
        self.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: v if bool(pattern.match(k)) else None,
                replacement=value,
                replace_reference=False,
            )
        )

    def replace_value(self, pattern: Pattern[str], value: str):
        self.add_transformer(
            KeyValueBasedTransformer(
                lambda _, v: v if bool(pattern.match(v)) else None,
                replacement=value,
                replace_reference=False,
            )
        )
