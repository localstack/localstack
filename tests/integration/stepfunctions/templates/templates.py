import copy
import os
from typing import Final

import json5

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))
BASE_INVALID_DER: Final[str] = os.path.join(_THIS_FOLDER, "base/invalid_der.json5")
BASE_PASS_RESULT: Final[str] = os.path.join(_THIS_FOLDER, "base/pass_result.json5")
BASE_TASK_SEQ_2: Final[str] = os.path.join(_THIS_FOLDER, "base/task_seq_2.json5")
BASE_WAIT_1_MIN: Final[str] = os.path.join(_THIS_FOLDER, "base/wait_1_min.json5")

_LOAD_CACHE: Final[dict[str, dict]] = dict()


def load_sfn_template(file_path: str) -> dict:
    template = _LOAD_CACHE.get(file_path)
    if template is None:
        with open(file_path, "r") as df:
            template = json5.load(df)
        _LOAD_CACHE[file_path] = template
    return copy.deepcopy(template)
