import abc
import copy
from typing import Final

import json5

_LOAD_CACHE: Final[dict[str, dict]] = dict()


class TemplateLoader(abc.ABC):
    @staticmethod
    def load_sfn_template(file_path: str) -> dict:
        template = _LOAD_CACHE.get(file_path)
        if template is None:
            with open(file_path, "r") as df:
                template = json5.load(df)
            _LOAD_CACHE[file_path] = template
        return copy.deepcopy(template)
