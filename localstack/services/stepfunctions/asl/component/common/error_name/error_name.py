from __future__ import annotations

import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class ErrorName(Component, abc.ABC):
    def __init__(self, error_name: str):
        self.error_name: Final[str] = error_name

    def matches(self, error_name: str) -> bool:
        return self.error_name == error_name

    def __eq__(self, other):
        if isinstance(other, ErrorName):
            return self.matches(other.error_name)
        return False
