from __future__ import annotations

import abc
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.component import Component


class ErrorName(Component, abc.ABC):
    error_name: Final[Optional[str]]

    def __init__(self, error_name: Optional[str]):
        self.error_name = error_name

    def matches(self, error_name: Optional[str]) -> bool:
        return self.error_name == error_name

    def __eq__(self, other):
        if isinstance(other, ErrorName):
            return self.matches(other.error_name)
        return False
