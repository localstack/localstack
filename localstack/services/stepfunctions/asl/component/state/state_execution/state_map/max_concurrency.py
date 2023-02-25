from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class MaxConcurrency(Component):

    DEFAULT: Final[int] = 0  # No limit.

    def __init__(self, num: int = DEFAULT):
        self.num: Final[int] = num
