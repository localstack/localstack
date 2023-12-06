from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class BackoffRateDecl(Component):
    """
    "BackoffRate": a number which is the multiplier that increases the retry interval on each
    attempt (default: 2.0). The value of BackoffRate MUST be greater than or equal to 1.0.
    """

    DEFAULT_RATE: Final[float] = 2.0
    MIN_RATE: Final[float] = 1.0

    def __init__(self, rate: float = DEFAULT_RATE):
        if rate < self.MIN_RATE:
            raise ValueError(
                f"The value of BackoffRate MUST be greater than or equal to 1.0, got '{rate}'."
            )
        self.rate: Final[float] = rate
