from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class MaxAttemptsDecl(Component):
    """
    "MaxAttempts": value MUST be a non-negative integer, representing the maximum number
    of retry attempts (default: 3)
    """

    DEFAULT_ATTEMPTS: Final[int] = 3

    def __init__(self, attempts: int = DEFAULT_ATTEMPTS):
        if attempts < 0:
            raise ValueError(f"MaxAttempts value MUST be a non-negative integer, got '{attempts}'.")
        self.attempts: Final[int] = attempts
