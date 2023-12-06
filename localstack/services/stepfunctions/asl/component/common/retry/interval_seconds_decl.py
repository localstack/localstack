from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class IntervalSecondsDecl(Component):
    """
    IntervalSeconds: its value MUST be a positive integer, representing the number of seconds before the
    first retry attempt (default value: 1);
    """

    DEFAULT_SECONDS: Final[int] = 1

    def __init__(self, seconds: int = DEFAULT_SECONDS):
        if seconds < 0:
            raise ValueError(
                f"IntervalSeconds value must be a positive integer, found '{seconds}'."
            )
        self.seconds: Final[int] = seconds
