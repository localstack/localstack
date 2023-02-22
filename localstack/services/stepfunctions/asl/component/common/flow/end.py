from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class End(Component):
    def __init__(self, is_end: bool):
        # Designates this state as a terminal state (ends the execution) if set to true.
        self.is_end: Final[bool] = is_end
