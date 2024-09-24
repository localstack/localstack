from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class StartAt(Component):
    def __init__(self, start_at_name: str):
        self.start_at_name: Final[str] = start_at_name
