from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class Label(Component):
    def __init__(self, label: str = ""):
        self.label: Final[str] = label
