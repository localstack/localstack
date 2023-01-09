from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class Comment(Component):
    def __init__(self, comment: str):
        self.comment: Final[str] = comment
