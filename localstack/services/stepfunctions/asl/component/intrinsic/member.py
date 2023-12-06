from typing import Final

from localstack.services.stepfunctions.asl.component.intrinsic.component import Component


class Member(Component):
    ...


class IdentifiedMember(Member):
    def __init__(self, identifier: str):
        self.identifier: Final[str] = identifier


class DollarMember(IdentifiedMember):
    def __init__(self):
        super(DollarMember, self).__init__(identifier="$")
