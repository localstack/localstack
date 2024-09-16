from typing import Final

from localstack.services.stepfunctions.asl.component.intrinsic.member import Member


class MemberAccess(Member):
    def __init__(self, subject: Member, target: Member):
        self.subject: Final[Member] = subject
        self.target: Final[Member] = target
