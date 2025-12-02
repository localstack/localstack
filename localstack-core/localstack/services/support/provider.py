from abc import ABC

from localstack.aws.api.support import SupportApi
from localstack.state import StateVisitor


class SupportProvider(SupportApi, ABC):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.support.models import support_backends

        visitor.visit(support_backends)
