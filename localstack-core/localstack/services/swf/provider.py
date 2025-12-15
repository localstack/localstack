from abc import ABC

from localstack.aws.api.swf import SwfApi
from localstack.state import StateVisitor


class SWFProvider(SwfApi, ABC):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.swf.models import swf_backends

        visitor.visit(swf_backends)
