import abc

from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParserVisitor import (
    ASLIntrinsicParserVisitor,
)
from localstack.services.stepfunctions.asl.parse.intrinsic.intrinsic_parser import IntrinsicParser


class IntrinsicStaticAnalyser(ASLIntrinsicParserVisitor, abc.ABC):
    def analyse(self, definition: str) -> None:
        _, parser_rule_context = IntrinsicParser.parse(definition)
        self.visit(parser_rule_context)
