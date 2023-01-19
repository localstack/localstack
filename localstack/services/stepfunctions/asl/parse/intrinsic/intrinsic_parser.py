import abc

from antlr4 import CommonTokenStream, InputStream

from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicLexer import ASLIntrinsicLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParser import (
    ASLIntrinsicParser,
)
from localstack.services.stepfunctions.asl.component.intrinsic.program import Program
from localstack.services.stepfunctions.asl.parse.intrinsic.preprocessor import Preprocessor


class IntrinsicParser(abc.ABC):
    @staticmethod
    def parse(src: str) -> Program:
        input_stream = InputStream(src)
        lexer = ASLIntrinsicLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = ASLIntrinsicParser(stream)
        tree = parser.compilation_unit()
        preprocessor = Preprocessor()
        program = preprocessor.visit(tree)
        return program
