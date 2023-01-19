import abc

from antlr4 import CommonTokenStream, InputStream

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.parse.preprocessor import Preprocessor


class AmazonStateLanguageParser(abc.ABC):
    @staticmethod
    def parse(src: str) -> Program:
        input_stream = InputStream(src)
        lexer = ASLLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = ASLParser(stream)
        tree = parser.program_decl()
        preprocessor = Preprocessor()
        program = preprocessor.visit(tree)
        return program
