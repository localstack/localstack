import abc

from antlr4 import CommonTokenStream, InputStream

from localstack.services.stepfunctions.asl.antlr.runtime.LSLLexer import LSLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.LSLParser import LSLParser
from localstack.services.stepfunctions.asl.parse.lsl.transpiler import Transpiler


class LocalStackStateLanguageParser(abc.ABC):
    @staticmethod
    def parse(definition: str) -> dict:
        input_stream = InputStream(definition)
        lexer = LSLLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = LSLParser(stream)
        tree = parser.state_machine()
        transpiler = Transpiler()
        transpiler.visit(tree)
        workflow = transpiler.get_workflow()
        return workflow
