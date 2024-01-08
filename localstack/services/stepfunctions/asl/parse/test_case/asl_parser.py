from antlr4 import CommonTokenStream, InputStream

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.test_case.test_case_program import (
    TestCaseProgram,
)
from localstack.services.stepfunctions.asl.parse.asl_parser import (
    AmazonStateLanguageParser,
    ASLParserException,
    SyntaxErrorListener,
)
from localstack.services.stepfunctions.asl.parse.test_case.preprocessor import TestCasePreprocessor

ASLParseTree = ASLParser.Program_declContext


class TestCaseAmazonStateLanguageParser(AmazonStateLanguageParser):
    @staticmethod
    def parse(src: str) -> tuple[TestCaseProgram, ASLParseTree]:
        # Attempt to build the AST and look out for syntax errors.
        syntax_error_listener = SyntaxErrorListener()

        input_stream = InputStream(src)
        lexer = ASLLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = ASLParser(stream)
        parser.removeErrorListeners()
        parser.addErrorListener(syntax_error_listener)
        tree = parser.state_decl_body()

        errors = syntax_error_listener.errors
        if errors:
            raise ASLParserException(errors=errors)

        # Attempt to preprocess the AST into evaluation components.
        preprocessor = TestCasePreprocessor()
        test_case_program = preprocessor.visit(tree)

        return test_case_program
