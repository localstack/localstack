from antlr4 import CommonTokenStream, InputStream, ParserRuleContext

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.parse.asl_parser import (
    AmazonStateLanguageParser,
    ASLParserException,
    SyntaxErrorListener,
)
from localstack.services.stepfunctions.asl.parse.test_state.preprocessor import (
    TestStatePreprocessor,
)


class TestStateAmazonStateLanguageParser(AmazonStateLanguageParser):
    @staticmethod
    def parse(
        definition: str, state_name: str | None = None
    ) -> tuple[EvalComponent, ParserRuleContext]:
        # Attempt to build the AST and look out for syntax errors.
        syntax_error_listener = SyntaxErrorListener()

        input_stream = InputStream(definition)
        lexer = ASLLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = ASLParser(stream)
        parser.removeErrorListeners()
        parser.addErrorListener(syntax_error_listener)

        tree = parser.state_machine() if state_name else parser.state_decl_body()
        errors = syntax_error_listener.errors
        if errors:
            raise ASLParserException(errors=errors)

        # Attempt to preprocess the AST into evaluation components.
        preprocessor = TestStatePreprocessor()
        test_state_program = preprocessor.to_test_state_program(tree, state_name)

        return test_state_program, tree
