import abc
from typing import Final

from antlr4 import CommonTokenStream, InputStream, ParserRuleContext
from antlr4.error.ErrorListener import ErrorListener

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.parse.preprocessor import Preprocessor


class SyntaxErrorListener(ErrorListener):
    errors: Final[list[str]]

    def __init__(self):
        super().__init__()
        self.errors = list()

    def syntaxError(self, recognizer, offending_symbol, line, column, message, exception):
        log_parts = [f"line {line}:{column}"]
        if offending_symbol is not None and offending_symbol.text:
            log_parts.append(f"at {offending_symbol.text}")
        if message:
            log_parts.append(message)
        error_log = ", ".join(log_parts)
        self.errors.append(error_log)


class ASLParserException(Exception):
    errors: Final[list[str]]

    def __init__(self, errors: list[str]):
        self.errors = errors

    def __str__(self):
        return repr(self)

    def __repr__(self):
        if not self.errors:
            error_str = "No error details available"
        elif len(self.errors) == 1:
            error_str = self.errors[0]
        else:
            error_str = str(self.errors)
        return f"ASLParserException {error_str}"


class AmazonStateLanguageParser(abc.ABC):
    @staticmethod
    def parse(definition: str) -> tuple[EvalComponent, ParserRuleContext]:
        # Attempt to build the AST and look out for syntax errors.
        syntax_error_listener = SyntaxErrorListener()

        input_stream = InputStream(definition)
        lexer = ASLLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = ASLParser(stream)
        parser.removeErrorListeners()
        parser.addErrorListener(syntax_error_listener)
        tree = parser.state_machine()

        errors = syntax_error_listener.errors
        if errors:
            raise ASLParserException(errors=errors)

        # Attempt to preprocess the AST into evaluation components.
        preprocessor = Preprocessor()
        program = preprocessor.visit(tree)

        return program, tree
