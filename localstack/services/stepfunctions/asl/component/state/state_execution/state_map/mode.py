from enum import Enum

from antlr4.localstack.services.stepfunctions.asl.antlr.ASLLexer import ASLLexer


class Mode(Enum):
    Inline = ASLLexer.INLINE
