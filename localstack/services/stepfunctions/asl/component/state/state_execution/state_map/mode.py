from enum import Enum

from localstack.services.stepfunctions.asl.antlr.gen.ASLLexer import ASLLexer


class Mode(Enum):
    Inline = ASLLexer.INLINE
