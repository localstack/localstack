from enum import Enum

from antlr4.localstack.services.stepfunctions.asl.antlr.ASLLexer import ASLLexer


class StateType(Enum):
    Task = ASLLexer.TASK
    Pass = ASLLexer.PASS
    Choice = ASLLexer.CHOICE
    Fail = ASLLexer.FAIL
    Succeed = ASLLexer.SUCCEED
    Wait = ASLLexer.WAIT
    Map = ASLLexer.MAP
    Parallel = ASLLexer.PARALLEL
