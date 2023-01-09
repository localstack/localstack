from enum import Enum

from localstack.services.stepfunctions.asl.antlr.gen.ASLLexer import ASLLexer


class StateType(Enum):
    Task = ASLLexer.TASK
    Pass = ASLLexer.PASS
    Choice = ASLLexer.CHOICE
    Fail = ASLLexer.FAIL
    Succeed = ASLLexer.SUCCEED
    Wait = ASLLexer.WAIT
    Map = ASLLexer.MAP
    Parallel = ASLLexer.PARALLEL
