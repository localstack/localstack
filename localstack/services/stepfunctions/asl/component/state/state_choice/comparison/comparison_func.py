from __future__ import annotations

import json
from enum import Enum
from typing import Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_stmt import (
    ComparisonStmt,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.variable import NoSuchVariable
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ComparisonFunc(ComparisonStmt):
    class ComparisonOperator(Enum):
        BooleanEqual = ASLLexer.BOOLEANEQUALS
        BooleanEqualsPath = ASLLexer.BOOLEANQUALSPATH
        IsBoolean = ASLLexer.ISBOOLEAN
        IsNull = ASLLexer.ISNULL
        IsNumeric = ASLLexer.ISNUMERIC
        IsPresent = ASLLexer.ISPRESENT
        IsString = ASLLexer.ISSTRING
        IsTimestamp = ASLLexer.ISTIMESTAMP
        NumericEquals = ASLLexer.NUMERICEQUALS
        NumericEqualsPath = ASLLexer.NUMERICEQUALSPATH
        NumericGreaterThan = ASLLexer.NUMERICGREATERTHAN
        NumericGreaterThanPath = ASLLexer.NUMERICGREATERTHANPATH
        NumericGreaterThanEquals = ASLLexer.NUMERICGREATERTHANEQUALS
        NumericGreaterThanEqualsPath = ASLLexer.NUMERICGREATERTHANEQUALSPATH
        NumericLessThan = ASLLexer.NUMERICLESSTHAN
        NumericLessThanPath = ASLLexer.NUMERICLESSTHANPATH
        NumericLessThanEquals = ASLLexer.NUMERICLESSTHANEQUALS
        NumericLessThanEqualsPath = ASLLexer.NUMERICLESSTHANEQUALSPATH
        StringEquals = ASLLexer.STRINGEQUALS
        StringEqualsPath = ASLLexer.STRINGEQUALSPATH
        StringGreaterThan = ASLLexer.STRINGGREATERTHAN
        StringGreaterThanPath = ASLLexer.STRINGGREATERTHANPATH
        StringGreaterThanEquals = ASLLexer.STRINGGREATERTHANEQUALS
        StringGreaterThanEqualsPath = ASLLexer.STRINGGREATERTHANEQUALSPATH
        StringLessThan = ASLLexer.STRINGLESSTHAN
        StringLessThanPath = ASLLexer.STRINGLESSTHANPATH
        StringLessThanEquals = ASLLexer.STRINGLESSTHANEQUALS
        StringLessThanEqualsPath = ASLLexer.STRINGLESSTHANEQUALSPATH
        StringMatches = ASLLexer.STRINGMATCHES
        TimestampEquals = ASLLexer.TIMESTAMPEQUALS
        TimestampEqualsPath = ASLLexer.TIMESTAMPEQUALSPATH
        TimestampGreaterThan = ASLLexer.TIMESTAMPGREATERTHAN
        TimestampGreaterThanPath = ASLLexer.TIMESTAMPGREATERTHANPATH
        TimestampGreaterThanEquals = ASLLexer.TIMESTAMPGREATERTHANEQUALS
        TimestampGreaterThanEqualsPath = ASLLexer.TIMESTAMPGREATERTHANEQUALSPATH
        TimestampLessThan = ASLLexer.TIMESTAMPLESSTHAN
        TimestampLessThanPath = ASLLexer.TIMESTAMPLESSTHANPATH
        TimestampLessThanEquals = ASLLexer.TIMESTAMPLESSTHANEQUALS
        TimestampLessThanEqualsPath = ASLLexer.TIMESTAMPLESSTHANEQUALSPATH

        def __str__(self):
            return f"({self.__class__.__name__}| {self})"

    def __init__(self, operator: ComparisonFunc.ComparisonOperator, value: json):
        self.operator: Final[ComparisonFunc.ComparisonOperator] = operator
        self.value: json = value

    def _eval_body(self, env: Environment) -> None:
        value = self.value
        match self.operator:
            case ComparisonFunc.ComparisonOperator.IsNull:
                self._is_null(env, value)
            case ComparisonFunc.ComparisonOperator.StringEquals:
                self._string_equals(env, value)
            case ComparisonFunc.ComparisonOperator.IsPresent:
                self._is_present(env)
            # TODO: add other operators.
            case x:
                raise NotImplementedError(f"ComparisonFunc '{x}' is not supported yet.")  # noqa

    @staticmethod
    def _is_null(env: Environment, value: json) -> None:
        if not isinstance(value, bool):
            raise RuntimeError(f"Unexpected binding to IsNull: '{value}'.")
        val = env.stack.pop()
        is_null = val is None and not isinstance(
            val, NoSuchVariable
        )  # TODO: what if input_state is empty, eg. "" or {}?
        res = is_null == value
        env.stack.append(res)

    @staticmethod
    def _string_equals(env: Environment, value: json) -> None:
        val = env.stack.pop()
        res = str(val) == value
        env.stack.append(res)

    @staticmethod
    def _is_present(env: Environment) -> None:
        val = env.stack.pop()
        res = not isinstance(val, NoSuchVariable)
        env.stack.append(res)
