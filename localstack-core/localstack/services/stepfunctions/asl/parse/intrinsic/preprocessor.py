import re
from typing import Optional

from antlr4.tree.Tree import ParseTree, TerminalNodeImpl

from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicLexer import ASLIntrinsicLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParser import (
    ASLIntrinsicParser,
)
from localstack.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParserVisitor import (
    ASLIntrinsicParserVisitor,
)
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import Antlr4Utils
from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument import (
    FunctionArgument,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_bool import (
    FunctionArgumentBool,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_context_path import (
    FunctionArgumentContextPath,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_float import (
    FunctionArgumentFloat,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_function import (
    FunctionArgumentFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_int import (
    FunctionArgumentInt,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_json_path import (
    FunctionArgumentJsonPath,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_string import (
    FunctionArgumentString,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.factory import (
    StatesFunctionFactory,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)


class Preprocessor(ASLIntrinsicParserVisitor):
    @staticmethod
    def _replace_escaped_characters(match):
        escaped_char = match.group(1)
        if escaped_char.isalpha():
            replacements = {"n": "\n", "t": "\t", "r": "\r"}
            return replacements.get(escaped_char, escaped_char)
        elif escaped_char == '"':
            return '"'
        else:
            return match.group(0)

    @staticmethod
    def _text_of_str(parse_tree: ParseTree) -> str:
        pt = Antlr4Utils.is_production(parse_tree) or Antlr4Utils.is_terminal(parse_tree)
        inner_str = pt.getText()
        inner_str = inner_str[1:-1]
        inner_str = re.sub(r"\\(.)", Preprocessor._replace_escaped_characters, inner_str)
        return inner_str

    def visitFunc_arg_int(self, ctx: ASLIntrinsicParser.Func_arg_intContext) -> FunctionArgumentInt:
        integer = int(ctx.INT().getText())
        return FunctionArgumentInt(integer=integer)

    def visitFunc_arg_float(
        self, ctx: ASLIntrinsicParser.Func_arg_floatContext
    ) -> FunctionArgumentFloat:
        number = float(ctx.INT().getText())
        return FunctionArgumentFloat(number=number)

    def visitFunc_arg_string(
        self, ctx: ASLIntrinsicParser.Func_arg_stringContext
    ) -> FunctionArgumentString:
        text: str = self._text_of_str(ctx.STRING())
        return FunctionArgumentString(string=text)

    def visitFunc_arg_context_path(
        self, ctx: ASLIntrinsicParser.Func_arg_context_pathContext
    ) -> FunctionArgumentContextPath:
        json_path: str = ctx.CONTEXT_PATH_STRING().getText()[1:]
        return FunctionArgumentContextPath(json_path=json_path)

    def visitFunc_arg_json_path(
        self, ctx: ASLIntrinsicParser.Func_arg_json_pathContext
    ) -> FunctionArgumentJsonPath:
        json_path: str = ctx.JSON_PATH_STRING().getText()
        return FunctionArgumentJsonPath(json_path=json_path)

    def visitFunc_arg_func_decl(
        self, ctx: ASLIntrinsicParser.Func_arg_func_declContext
    ) -> FunctionArgumentFunction:
        function: Function = self.visit(ctx.states_func_decl())
        return FunctionArgumentFunction(function=function)

    def visitFunc_arg_bool(
        self, ctx: ASLIntrinsicParser.Func_arg_boolContext
    ) -> FunctionArgumentBool:
        bool_term: TerminalNodeImpl = ctx.children[0]
        bool_term_rule: int = bool_term.getSymbol().type
        bool_val: bool = bool_term_rule == ASLIntrinsicLexer.TRUE
        return FunctionArgumentBool(boolean=bool_val)

    def visitFunc_arg_list(
        self, ctx: ASLIntrinsicParser.Func_arg_listContext
    ) -> FunctionArgumentList:
        arg_list: list[FunctionArgument] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, FunctionArgument):
                arg_list.append(cmp)
        return FunctionArgumentList(arg_list=arg_list)

    def visitState_fun_name(
        self, ctx: ASLIntrinsicParser.State_fun_nameContext
    ) -> StatesFunctionName:
        tok_typ: int = ctx.children[0].symbol.type
        name_typ = StatesFunctionNameType(tok_typ)
        return StatesFunctionName(function_type=name_typ)

    def visitStates_func_decl(
        self, ctx: ASLIntrinsicParser.States_func_declContext
    ) -> StatesFunction:
        func_name: StatesFunctionName = self.visit(ctx.state_fun_name())
        arg_list: FunctionArgumentList = self.visit(ctx.func_arg_list())
        func: StatesFunction = StatesFunctionFactory.from_name(
            func_name=func_name, arg_list=arg_list
        )
        return func

    def visitFunc_decl(self, ctx: ASLIntrinsicParser.Func_declContext) -> Function:
        return self.visit(ctx.children[0])
