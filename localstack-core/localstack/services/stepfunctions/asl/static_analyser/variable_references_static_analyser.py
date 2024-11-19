from collections import OrderedDict
from typing import Final

from antlr4.tree.Tree import TerminalNodeImpl

from localstack.aws.api.stepfunctions import (
    StateName,
    VariableName,
    VariableNameList,
    VariableReferences,
)
from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import Antlr4Utils
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    VariableReference,
    extract_jsonata_variable_references,
)
from localstack.services.stepfunctions.asl.static_analyser.intrinsic.variable_names_intrinsic_static_analyser import (
    VariableNamesIntrinsicStaticAnalyser,
)
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser


class VariableReferencesStaticAnalyser(StaticAnalyser):
    @staticmethod
    def process_and_get(definition: str) -> VariableReferences:
        analyser = VariableReferencesStaticAnalyser()
        analyser.analyse(definition=definition)
        return analyser.get_variable_references()

    _fringe_state_names: Final[list[StateName]]
    _variable_references: Final[VariableReferences]

    def __init__(self):
        super().__init__()
        self._fringe_state_names = list()
        self._variable_references = OrderedDict()

    def get_variable_references(self) -> VariableReferences:
        return self._variable_references

    def _enter_state(self, state_name: StateName) -> None:
        self._fringe_state_names.append(state_name)

    def _exit_state(self) -> None:
        self._fringe_state_names.pop()

    def visitState_name(self, ctx: ASLParser.State_nameContext) -> None:
        state_name: str = ctx.keyword_or_string().getText()[1:-1]
        self._enter_state(state_name)

    def visitState_decl(self, ctx: ASLParser.State_declContext) -> None:
        super().visitState_decl(ctx=ctx)
        self._exit_state()

    def _put_variable_reference(self, variable_reference: VariableReference) -> None:
        variable_name: VariableName = variable_reference[1:]
        self._put_variable_name(variable_name)

    def _put_variable_name(self, variable_name: VariableName) -> None:
        state_name = self._fringe_state_names[-1]
        variable_name_list: VariableNameList = self._variable_references.get(state_name, list())
        if variable_name in variable_name_list:
            return
        variable_name_list.append(variable_name)
        if state_name not in self._variable_references:
            self._variable_references[state_name] = variable_name_list

    def _extract_variable_references_from_string_var(self, terminal_node: TerminalNodeImpl) -> None:
        reference_body = terminal_node.getText()[1:-1]
        variable_references: set[VariableReference] = extract_jsonata_variable_references(
            reference_body
        )
        for variable_reference in variable_references:
            self._put_variable_reference(variable_reference)

    def _extract_variable_references_from_intrinsic_function(
        self, terminal_node: TerminalNodeImpl
    ) -> None:
        definition_body = terminal_node.getText()[1:-1]
        variable_name_list: VariableNameList = VariableNamesIntrinsicStaticAnalyser.process_and_get(
            definition_body
        )
        for variable_name in variable_name_list:
            self._put_variable_name(variable_name)

    def visitTerminal(self, node) -> None:
        if Antlr4Utils.is_production(node.parentCtx, ASLParser.RULE_keyword_or_string):
            return

        maybe_string_var = Antlr4Utils.is_terminal(pt=node, token_type=ASLLexer.STRINGVAR)
        if maybe_string_var is not None:
            self._extract_variable_references_from_string_var(terminal_node=maybe_string_var)

        maybe_intrinsic_function = Antlr4Utils.is_terminal(
            pt=node, token_type=ASLLexer.STRINGINTRINSICFUNC
        )
        if maybe_intrinsic_function is not None:
            self._extract_variable_references_from_intrinsic_function(
                terminal_node=maybe_intrinsic_function
            )
