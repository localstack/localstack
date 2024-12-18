from collections import OrderedDict
from typing import Final

from localstack.aws.api.stepfunctions import (
    StateName,
    VariableName,
    VariableNameList,
    VariableReferences,
)
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
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

    def visitState_decl(self, ctx: ASLParser.State_declContext) -> None:
        state_name: str = ctx.string_literal().getText()[1:-1]
        self._enter_state(state_name=state_name)
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

    def visitString_variable_sample(self, ctx: ASLParser.String_variable_sampleContext):
        reference_body = ctx.getText()[1:-1]
        variable_references: set[VariableReference] = extract_jsonata_variable_references(
            reference_body
        )
        for variable_reference in variable_references:
            self._put_variable_reference(variable_reference)

    def visitString_intrinsic_function(self, ctx: ASLParser.String_intrinsic_functionContext):
        definition_body = ctx.getText()[1:-1]
        variable_name_list: VariableNameList = VariableNamesIntrinsicStaticAnalyser.process_and_get(
            definition_body
        )
        for variable_name in variable_name_list:
            self._put_variable_name(variable_name)

    def visitString_literal(self, ctx: ASLParser.String_literalContext):
        # Prune everything parsed as a string literal.
        return
