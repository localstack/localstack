import abc
from dataclasses import dataclass, field
from typing import List, Set

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParserVisitor import ASLParserVisitor
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser


@dataclass
class StateNamesScope:
    found_state_names: Set[str] = field(default_factory=set)
    target_states: Set[tuple[str, str]] = field(default_factory=set)  # FIXME use type


class StaticAnalyser(ASLParserVisitor, abc.ABC):
    _state_names_scope: List[StateNamesScope]
    _error_messages: List[str]
    _ERROR_MSG_PREFIX: str = "Invalid State Machine Definition: "

    def __init__(self):
        super().__init__()
        self._state_names_scope = []
        self._error_messages = []

    def analyse(self, definition: str) -> None:
        _, parser_rule_context = AmazonStateLanguageParser.parse(definition)
        self.visit(parser_rule_context)

        if len(self._error_messages) > 0:
            error_msg = ", ".join(self._error_messages)
            raise ValueError(self._ERROR_MSG_PREFIX + error_msg)

    def _assert_missing_transitions(self, scope: StateNamesScope) -> None:
        self._assert_all_targets_found(scope)
        self._assert_all_states_targetted(scope)

    def _assert_all_targets_found(self, scope: StateNamesScope) -> None:
        for target_state_name, target_type in scope.target_states:
            if target_state_name not in scope.found_state_names:
                self._error_messages.append(
                    f"MISSING_TRANSITION_TARGET: Missing {target_type} target: {target_state_name} at FIXME"
                )

    def _assert_all_states_targetted(self, scope: StateNamesScope) -> None:
        target_state_names = {state for (state, _) in scope.target_states}
        for state_name in scope.found_state_names - target_state_names:
            self._error_messages.append(
                f"MISSING_TRANSITION_TARGET: State {state_name} is not reachable. at FIXME"
            )

    def _current_scope(self) -> StateNamesScope:
        return self._state_names_scope[-1]

    def visitNext_decl(self, ctx: ASLParser.Next_declContext):
        next_state_name: str = ctx.string_literal().getText()[1:-1]
        self._current_scope().target_states.add((next_state_name, "Next"))

    def visitStartat_decl(self, ctx: ASLParser.Startat_declContext):
        start_state_name: str = ctx.string_literal().getText()[1:-1]
        self._current_scope().target_states.add((start_state_name, "StartAt"))

    def visitState_decl(self, ctx: ASLParser.State_declContext):
        state_name: str = ctx.string_literal().getText()[1:-1]
        self._current_scope().found_state_names.add(state_name)
        super().visitState_decl(ctx=ctx)

    def visitProgram_decl(self, ctx: ASLParser.Program_declContext):
        self._state_names_scope.append(StateNamesScope())
        super().visitProgram_decl(ctx=ctx)
        scope = self._state_names_scope.pop()
        self._assert_missing_transitions(scope)
