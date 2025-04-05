import abc
from typing import List, Set

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParserVisitor import ASLParserVisitor
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser

class StaticAnalyser(ASLParserVisitor, abc.ABC):
    _found_state_names: Set[str]
    _target_states: Set[tuple[str, str]] # FIXME use type
    _duplicate_state_names: Set[str]
    _error_messages: List[str]
    _ERROR_MSG_PREFIX: str = "Invalid State Machine Definition: "

    def __init__(self):
        super().__init__()
        self._found_state_names = set()
        self._target_states = set()
        self._duplicate_state_names = set()
        self._error_messages = [] 

    def analyse(self, definition: str) -> None:
        _, parser_rule_context = AmazonStateLanguageParser.parse(definition)
        self.visit(parser_rule_context)
        self._assert()

    def _assert(self) -> None:
        self._assert_all_targets_found()
        self._assert_all_states_targetted()
        self._assert_no_duplicate_states()

        if len(self._error_messages) > 0:
            error_msg = ", ".join(self._error_messages)
            raise ValueError(self._ERROR_MSG_PREFIX + error_msg)

    def _assert_all_targets_found(self) -> None:
        for target_state_name, target_type in self._target_states:
            if target_state_name not in self._found_state_names:
                self._error_messages.append(f"MISSING_TRANSITION_TARGET: Missing {target_type} target: {target_state_name} at FIXME")

    def _assert_all_states_targetted(self) -> None:
        target_state_names = { state for (state, _) in self._target_states }
        for state_name in ( self._found_state_names - target_state_names ):
            self._error_messages.append(f"MISSING_TRANSITION_TARGET: State {state_name} is not reachable. at FIXME")

    def _assert_no_duplicate_states(self) -> None:
        for state_name in self._duplicate_state_names:
            self._error_messages.append(f"DUPLICATE_STATE_NAME:  Duplicate State name {state_name}  at FIXME")

    def visitNext_decl(self, ctx:ASLParser.Next_declContext):
        """
        extract the next string from ctx and store in member var
        """
        next_state_name: str = ctx.string_literal().getText()[1:-1]
        self._target_states.add((next_state_name, "Next"))

    def visitStartat_decl(self, ctx:ASLParser.Startat_declContext):
        """"
        extract the start at string from ctx and check in the member var store if it exists in this scope
        """
        start_state_name: str = ctx.string_literal().getText()[1:-1]
        self._target_states.add((start_state_name, "StartAt"))

    def visitState_decl(self, ctx:ASLParser.State_declContext):
        """
        sample the state name string and store it in a member var for the current scope
        """
        state_name: str = ctx.string_literal().getText()[1:-1]
        if state_name in self._found_state_names:
            self._duplicate_state_names.add(state_name)
        self._found_state_names.add(state_name)
        super().visitState_decl(ctx=ctx)

