from dataclasses import dataclass, field
from typing import List, Set

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser


@dataclass(frozen=True)
class TargetState:
    target_state: str
    source_tree_path: str


@dataclass
class StateNamesScope:
    found_state_names: Set[str] = field(default_factory=set)
    target_states: Set[TargetState] = field(default_factory=set)


class AccessibleStatesStaticAnalyser(StaticAnalyser):
    _state_names_scope: List[StateNamesScope]
    _error_messages: List[str]
    _tree_path: List[str | int]

    _ERROR_MSG_PREFIX: str = "Invalid State Machine Definition: "
    _TREE_PATH_SEP: str = "/"

    def __init__(self):
        super().__init__()
        self._state_names_scope = []
        self._error_messages = []
        self._tree_path = []

    def analyse(self, definition: str) -> None:
        super().analyse(definition=definition)

        if len(self._error_messages) > 0:
            error_msg = ", ".join(self._error_messages)
            raise ValueError(self._ERROR_MSG_PREFIX + error_msg)

    def _assert_missing_transitions(self, scope: StateNamesScope) -> None:
        self._assert_all_targets_found(scope)
        self._assert_all_states_targetted(scope)

    def _assert_all_targets_found(self, scope: StateNamesScope) -> None:
        for state in scope.target_states:
            if state.target_state not in scope.found_state_names:
                target_type = self._path_leaf(state.source_tree_path)
                self._error_messages.append(
                    f"MISSING_TRANSITION_TARGET: Missing '{target_type}' target: {state.target_state} at {state.source_tree_path}"
                )

    def _assert_all_states_targetted(self, scope: StateNamesScope) -> None:
        target_state_names = {state.target_state for state in scope.target_states}
        for state_name in scope.found_state_names - target_state_names:
            self._error_messages.append(
                f'MISSING_TRANSITION_TARGET: State "{state_name}" is not reachable. at FIXME'
            )

    def _current_scope(self) -> StateNamesScope:
        return self._state_names_scope[-1]

    def _current_tree_path(self) -> str:
        path = ""
        for node in self._tree_path:
            match node:
                case str():
                    path += self._TREE_PATH_SEP + node
                case int():
                    path += f"[{node}]"
        return path

    def _path_leaf(self, source_tree_path: str) -> str:
        return source_tree_path.split(self._TREE_PATH_SEP)[-1]

    def _path_move_to_sibling(self):
        if len(self._tree_path) > 0 and type(self._tree_path[-1]) is int:
            self._tree_path[-1] += 1

    def visitNext_decl(self, ctx: ASLParser.Next_declContext):
        target_state_name: str = ctx.string_literal().getText()[1:-1]
        self._tree_path.append("Next")
        self._current_scope().target_states.add(
            TargetState(target_state_name, self._current_tree_path())
        )
        self._tree_path.pop()

    def visitStartat_decl(self, ctx: ASLParser.Startat_declContext):
        target_state_name: str = ctx.string_literal().getText()[1:-1]
        self._tree_path.append("StartAt")
        self._current_scope().target_states.add(
            TargetState(target_state_name, self._current_tree_path())
        )
        self._tree_path.pop()

    def visitState_decl(self, ctx: ASLParser.State_declContext):
        state_name: str = ctx.string_literal().getText()[1:-1]
        self._tree_path.append(state_name)
        self._current_scope().found_state_names.add(state_name)
        super().visitState_decl(ctx=ctx)
        self._tree_path.pop()

    def visitProgram_decl(self, ctx: ASLParser.Program_declContext):
        self._state_names_scope.append(StateNamesScope())
        super().visitProgram_decl(ctx=ctx)
        scope = self._state_names_scope.pop()
        self._path_move_to_sibling()
        self._assert_missing_transitions(scope)

    def visitStates_decl(self, ctx: ASLParser.States_declContext):
        self._tree_path.append("States")
        super().visitStates_decl(ctx=ctx)
        self._tree_path.pop()

    def visitBranches_decl(self, ctx: ASLParser.Branches_declContext):
        self._tree_path.append("Branches")
        self._tree_path.append(0)
        super().visitBranches_decl(ctx=ctx)
        self._tree_path.pop()
        self._tree_path.pop()
