import copy
from typing import Any, Final, NotRequired, Optional, TypedDict

from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    VariableDeclarations,
    VariableReference,
    encode_jsonata_variable_declarations,
)
from localstack.services.stepfunctions.asl.utils.json_path import extract_json
from localstack.utils.strings import long_uid

_STATES_PREFIX: Final[str] = "$states"
_STATES_INPUT_PREFIX: Final[str] = "$states.input"
_STATES_CONTEXT_PREFIX: Final[str] = "$states.context"
_STATES_RESULT_PREFIX: Final[str] = "$states.result"
_STATES_ERROR_OUTPUT_PREFIX: Final[str] = "$states.errorOutput"


class ExecutionData(TypedDict):
    Id: str
    Input: Optional[Any]
    Name: str
    RoleArn: str
    StartTime: str  # Format: ISO 8601.


class StateData(TypedDict):
    EnteredTime: str  # Format: ISO 8601.
    Name: str
    RetryCount: int


class StateMachineData(TypedDict):
    Id: str
    Name: str


class TaskData(TypedDict):
    Token: str


class ItemData(TypedDict):
    # Contains the index number for the array item that is being currently processed.
    Index: int
    # Contains the array item being processed.
    Value: Optional[Any]


class MapData(TypedDict):
    Item: ItemData


class ContextObjectData(TypedDict):
    Execution: ExecutionData
    State: NotRequired[StateData]
    StateMachine: StateMachineData
    Task: NotRequired[TaskData]  # Null if the Parameters field is outside a task state.
    Map: NotRequired[MapData]  # Only available when processing a Map state.


class ContextObject:
    context_object_data: Final[ContextObjectData]

    def __init__(self, context_object: ContextObjectData):
        self.context_object_data = context_object

    def update_task_token(self) -> str:
        new_token = long_uid()
        self.context_object_data["Task"] = TaskData(Token=new_token)
        return new_token


class StatesData(TypedDict):
    input: Any
    context: ContextObjectData
    result: NotRequired[Optional[Any]]
    errorOutput: NotRequired[Optional[Any]]


class States:
    _states_data: Final[StatesData]
    context_object: Final[ContextObject]

    def __init__(self, context: ContextObjectData):
        input_value = context["Execution"]["Input"]
        self._states_data = StatesData(input=input_value, context=context)
        self.context_object = ContextObject(context_object=context)

    @staticmethod
    def _extract(query: Optional[str], data: Any) -> Any:
        if query is None:
            result = data
        else:
            result = extract_json(query, data)
        return copy.deepcopy(result)

    def extract(self, query: str) -> Any:
        if not query.startswith(_STATES_PREFIX):
            raise RuntimeError(f"No such variable {query} in $states")
        jsonpath_states_query = "$." + query[1:]
        return self._extract(jsonpath_states_query, self._states_data)

    def get_input(self, query: Optional[str] = None) -> Any:
        return self._extract(query, self._states_data["input"])

    def reset(self, input_value: Any) -> None:
        clone_input_value = copy.deepcopy(input_value)
        self._states_data["input"] = clone_input_value
        self._states_data["result"] = None
        self._states_data["errorOutput"] = None

    def get_context(self, query: Optional[str] = None) -> Any:
        return self._extract(query, self._states_data["context"])

    def get_result(self, query: Optional[str] = None) -> Any:
        if "result" not in self._states_data:
            raise RuntimeError("Illegal access to $states.result")
        return self._extract(query, self._states_data["result"])

    def set_result(self, result: Any) -> Any:
        clone_result = copy.deepcopy(result)
        self._states_data["result"] = clone_result

    def get_error_output(self, query: Optional[str] = None) -> Any:
        if "errorOutput" not in self._states_data:
            raise RuntimeError("Illegal access to $states.errorOutput")
        return self._extract(query, self._states_data["errorOutput"])

    def set_error_output(self, error_output: Any) -> None:
        clone_error_output = copy.deepcopy(error_output)
        self._states_data["errorOutput"] = clone_error_output

    def to_variable_declarations(
        self, variable_references: Optional[set[VariableReference]] = None
    ) -> VariableDeclarations:
        if not variable_references or _STATES_PREFIX in variable_references:
            return encode_jsonata_variable_declarations(
                bindings={_STATES_PREFIX: self._states_data}
            )
        candidate_sub_states = {
            "input": _STATES_INPUT_PREFIX,
            "context": _STATES_CONTEXT_PREFIX,
            "result": _STATES_RESULT_PREFIX,
            "errorOutput": _STATES_ERROR_OUTPUT_PREFIX,
        }
        sub_states = dict()
        for variable_reference in variable_references:
            if not candidate_sub_states:
                break
            for sub_states_key, sub_states_prefix in candidate_sub_states.items():
                if variable_reference.startswith(sub_states_prefix):
                    sub_states[sub_states_key] = self._states_data[sub_states_key]  # noqa
                    del candidate_sub_states[sub_states_key]
                    break
        return encode_jsonata_variable_declarations(bindings={_STATES_PREFIX: sub_states})
