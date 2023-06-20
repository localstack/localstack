from typing import Final, Optional, TypedDict

from localstack.utils.strings import long_uid


class Execution(TypedDict):
    Id: str
    Input: Optional[dict]
    Name: str
    RoleArn: str
    StartTime: str  # Format: ISO 8601.


class State(TypedDict):
    EnteredTime: str  # Format: ISO 8601.
    Name: str
    RetryCount: int


class StateMachine(TypedDict):
    Id: str
    Name: str


class Task(TypedDict):
    Token: str


class Item(TypedDict):
    # Contains the index number for the array item that is being currently processed.
    Index: int
    # Contains the array item being processed.
    Value: Optional[str]


class Map(TypedDict):
    Item: Item


class ContextObject(TypedDict):
    Execution: Execution
    State: Optional[State]
    StateMachine: StateMachine
    Task: Optional[Task]  # Null if the Parameters field is outside a task state.
    Map: Optional[Map]  # Only available when processing a Map state.


class ContextObjectManager:
    context_object: Final[ContextObject]

    def __init__(self, context_object: ContextObject):
        self.context_object = context_object

    def update_task_token(self) -> str:
        new_token = long_uid()
        self.context_object["Task"] = Task(Token=new_token)
        return new_token


class ContextObjectInitData(TypedDict):
    Execution: Execution
    StateMachine: StateMachine
