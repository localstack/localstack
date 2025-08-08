from typing import Literal, TypedDict

Action = str


class ResourceChange(TypedDict):
    Action: Action
    LogicalResourceId: str
    PhysicalResourceId: str | None
    ResourceType: str
    Scope: list
    Details: list
    Replacement: Literal["False"] | None


class ChangeConfig(TypedDict):
    Type: str
    ResourceChange: ResourceChange
