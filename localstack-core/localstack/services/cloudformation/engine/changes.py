from typing import Literal, Optional, TypedDict

Action = str


class ResourceChange(TypedDict):
    Action: Action
    LogicalResourceId: str
    PhysicalResourceId: Optional[str]
    ResourceType: str
    Scope: list
    Details: list
    Replacement: Optional[Literal["False"]]


class ChangeConfig(TypedDict):
    Type: str
    ResourceChange: ResourceChange
