from __future__ import annotations
from datetime import datetime
from typing import NotRequired, TypedDict

from localstack.aws.api.cloudformation import ResourceStatus


class EngineParameter(TypedDict):
    """
    Parameters supplied by the user. The resolved value field is populated by the engine
    """

    type_: str
    given_value: NotRequired[str | None]
    resolved_value: NotRequired[str | None]
    default_value: NotRequired[str | None]
    no_echo: NotRequired[bool | None]


def engine_parameter_value(parameter: EngineParameter) -> str:
    value = parameter.get("given_value") or parameter.get("default_value")
    if value is None:
        raise RuntimeError("Parameter value is None")

    return value


class ResolvedResource(TypedDict):
    LogicalResourceId: str
    Type: str
    Properties: dict
    ResourceStatus: ResourceStatus
    PhysicalResourceId: str | None
    LastUpdatedTimestamp: datetime | None


class _AWSNoValueType:
    def __repr__(self) -> str:
        return "AWS::NoValue"

    def __str__(self) -> str:
        return repr(self)


AWSNoValue = _AWSNoValueType()
