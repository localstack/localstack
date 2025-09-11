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
    given_value = parameter.get("given_value")
    if given_value is not None:
        return given_value

    default_value = parameter.get("default_value")
    if default_value is not None:
        return default_value

    raise RuntimeError("Parameter value is None")


class ResolvedResource(TypedDict):
    LogicalResourceId: str
    Type: str
    Properties: dict
    LastUpdatedTimestamp: datetime
    ResourceStatus: NotRequired[ResourceStatus]
    PhysicalResourceId: NotRequired[str]
    ResourceStatusReason: NotRequired[str]
