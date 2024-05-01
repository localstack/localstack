from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class StackStatus(Enum):
    CREATE_COMPLETE = "CREATE_COMPLETE"


class AwsResource(ABC):
    @abstractmethod
    def serialize(self) -> dict: ...


class Tag(AwsResource):
    name: str
    value: str

    def serialize(self) -> dict:
        raise NotImplementedError


@dataclass
class Parameter(AwsResource):
    key: str
    value: str

    def serialize(self) -> dict:
        return {
            "ParameterKey": self.key,
            "ParameterValue": self.value,
        }


@dataclass
class DriftStatus(AwsResource):
    status: str = "NOT_CHECKED"

    def serialize(self) -> dict:
        return {
            "StackDriftStatus": self.status,
        }


@dataclass
class StackOutput(AwsResource):
    key: str
    value: Any
    description: str | None = None

    def serialize(self) -> dict:
        return {
            "OutputKey": self.key,
            "OutputValue": self.value,
            "Description": self.description or "",
        }


@dataclass
class Stack(AwsResource):
    id: str
    name: str
    parameters: list[Parameter] = field(default_factory=list)

    description: str | None = None
    creation_time: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    rollback_configuration: dict = field(default_factory=dict)
    # TODO: not correct
    status: StackStatus = field(default=StackStatus.CREATE_COMPLETE)
    disable_rollback: bool = False
    notification_arns: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    outputs: list[StackOutput] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    enable_termination_protection: bool = False
    drift_information: DriftStatus = field(default_factory=DriftStatus)

    def serialize(self) -> dict:
        return {
            "StackId": self.id,
            "StackName": self.name,
            "Description": self.description or "",
            "Parameters": [parameter.serialize() for parameter in self.parameters],
            "CreationTime": self.creation_time.isoformat(),
            "RollbackConfiguration": self.rollback_configuration,
            "StackStatus": self.status.value,
            "DisableRollback": self.disable_rollback,
            "NotificationARNs": self.notification_arns,
            "Capabilities": self.capabilities,
            "Outputs": [output.serialize() for output in self.outputs],
            "Tags": [tag.serialize() for tag in self.tags],
            "EnableTerminationProtection": self.enable_termination_protection,
            "DriftInformation": self.drift_information.serialize(),
        }


@dataclass
class StackSet(AwsResource):
    def serialize(self) -> dict:
        return {}


@dataclass
class StackInstance(AwsResource):
    def serialize(self) -> dict:
        return {}


class ChangeType(Enum):
    resource = "Resource"


@dataclass
class ResourceChange(AwsResource):
    # TODO: enum
    action: str
    logical_resource_id: str
    resource_type: str

    scope: list = field(default_factory=list)
    details: list = field(default_factory=list)

    def serialize(self) -> dict:
        return {
            "Action": self.action,
            "LogicalResourceId": self.logical_resource_id,
            "ResourceType": self.resource_type,
            "Scope": self.scope,
            "Details": self.details,
        }


@dataclass
class Change(AwsResource):
    type: ChangeType

    resource_change: ResourceChange | None

    def serialize(self) -> dict:
        match self.type:
            case ChangeType.resource:
                assert self.resource_change is not None

                return {
                    "Type": self.type.value,
                    "ResourceChange": self.resource_change.serialize(),
                }
            case other:
                raise NotImplementedError(f"Change type '{other}' not implemented yet")


@dataclass
class ChangeSet(AwsResource):
    name: str
    id: str
    stack_id: str
    stack_name: str

    changes: list[Change] = field(default_factory=list)

    def serialize(self) -> dict:
        return {
            "Changes": [change.serialize() for change in self.changes],
            "ChangeSetName": self.name,
            "ChangeSetId": self.id,
            "StackId": self.stack_id,
            "StackName": self.stack_name,
        }
