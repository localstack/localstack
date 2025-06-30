import enum
from typing import Self

from localstack.aws.api.cloudformation import ChangeAction
from localstack.utils.analytics.metrics import LabeledCounter

COUNTER_NAMESPACE = "cloudformation"
COUNTER_VERSION = 2


class ActionOptions(enum.StrEnum):
    """
    Available actions that can be performed on a resource.

    Must support both CFn and CloudControl.
    """

    CREATE = "create"
    DELETE = "delete"
    UPDATE = "update"
    # for cloudcontrol
    READ = "read"
    LIST = "list"

    @classmethod
    def from_action(cls, action: Self | str | ChangeAction) -> Self:
        if isinstance(action, cls):
            return action

        # only used in CFn
        if isinstance(action, ChangeAction):
            action = action.value

        match action:
            case "Add":
                return cls.CREATE
            case "Modify" | "Dynamic":
                return cls.UPDATE
            case "Remove":
                return cls.DELETE
            case "Read":
                return cls.READ
            case "List":
                return cls.LIST
            case _:
                available_values = [every.value for every in cls]
                raise ValueError(
                    f"Invalid action option '{action}', should be one of {available_values}"
                )


resources = LabeledCounter(
    namespace=COUNTER_NAMESPACE,
    name="resources",
    labels=["resource_type", "missing", "action"],
    schema_version=COUNTER_VERSION,
)


def track_resource_operation(
    action: ActionOptions | str, expected_resource_type: str, *, missing: bool
):
    resources.labels(
        resource_type=expected_resource_type,
        missing=missing,
        action=ActionOptions.from_action(action),
    ).increment()
