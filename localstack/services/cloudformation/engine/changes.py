import logging

from localstack.services.cloudformation.engine.schema import (
    SCHEMA_PROVIDER,
    resource_needs_replacement,
)
from localstack.services.cloudformation.engine.types import ChangeConfig, ResourceChange

LOG = logging.getLogger(__name__)


def construct_changes_for_create(new_resources: dict) -> list[ChangeConfig]:
    adds = [val for key, val in new_resources.items()]

    changes = []
    for item in adds:
        item["Properties"] = item.get("Properties", {})  # TODO: try to remove this
        changes.append(
            ChangeConfig(
                Type="Resource",
                ResourceChange=ResourceChange(
                    Action="Add",
                    LogicalResourceId=item["LogicalResourceId"],
                    ResourceType=item["Type"],
                ),
            )
        )

    return changes


def construct_changes(
    old_resources: dict,
    new_resources: dict,
) -> list[ChangeConfig]:
    """
    This is still far from perfect. At this point (when constructing changes) we actually already need to have resolved a lot of things like parameters, evaluated intrinsic functions, etc.
    """
    deletes = [val for key, val in old_resources.items() if key not in new_resources]
    adds = [val for key, val in new_resources.items() if key not in old_resources]
    conflicts = [val for key, val in new_resources.items() if key in old_resources]

    changes = []
    for action, items in (("Remove", deletes), ("Add", adds), ("Modify", conflicts)):
        for resource_new in items:
            resource_new["Properties"] = resource_new.get(
                "Properties", {}
            )  # TODO: try to remove this
            if action in {
                "Add",
                "Remove",
            }:  # change in the list of resources, defined by their logical resource id
                changes.append(
                    ChangeConfig(
                        Type="Resource",
                        ResourceChange=ResourceChange(
                            Action=action,
                            LogicalResourceId=resource_new["LogicalResourceId"],
                            ResourceType=resource_new["Type"],
                        ),
                    )
                )
            elif action == "Modify":  # in-place or replacement update
                # def _resource_config_differs(self, resource_new, old_resources) -> bool:
                resource_id = resource_new["LogicalResourceId"]
                resource_old = old_resources[resource_id]
                resource_type = resource_new["Type"]
                schema = SCHEMA_PROVIDER.schema(resource_type)
                if not schema:
                    # some resources do not have a schema, e.g. `AWS::CDK::Metadata`
                    continue

                mismatch = resource_new["Properties"] != resource_old["Properties"]
                if not mismatch:
                    LOG.warning("Skipping item add because no change detected :O")
                else:
                    needs_replacement = resource_needs_replacement(
                        schema, resource_old["Properties"], resource_new["Properties"]
                    )
                    if needs_replacement:
                        change = ChangeConfig(
                            Type="Resource",
                            ResourceChange=ResourceChange(
                                Action="Modify",
                                ResourceType=resource_new["Type"],
                                LogicalResourceId=resource_new["LogicalResourceId"],
                                # FIXME: need access to the physical resource id
                                # PhysicalResourceId=resource_old["PhysicalResourceId"],
                                Replacement="True",
                                # Scope=["Properties"],
                                # Details=[],
                            ),
                        )
                    else:
                        change = ChangeConfig(
                            Type="Resource",
                            ResourceChange=ResourceChange(
                                Action="Modify",
                                ResourceType=resource_new["Type"],
                                LogicalResourceId=resource_new["LogicalResourceId"],
                                # FIXME: need access to the physical resource id
                                # PhysicalResourceId=resource_old["PhysicalResourceId"],
                                Replacement="False",
                                # Scope=["Properties"],
                                # Details=[],
                            ),
                        )
                    changes.append(change)
            else:
                LOG.warning("Skipping item add because no change detected :O")

    return changes
