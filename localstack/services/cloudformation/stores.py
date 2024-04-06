import logging
from typing import Optional

from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet, StackSet
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute

LOG = logging.getLogger(__name__)


class CloudFormationStore(BaseStore):
    # maps stack ID to stack details
    stacks: dict[str, Stack] = LocalAttribute(default=dict)

    # maps stack set ID to stack set details
    stack_sets: dict[str, StackSet] = LocalAttribute(default=dict)

    # maps macro ID to macros
    macros: dict[str, dict] = LocalAttribute(default=dict)

    # exports: dict[str, str]
    @property
    def exports(self):
        exports = []
        output_keys = {}
        for stack_id, stack in self.stacks.items():
            for output in stack.resolved_outputs:
                export_name = output.get("ExportName")
                if not export_name:
                    continue
                if export_name in output_keys:
                    # TODO: raise exception on stack creation in case of duplicate exports
                    LOG.warning(
                        "Found duplicate export name %s in stacks: %s %s",
                        export_name,
                        output_keys[export_name],
                        stack.stack_id,
                    )
                entry = {
                    "ExportingStackId": stack.stack_id,
                    "Name": export_name,
                    "Value": output["OutputValue"],
                }
                exports.append(entry)
                output_keys[export_name] = stack.stack_id
        return exports


cloudformation_stores = AccountRegionBundle("cloudformation", CloudFormationStore)


def get_cloudformation_store(account_id: str, region_name: str) -> CloudFormationStore:
    return cloudformation_stores[account_id][region_name]


# TODO: rework / fix usage of this
def find_stack(account_id: str, region_name: str, stack_name: str) -> Stack | None:
    # Warning: This function may not return the correct stack if multiple stacks with same name exist.
    state = get_cloudformation_store(account_id, region_name)
    return (
        [s for s in state.stacks.values() if stack_name in [s.stack_name, s.stack_id]] or [None]
    )[0]


def find_stack_by_id(account_id: str, region_name: str, stack_id: str) -> Stack | None:
    """
    Find the stack by id.

    :param account_id: account of the stack
    :param region_name: region of the stack
    :param stack_id: stack id
    :return: Stack if it is found, None otherwise
    """
    state = get_cloudformation_store(account_id, region_name)
    for stack in state.stacks.values():
        # there can only be one stack with an id
        if stack_id == stack.stack_id:
            return stack
    return None


def find_active_stack_by_name_or_id(
    account_id: str, region_name: str, stack_name_or_id: str
) -> Stack | None:
    """
    Find the active stack by name. Some cloudformation operations only allow referencing by slack name if the stack is
    "active", which we currently interpret as not DELETE_COMPLETE.

    :param account_id: account of the stack
    :param region_name: region of the stack
    :param stack_name_or_id: stack name or stack id
    :return: Stack if it is found, None otherwise
    """
    state = get_cloudformation_store(account_id, region_name)
    for stack in state.stacks.values():
        # there can only be one stack where this condition is true for each region
        # as there can only be one active stack with a given name
        if (
            stack_name_or_id in [stack.stack_name, stack.stack_id]
            and stack.status != "DELETE_COMPLETE"
        ):
            return stack
    return None


def find_change_set(
    account_id: str, region_name: str, cs_name: str, stack_name: Optional[str] = None
) -> Optional[StackChangeSet]:
    store = get_cloudformation_store(account_id, region_name)
    for stack in store.stacks.values():
        if stack_name in (stack.stack_name, stack.stack_id, None):
            for change_set in stack.change_sets:
                if cs_name in (change_set.change_set_id, change_set.change_set_name):
                    return change_set
    return None


def exports_map(account_id: str, region_name: str):
    result = {}
    store = get_cloudformation_store(account_id, region_name)
    for export in store.exports:
        result[export["Name"]] = export
    return result
