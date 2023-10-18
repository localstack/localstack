import logging
from typing import Dict, Optional

from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet, StackSet
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute

LOG = logging.getLogger(__name__)


class CloudFormationStore(BaseStore):
    # FIXME: use stack name as ID instead ?
    # maps stack ID to stack details
    stacks: Dict[str, Stack] = LocalAttribute(default=dict)

    # maps stack set ID to stack set details
    stack_sets: Dict[str, StackSet] = LocalAttribute(default=dict)

    # maps macro ID to macros
    macros: Dict[str, Dict] = LocalAttribute(default=dict)

    # exports: Dict[str, str]
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


def find_stack(account_id: str, region_name: str, stack_name: str) -> Stack | None:
    state = get_cloudformation_store(account_id, region_name)
    return (
        [s for s in state.stacks.values() if stack_name in [s.stack_name, s.stack_id]] or [None]
    )[0]


def find_change_set(
    account_id: str, region_name: str, cs_name: str, stack_name: Optional[str] = None
) -> Optional[StackChangeSet]:
    state = get_cloudformation_store(account_id, region_name)
    stack = find_stack(account_id, region_name, stack_name)
    stacks = [stack] if stack else state.stacks.values()
    result = [
        cs
        for s in stacks
        for cs in s.change_sets
        if cs_name in [cs.change_set_id, cs.change_set_name]
    ]
    return (result or [None])[0]


def exports_map(account_id: str, region_name: str):
    result = {}
    store = get_cloudformation_store(account_id, region_name)
    for export in store.exports:
        result[export["Name"]] = export
    return result
