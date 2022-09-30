import logging
from typing import Dict

from localstack.aws.api.cloudformation import Stack, StackSet
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute

LOG = logging.getLogger(__name__)


class CloudFormationStore(BaseStore):
    # maps stack ID to stack details
    stacks: Dict[str, Stack] = LocalAttribute(default=dict)

    # maps stack set ID to stack set details
    stack_sets: Dict[str, StackSet] = LocalAttribute(default=dict)

    @property
    def exports(self):
        exports = []
        output_keys = {}
        for stack_id, stack in self.stacks.items():
            for output in stack.outputs_list():
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
