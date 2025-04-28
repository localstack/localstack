import copy
import logging
import uuid
from dataclasses import dataclass
from typing import Final, Optional

from localstack.aws.api.cloudformation import ChangeAction, StackStatus
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeOutput,
    NodeParameter,
    NodeResource,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
    PreprocOutput,
    PreprocProperties,
    PreprocResource,
)
from localstack.services.cloudformation.resource_provider import (
    Credentials,
    OperationStatus,
    ProgressEvent,
    ResourceProviderExecutor,
    ResourceProviderPayload,
)
from localstack.services.cloudformation.v2.entities import ChangeSet

LOG = logging.getLogger(__name__)


@dataclass
class ChangeSetModelExecutorResult:
    resources: dict
    parameters: dict
    outputs: dict


class ChangeSetModelExecutor(ChangeSetModelPreproc):
    _change_set: Final[ChangeSet]
    # TODO: add typing for resolved resources and parameters.
    resources: Final[dict]
    outputs: Final[dict]
    resolved_parameters: Final[dict]

    def __init__(self, change_set: ChangeSet):
        super().__init__(
            node_template=change_set.update_graph,
            before_resolved_resources=change_set.stack.resolved_resources,
        )
        self._change_set = change_set
        self.resources = dict()
        self.outputs = dict()
        self.resolved_parameters = dict()

    # TODO: use a structured type for the return value
    def execute(self) -> ChangeSetModelExecutorResult:
        self.process()
        return ChangeSetModelExecutorResult(
            resources=self.resources, parameters=self.resolved_parameters, outputs=self.outputs
        )

    def visit_node_parameter(self, node_parameter: NodeParameter) -> PreprocEntityDelta:
        delta = super().visit_node_parameter(node_parameter=node_parameter)
        self.resolved_parameters[node_parameter.name] = delta.after
        return delta

    def _after_resource_physical_id(self, resource_logical_id: str) -> Optional[str]:
        after_resolved_resources = self.resources
        return self._resource_physical_resource_id_from(
            logical_resource_id=resource_logical_id, resolved_resources=after_resolved_resources
        )

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        """
        Overrides the default preprocessing for NodeResource objects by annotating the
        `after` delta with the physical resource ID, if side effects resulted in an update.
        """
        delta = super().visit_node_resource(node_resource=node_resource)
        self._execute_on_resource_change(
            name=node_resource.name, before=delta.before, after=delta.after
        )
        after_resource = delta.after
        if after_resource is not None and delta.before != delta.after:
            after_logical_id = after_resource.logical_id
            after_physical_id: Optional[str] = self._after_resource_physical_id(
                resource_logical_id=after_logical_id
            )
            if after_physical_id is None:
                raise RuntimeError(
                    f"No PhysicalResourceId was found for resource '{after_physical_id}' post-update."
                )
            after_resource.physical_resource_id = after_physical_id
        return delta

    def visit_node_output(
        self, node_output: NodeOutput
    ) -> PreprocEntityDelta[PreprocOutput, PreprocOutput]:
        delta = super().visit_node_output(node_output=node_output)
        if delta.after is None:
            # handling deletion so the output does not really matter
            # TODO: are there other situations?
            return delta

        self.outputs[delta.after.name] = delta.after.value
        return delta

    def _execute_on_resource_change(
        self, name: str, before: Optional[PreprocResource], after: Optional[PreprocResource]
    ) -> None:
        if before == after:
            # unchanged: nothing to do.
            return
        # TODO: this logic is a POC and should be revised.
        if before is not None and after is not None:
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                # XXX hacky, stick the previous resources' properties into the payload
                before_properties = self._merge_before_properties(name, before)

                self._execute_resource_action(
                    action=ChangeAction.Modify,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before_properties,
                    after_properties=after.properties,
                )
            # Case: type migration.
            # TODO: Add test to assert that on type change the resources are replaced.
            else:
                # XXX hacky, stick the previous resources' properties into the payload
                before_properties = self._merge_before_properties(name, before)
                # Register a Removed for the previous type.
                self._execute_resource_action(
                    action=ChangeAction.Remove,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before_properties,
                    after_properties=None,
                )
                # Register a Create for the next type.
                self._execute_resource_action(
                    action=ChangeAction.Add,
                    logical_resource_id=name,
                    resource_type=after.resource_type,
                    before_properties=None,
                    after_properties=after.properties,
                )
        elif before is not None:
            # Case: removal
            # XXX hacky, stick the previous resources' properties into the payload
            # XXX hacky, stick the previous resources' properties into the payload
            before_properties = self._merge_before_properties(name, before)

            self._execute_resource_action(
                action=ChangeAction.Remove,
                logical_resource_id=name,
                resource_type=before.resource_type,
                before_properties=before_properties,
                after_properties=None,
            )
        elif after is not None:
            # Case: addition
            self._execute_resource_action(
                action=ChangeAction.Add,
                logical_resource_id=name,
                resource_type=after.resource_type,
                before_properties=None,
                after_properties=after.properties,
            )

    def _merge_before_properties(
        self, name: str, preproc_resource: PreprocResource
    ) -> PreprocProperties:
        if previous_resource_properties := self._change_set.stack.resolved_resources.get(
            name, {}
        ).get("Properties"):
            return PreprocProperties(properties=previous_resource_properties)

        # XXX fall back to returning the input value
        return copy.deepcopy(preproc_resource.properties)

    def _execute_resource_action(
        self,
        action: ChangeAction,
        logical_resource_id: str,
        resource_type: str,
        before_properties: Optional[PreprocProperties],
        after_properties: Optional[PreprocProperties],
    ) -> None:
        LOG.debug("Executing resource action: %s for resource '%s'", action, logical_resource_id)
        resource_provider_executor = ResourceProviderExecutor(
            stack_name=self._change_set.stack.stack_name, stack_id=self._change_set.stack.stack_id
        )
        payload = self.create_resource_provider_payload(
            action=action,
            logical_resource_id=logical_resource_id,
            resource_type=resource_type,
            before_properties=before_properties,
            after_properties=after_properties,
        )
        resource_provider = resource_provider_executor.try_load_resource_provider(resource_type)

        extra_resource_properties = {}
        if resource_provider is not None:
            # TODO: stack events
            try:
                event = resource_provider_executor.deploy_loop(
                    resource_provider, extra_resource_properties, payload
                )
            except Exception as e:
                reason = str(e)
                LOG.warning(
                    "Resource provider operation failed: '%s'",
                    reason,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                stack = self._change_set.stack
                stack_status = stack.status
                if stack_status == StackStatus.CREATE_IN_PROGRESS:
                    stack.set_stack_status(StackStatus.CREATE_FAILED, reason=reason)
                elif stack_status == StackStatus.UPDATE_IN_PROGRESS:
                    stack.set_stack_status(StackStatus.UPDATE_FAILED, reason=reason)
                return
        else:
            event = ProgressEvent(OperationStatus.SUCCESS, resource_model={})

        self.resources.setdefault(logical_resource_id, {"Properties": {}})
        match event.status:
            case OperationStatus.SUCCESS:
                # merge the resources state with the external state
                # TODO: this is likely a duplicate of updating from extra_resource_properties
                self.resources[logical_resource_id]["Properties"].update(event.resource_model)
                self.resources[logical_resource_id].update(extra_resource_properties)
                # XXX for legacy delete_stack compatibility
                self.resources[logical_resource_id]["LogicalResourceId"] = logical_resource_id
                self.resources[logical_resource_id]["Type"] = resource_type
            case OperationStatus.FAILED:
                reason = event.message
                LOG.warning(
                    "Resource provider operation failed: '%s'",
                    reason,
                )
                # TODO: duplication
                stack = self._change_set.stack
                stack_status = stack.status
                if stack_status == StackStatus.CREATE_IN_PROGRESS:
                    stack.set_stack_status(StackStatus.CREATE_FAILED, reason=reason)
                elif stack_status == StackStatus.UPDATE_IN_PROGRESS:
                    stack.set_stack_status(StackStatus.UPDATE_FAILED, reason=reason)
                else:
                    raise NotImplementedError(f"Unhandled stack status: '{stack.status}'")
            case any:
                raise NotImplementedError(f"Event status '{any}' not handled")

    def create_resource_provider_payload(
        self,
        action: ChangeAction,
        logical_resource_id: str,
        resource_type: str,
        before_properties: Optional[PreprocProperties],
        after_properties: Optional[PreprocProperties],
    ) -> Optional[ResourceProviderPayload]:
        # FIXME: use proper credentials
        creds: Credentials = {
            "accessKeyId": self._change_set.stack.account_id,
            "secretAccessKey": INTERNAL_AWS_SECRET_ACCESS_KEY,
            "sessionToken": "",
        }
        before_properties_value = before_properties.properties if before_properties else None
        after_properties_value = after_properties.properties if after_properties else None

        match action:
            case ChangeAction.Add:
                resource_properties = after_properties_value or {}
                previous_resource_properties = None
            case ChangeAction.Modify | ChangeAction.Dynamic:
                resource_properties = after_properties_value or {}
                previous_resource_properties = before_properties_value or {}
            case ChangeAction.Remove:
                resource_properties = before_properties_value or {}
                previous_resource_properties = None
            case _:
                raise NotImplementedError(f"Action '{action}' not handled")

        resource_provider_payload: ResourceProviderPayload = {
            "awsAccountId": self._change_set.stack.account_id,
            "callbackContext": {},
            "stackId": self._change_set.stack.stack_name,
            "resourceType": resource_type,
            "resourceTypeVersion": "000000",
            # TODO: not actually a UUID
            "bearerToken": str(uuid.uuid4()),
            "region": self._change_set.stack.region_name,
            "action": str(action),
            "requestData": {
                "logicalResourceId": logical_resource_id,
                "resourceProperties": resource_properties,
                "previousResourceProperties": previous_resource_properties,
                "callerCredentials": creds,
                "providerCredentials": creds,
                "systemTags": {},
                "previousSystemTags": {},
                "stackTags": {},
                "previousStackTags": {},
            },
        }
        return resource_provider_payload
