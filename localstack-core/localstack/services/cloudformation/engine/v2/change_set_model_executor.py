import copy
import logging
import uuid
from typing import Final, Optional

from localstack.aws.api.cloudformation import ChangeAction, StackStatus
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeParameter,
    NodeResource,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
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


class ChangeSetModelExecutor(ChangeSetModelPreproc):
    account_id: Final[str]
    region: Final[str]

    def __init__(
        self,
        change_set: ChangeSet,
    ):
        self.node_template = change_set.update_graph
        super().__init__(self.node_template)
        self.account_id = change_set.stack.account_id
        self.region = change_set.stack.region_name
        self.stack = change_set.stack
        self.stack_name = self.stack.stack_name
        self.stack_id = self.stack.stack_id
        self.resources = {}
        self.resolved_parameters = {}

    # TODO: use a structured type for the return value
    def execute(self) -> tuple[dict, dict]:
        self.process()
        return self.resources, self.resolved_parameters

    def visit_node_parameter(self, node_parameter: NodeParameter) -> PreprocEntityDelta:
        delta = super().visit_node_parameter(node_parameter=node_parameter)
        self.resolved_parameters[node_parameter.name] = delta.after
        return delta

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        delta = super().visit_node_resource(node_resource=node_resource)
        self._execute_on_resource_change(
            name=node_resource.name, before=delta.before, after=delta.after
        )
        return delta

    def _reduce_intrinsic_function_ref_value(self, preproc_value: PreprocResource | str) -> str:
        # TODO: why is this here?
        # if preproc_value is None:
        #     return None
        name = preproc_value
        if isinstance(preproc_value, PreprocResource):
            name = preproc_value.name
        resource = self.resources.get(name)
        if resource is None:
            raise NotImplementedError(f"No resource '{preproc_value.name}' found")
        physical_resource_id = resource.get("PhysicalResourceId")
        if not physical_resource_id:
            raise NotImplementedError(
                f"no physical resource id found for resource '{preproc_value.name}'"
            )
        return physical_resource_id

    def _execute_on_resource_change(
        self, name: str, before: Optional[PreprocResource], after: Optional[PreprocResource]
    ) -> None:
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
        before_properties = copy.deepcopy(preproc_resource.properties)
        if previous_properties := self._node_template.extra_context.get(
            "previous_resources", {}
        ).get(name):
            before_properties = PreprocProperties(previous_properties["Properties"])

        return before_properties

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
            stack_name=self.stack_name, stack_id=self.stack_id
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
                if self.stack.status == StackStatus.CREATE_IN_PROGRESS:
                    self.stack.set_stack_status(StackStatus.CREATE_FAILED, reason=reason)
                elif self.stack.status == StackStatus.UPDATE_IN_PROGRESS:
                    self.stack.set_stack_status(StackStatus.UPDATE_FAILED, reason=reason)
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
                if self.stack.status == StackStatus.CREATE_IN_PROGRESS:
                    self.stack.set_stack_status(StackStatus.CREATE_FAILED, reason=reason)
                elif self.stack.status == StackStatus.UPDATE_IN_PROGRESS:
                    self.stack.set_stack_status(StackStatus.UPDATE_FAILED, reason=reason)
                else:
                    raise NotImplementedError(f"Unhandled stack status: '{self.stack.status}'")
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
            "accessKeyId": self.account_id,
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
            "awsAccountId": self.account_id,
            "callbackContext": {},
            "stackId": self.stack_name,
            "resourceType": resource_type,
            "resourceTypeVersion": "000000",
            # TODO: not actually a UUID
            "bearerToken": str(uuid.uuid4()),
            "region": self.region,
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
