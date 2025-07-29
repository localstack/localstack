import copy
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, Optional

from localstack import config
from localstack.aws.api.cloudformation import (
    ChangeAction,
    ResourceStatus,
    StackStatus,
)
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.analytics import track_resource_operation
from localstack.services.cloudformation.deployment_utils import log_not_available_message
from localstack.services.cloudformation.engine.parameters import resolve_ssm_parameter
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeDependsOn,
    NodeOutput,
    NodeParameter,
    NodeResource,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    MOCKED_REFERENCE,
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
from localstack.services.cloudformation.v2.entities import ChangeSet, ResolvedResource

LOG = logging.getLogger(__name__)

EventOperationFromAction = {"Add": "CREATE", "Modify": "UPDATE", "Remove": "DELETE"}


@dataclass
class ChangeSetModelExecutorResult:
    resources: dict[str, ResolvedResource]
    parameters: dict
    outputs: dict


class ChangeSetModelExecutor(ChangeSetModelPreproc):
    # TODO: add typing for resolved resources and parameters.
    resources: Final[dict[str, ResolvedResource]]
    outputs: Final[dict]
    resolved_parameters: Final[dict]

    def __init__(self, change_set: ChangeSet):
        super().__init__(change_set=change_set)
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
        delta = super().visit_node_parameter(node_parameter)

        # handle dynamic references, e.g. references to SSM parameters
        # TODO: support more parameter types
        parameter_type: str = node_parameter.type_.value
        if parameter_type.startswith("AWS::SSM"):
            if parameter_type in [
                "AWS::SSM::Parameter::Value<String>",
                "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "AWS::SSM::Parameter::Value<CommaDelimitedList>",
            ]:
                delta.after = resolve_ssm_parameter(
                    account_id=self._change_set.account_id,
                    region_name=self._change_set.region_name,
                    stack_parameter_value=delta.after,
                )
            else:
                raise Exception(f"Unsupported stack parameter type: {parameter_type}")

        self.resolved_parameters[node_parameter.name] = delta.after
        return delta

    def _get_physical_id(self, logical_resource_id, strict: bool = True) -> str | None:
        physical_resource_id = None
        try:
            physical_resource_id = self._after_resource_physical_id(logical_resource_id)
        except RuntimeError:
            # The physical id is missing or is set to None, which is invalid.
            pass
        if physical_resource_id is None:
            # The physical resource id is None after an update that didn't rewrite the resource, the previous
            # resource id is therefore the current physical id of this resource.

            try:
                physical_resource_id = self._before_resource_physical_id(logical_resource_id)
            except RuntimeError as e:
                if strict:
                    raise e
        return physical_resource_id

    def _process_event(
        self,
        action: ChangeAction,
        logical_resource_id,
        event_status: OperationStatus,
        special_action: str = None,
        reason: str = None,
        resource_type=None,
    ):
        status_from_action = special_action or EventOperationFromAction[action.value]
        if event_status == OperationStatus.SUCCESS:
            status = f"{status_from_action}_COMPLETE"
        else:
            status = f"{status_from_action}_{event_status.name}"

        self._change_set.stack.set_resource_status(
            logical_resource_id=logical_resource_id,
            physical_resource_id=self._get_physical_id(logical_resource_id, False),
            resource_type=resource_type,
            status=ResourceStatus(status),
            resource_status_reason=reason,
        )

        if event_status == OperationStatus.FAILED:
            self._change_set.stack.set_stack_status(StackStatus(status))

    def _after_deployed_property_value_of(
        self, resource_logical_id: str, property_name: str
    ) -> str:
        after_resolved_resources = self.resources
        return self._deployed_property_value_of(
            resource_logical_id=resource_logical_id,
            property_name=property_name,
            resolved_resources=after_resolved_resources,
        )

    def _after_resource_physical_id(self, resource_logical_id: str) -> str:
        after_resolved_resources = self.resources
        return self._resource_physical_resource_id_from(
            logical_resource_id=resource_logical_id, resolved_resources=after_resolved_resources
        )

    def visit_node_depends_on(self, node_depends_on: NodeDependsOn) -> PreprocEntityDelta:
        array_identifiers_delta = super().visit_node_depends_on(node_depends_on=node_depends_on)

        # Visit depends_on resources before returning.
        depends_on_resource_logical_ids: set[str] = set()
        if array_identifiers_delta.before:
            depends_on_resource_logical_ids.update(array_identifiers_delta.before)
        if array_identifiers_delta.after:
            depends_on_resource_logical_ids.update(array_identifiers_delta.after)
        for depends_on_resource_logical_id in depends_on_resource_logical_ids:
            node_resource = self._get_node_resource_for(
                resource_name=depends_on_resource_logical_id,
                node_template=self._change_set.update_model.node_template,
            )
            self.visit(node_resource)

        return array_identifiers_delta

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        """
        Overrides the default preprocessing for NodeResource objects by annotating the
        `after` delta with the physical resource ID, if side effects resulted in an update.
        """
        try:
            delta = super().visit_node_resource(node_resource=node_resource)
        except Exception as e:
            self._process_event(
                node_resource.change_type.to_change_action(),
                node_resource.name,
                OperationStatus.FAILED,
                reason=str(e),
                resource_type=node_resource.type_.value,
            )
            raise e

        before = delta.before
        after = delta.after

        if before != after:
            # There are changes for this resource.
            self._execute_resource_change(name=node_resource.name, before=before, after=after)
        else:
            # There are no updates for this resource; iff the resource was previously
            # deployed, then the resolved details are copied in the current state for
            # references or other downstream operations.
            if not is_nothing(before):
                before_logical_id = delta.before.logical_id
                before_resource = self._before_resolved_resources.get(before_logical_id, dict())
                self.resources[before_logical_id] = before_resource

        # Update the latest version of this resource for downstream references.
        if not is_nothing(after):
            after_logical_id = after.logical_id
            after_physical_id: str = self._after_resource_physical_id(
                resource_logical_id=after_logical_id
            )
            after.physical_resource_id = after_physical_id
        return delta

    def visit_node_output(
        self, node_output: NodeOutput
    ) -> PreprocEntityDelta[PreprocOutput, PreprocOutput]:
        delta = super().visit_node_output(node_output=node_output)
        after = delta.after
        if is_nothing(after) or (isinstance(after, PreprocOutput) and after.condition is False):
            return delta
        self.outputs[delta.after.name] = delta.after.value
        return delta

    def _execute_resource_change(
        self, name: str, before: Optional[PreprocResource], after: Optional[PreprocResource]
    ) -> None:
        # Changes are to be made about this resource.
        # TODO: this logic is a POC and should be revised.
        if not is_nothing(before) and not is_nothing(after):
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                # XXX hacky, stick the previous resources' properties into the payload
                before_properties = self._merge_before_properties(name, before)

                self._process_event(ChangeAction.Modify, name, OperationStatus.IN_PROGRESS)
                event = self._execute_resource_action(
                    action=ChangeAction.Modify,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before_properties,
                    after_properties=after.properties,
                )
                self._process_event(
                    ChangeAction.Modify,
                    name,
                    event.status,
                    reason=event.message,
                    resource_type=before.resource_type,
                )
            # Case: type migration.
            # TODO: Add test to assert that on type change the resources are replaced.
            else:
                # XXX hacky, stick the previous resources' properties into the payload
                before_properties = self._merge_before_properties(name, before)
                # Register a Removed for the previous type.

                event = self._execute_resource_action(
                    action=ChangeAction.Remove,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before_properties,
                    after_properties=None,
                )
                # Register a Create for the next type.
                self._process_event(
                    ChangeAction.Modify,
                    name,
                    event.status,
                    reason=event.message,
                    resource_type=before.resource_type,
                )
                event = self._execute_resource_action(
                    action=ChangeAction.Add,
                    logical_resource_id=name,
                    resource_type=after.resource_type,
                    before_properties=None,
                    after_properties=after.properties,
                )
                self._process_event(
                    ChangeAction.Modify,
                    name,
                    event.status,
                    reason=event.message,
                    resource_type=before.resource_type,
                )
        elif not is_nothing(before):
            # Case: removal
            # XXX hacky, stick the previous resources' properties into the payload
            # XXX hacky, stick the previous resources' properties into the payload
            before_properties = self._merge_before_properties(name, before)
            self._process_event(
                ChangeAction.Remove,
                name,
                OperationStatus.IN_PROGRESS,
                resource_type=before.resource_type,
            )
            event = self._execute_resource_action(
                action=ChangeAction.Remove,
                logical_resource_id=name,
                resource_type=before.resource_type,
                before_properties=before_properties,
                after_properties=None,
            )
            self._process_event(
                ChangeAction.Remove,
                name,
                event.status,
                reason=event.message,
                resource_type=before.resource_type,
            )
        elif not is_nothing(after):
            # Case: addition
            self._process_event(
                ChangeAction.Add,
                name,
                OperationStatus.IN_PROGRESS,
                resource_type=after.resource_type,
            )
            event = self._execute_resource_action(
                action=ChangeAction.Add,
                logical_resource_id=name,
                resource_type=after.resource_type,
                before_properties=None,
                after_properties=after.properties,
            )
            self._process_event(
                ChangeAction.Add,
                name,
                event.status,
                reason=event.message,
                resource_type=after.resource_type,
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
    ) -> ProgressEvent:
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
        track_resource_operation(action, resource_type, missing=resource_provider is not None)

        extra_resource_properties = {}
        if resource_provider is not None:
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
                event = ProgressEvent(
                    OperationStatus.FAILED,
                    resource_model={},
                    message=f"Resource provider operation failed: {reason}",
                )
        elif config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
            log_not_available_message(
                resource_type,
                f'No resource provider found for "{resource_type}"',
            )
            LOG.warning(
                "Deployment of resource type %s successful due to config CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES"
            )
            event = ProgressEvent(
                OperationStatus.SUCCESS,
                resource_model={},
                message=f"Resource type {resource_type} is not supported but was deployed as a fallback",
            )
        else:
            log_not_available_message(
                resource_type,
                f'No resource provider found for "{resource_type}"',
            )
            event = ProgressEvent(
                OperationStatus.FAILED,
                resource_model={},
                message=f"Resource type {resource_type} not supported",
            )

        match event.status:
            case OperationStatus.SUCCESS:
                # merge the resources state with the external state
                # TODO: this is likely a duplicate of updating from extra_resource_properties

                # TODO: add typing
                # TODO: avoid the use of string literals for sampling from the object, use typed classes instead
                # TODO: avoid sampling from resources and use tmp var reference
                # TODO: add utils functions to abstract this logic away (resource.update(..))
                # TODO: avoid the use of setdefault (debuggability/readability)
                # TODO: review the use of merge

                status_from_action = EventOperationFromAction[action.value]
                physical_resource_id = (
                    extra_resource_properties["PhysicalResourceId"]
                    if resource_provider
                    else MOCKED_REFERENCE
                )
                resolved_resource = ResolvedResource(
                    Properties=event.resource_model,
                    LogicalResourceId=logical_resource_id,
                    Type=resource_type,
                    LastUpdatedTimestamp=datetime.now(timezone.utc),
                    ResourceStatus=ResourceStatus(f"{status_from_action}_COMPLETE"),
                    PhysicalResourceId=physical_resource_id,
                )
                # TODO: do we actually need this line?
                resolved_resource.update(extra_resource_properties)

                self.resources[logical_resource_id] = resolved_resource

            case OperationStatus.FAILED:
                reason = event.message
                LOG.warning(
                    "Resource provider operation failed: '%s'",
                    reason,
                )
            case other:
                raise NotImplementedError(f"Event status '{other}' not handled")
        return event

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
                # previous_resource_properties = None
                # HACK: our providers use a mix of `desired_state` and `previous_state` so ensure the payload is present for both
                previous_resource_properties = resource_properties
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
