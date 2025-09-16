import copy
import logging
import os
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol, TypeVar

from localstack import config
from localstack.aws.api.cloudformation import (
    ChangeAction,
    Output,
    ResourceStatus,
    StackStatus,
)
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.analytics import track_resource_operation
from localstack.services.cloudformation.deployment_utils import log_not_available_message
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeDependsOn,
    NodeOutput,
    NodeResource,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    _AWS_URL_SUFFIX,
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

REGEX_OUTPUT_APIGATEWAY = re.compile(
    rf"^(https?://.+\.execute-api\.)(?:[^-]+-){{2,3}}\d\.(amazonaws\.com|{_AWS_URL_SUFFIX})/?(.*)$"
)

_T = TypeVar("_T")


@dataclass
class ChangeSetModelExecutorResult:
    resources: dict[str, ResolvedResource]
    outputs: list[Output]
    failure_message: str | None = None


class DeferredAction(Protocol):
    def __call__(self) -> None: ...


@dataclass
class Deferred:
    name: str
    action: DeferredAction


class TriggerRollback(Exception):
    """
    Sentinel exception to signal that the deployment should be stopped for a reason
    """

    def __init__(self, logical_resource_id: str, reason: str | None):
        self.logical_resource_id = logical_resource_id
        self.reason = reason


class ChangeSetModelExecutor(ChangeSetModelPreproc):
    # TODO: add typing for resolved resources and parameters.
    resources: Final[dict[str, ResolvedResource]]
    outputs: Final[list[Output]]
    _deferred_actions: list[Deferred]

    def __init__(self, change_set: ChangeSet):
        super().__init__(change_set=change_set)
        self.resources = {}
        self.outputs = []
        self._deferred_actions = []
        self.resource_provider_executor = ResourceProviderExecutor(
            stack_name=change_set.stack.stack_name,
            stack_id=change_set.stack.stack_id,
        )

    def execute(self) -> ChangeSetModelExecutorResult:
        # constructive process
        failure_message = None
        try:
            self.process()
        except TriggerRollback as e:
            failure_message = e.reason
        except Exception as e:
            failure_message = str(e)

        if self._deferred_actions:
            if failure_message:
                # TODO: differentiate between update and create
                self._change_set.stack.set_stack_status(StackStatus.ROLLBACK_IN_PROGRESS)
            else:
                # TODO: correct status
                self._change_set.stack.set_stack_status(
                    StackStatus.UPDATE_COMPLETE_CLEANUP_IN_PROGRESS
                )

            # perform all deferred actions such as deletions. These must happen in reverse from their
            # defined order so that resource dependencies are honoured
            # TODO: errors will stop all rollbacks; get parity on this behaviour
            for deferred in self._deferred_actions[::-1]:
                LOG.debug("executing deferred action: '%s'", deferred.name)
                deferred.action()

        if failure_message:
            # TODO: differentiate between update and create
            self._change_set.stack.set_stack_status(StackStatus.ROLLBACK_COMPLETE)

        return ChangeSetModelExecutorResult(
            resources=self.resources, outputs=self.outputs, failure_message=failure_message
        )

    def _defer_action(self, name: str, action: DeferredAction):
        self._deferred_actions.append(Deferred(name=name, action=action))

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
        *,
        action: ChangeAction,
        logical_resource_id,
        event_status: OperationStatus,
        resource_type: str,
        special_action: str = None,
        reason: str = None,
    ):
        status_from_action = special_action or EventOperationFromAction[action.value]
        if event_status == OperationStatus.SUCCESS:
            status = f"{status_from_action}_COMPLETE"
        else:
            status = f"{status_from_action}_{event_status.name}"

        physical_resource_id = self._get_physical_id(logical_resource_id, False)
        self._change_set.stack.set_resource_status(
            logical_resource_id=logical_resource_id,
            physical_resource_id=physical_resource_id,
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
            LOG.debug(
                "preprocessing resource '%s' failed: %s",
                node_resource.name,
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG) and config.CFN_VERBOSE_ERRORS,
            )
            self._process_event(
                action=node_resource.change_type.to_change_action(),
                logical_resource_id=node_resource.name,
                event_status=OperationStatus.FAILED,
                resource_type=node_resource.type_.value,
                reason=str(e),
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
                before_resource = self._before_resolved_resources.get(before_logical_id, {})
                self.resources[before_logical_id] = before_resource

        # Update the latest version of this resource for downstream references.
        if not is_nothing(after):
            after_logical_id = after.logical_id
            resource = self.resources[after_logical_id]
            resource_failed_to_deploy = resource["ResourceStatus"] in {
                ResourceStatus.CREATE_FAILED,
                ResourceStatus.UPDATE_FAILED,
            }
            if not resource_failed_to_deploy:
                after_physical_id: str = self._after_resource_physical_id(
                    resource_logical_id=after_logical_id
                )
                after.physical_resource_id = after_physical_id
            after.status = resource["ResourceStatus"]

            # terminate the deployment process
            if resource_failed_to_deploy:
                raise TriggerRollback(
                    logical_resource_id=after_logical_id,
                    reason=resource.get("ResourceStatusReason"),
                )
        return delta

    def visit_node_output(
        self, node_output: NodeOutput
    ) -> PreprocEntityDelta[PreprocOutput, PreprocOutput]:
        delta = super().visit_node_output(node_output=node_output)
        after = delta.after
        if is_nothing(after) or (isinstance(after, PreprocOutput) and after.condition is False):
            return delta

        output = Output(
            OutputKey=delta.after.name,
            OutputValue=delta.after.value,
            # TODO
            # Description=delta.after.description
        )
        if after.export:
            output["ExportName"] = after.export["Name"]
        self.outputs.append(output)
        return delta

    def _execute_resource_change(
        self, name: str, before: PreprocResource | None, after: PreprocResource | None
    ) -> None:
        # Changes are to be made about this resource.
        # TODO: this logic is a POC and should be revised.
        if not is_nothing(before) and not is_nothing(after):
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                # XXX hacky, stick the previous resources' properties into the payload
                before_properties = self._merge_before_properties(name, before)

                self._process_event(
                    action=ChangeAction.Modify,
                    logical_resource_id=name,
                    event_status=OperationStatus.IN_PROGRESS,
                    resource_type=before.resource_type,
                )
                if after.requires_replacement:
                    event = self._execute_resource_action(
                        action=ChangeAction.Add,
                        logical_resource_id=name,
                        resource_type=before.resource_type,
                        before_properties=None,
                        after_properties=after.properties,
                    )
                    self._process_event(
                        action=ChangeAction.Modify,
                        logical_resource_id=name,
                        event_status=event.status,
                        resource_type=before.resource_type,
                        reason=event.message,
                    )

                    def cleanup():
                        self._process_event(
                            action=ChangeAction.Remove,
                            logical_resource_id=name,
                            event_status=OperationStatus.IN_PROGRESS,
                            resource_type=before.resource_type,
                        )
                        event = self._execute_resource_action(
                            action=ChangeAction.Remove,
                            logical_resource_id=name,
                            resource_type=before.resource_type,
                            before_properties=before_properties,
                            after_properties=None,
                            part_of_replacement=True,
                        )
                        self._process_event(
                            action=ChangeAction.Remove,
                            logical_resource_id=name,
                            event_status=event.status,
                            resource_type=before.resource_type,
                            reason=event.message,
                        )

                    self._defer_action(f"cleanup-from-replacement-{name}", cleanup)
                else:
                    event = self._execute_resource_action(
                        action=ChangeAction.Modify,
                        logical_resource_id=name,
                        resource_type=before.resource_type,
                        before_properties=before_properties,
                        after_properties=after.properties,
                    )
                    self._process_event(
                        action=ChangeAction.Modify,
                        logical_resource_id=name,
                        event_status=event.status,
                        resource_type=before.resource_type,
                        reason=event.message,
                    )
            # Case: type migration.
            # TODO: Add test to assert that on type change the resources are replaced.
            else:
                # XXX hacky, stick the previous resources' properties into the payload
                before_properties = self._merge_before_properties(name, before)
                # Register a Removed for the previous type.

                def perform_deletion():
                    event = self._execute_resource_action(
                        action=ChangeAction.Remove,
                        logical_resource_id=name,
                        resource_type=before.resource_type,
                        before_properties=before_properties,
                        after_properties=None,
                    )
                    self._process_event(
                        action=ChangeAction.Modify,
                        logical_resource_id=name,
                        event_status=event.status,
                        resource_type=before.resource_type,
                        reason=event.message,
                    )

                self._defer_action(f"type-migration-{name}", perform_deletion)

                event = self._execute_resource_action(
                    action=ChangeAction.Add,
                    logical_resource_id=name,
                    resource_type=after.resource_type,
                    before_properties=None,
                    after_properties=after.properties,
                )
                self._process_event(
                    action=ChangeAction.Modify,
                    logical_resource_id=name,
                    event_status=event.status,
                    resource_type=before.resource_type,
                    reason=event.message,
                )
        elif not is_nothing(before):
            # Case: removal
            # XXX hacky, stick the previous resources' properties into the payload
            # XXX hacky, stick the previous resources' properties into the payload
            before_properties = self._merge_before_properties(name, before)

            def perform_deletion():
                self._process_event(
                    action=ChangeAction.Remove,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    event_status=OperationStatus.IN_PROGRESS,
                )
                event = self._execute_resource_action(
                    action=ChangeAction.Remove,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before_properties,
                    after_properties=None,
                )
                self._process_event(
                    action=ChangeAction.Remove,
                    logical_resource_id=name,
                    event_status=event.status,
                    resource_type=before.resource_type,
                    reason=event.message,
                )

            self._defer_action(f"remove-{name}", perform_deletion)
        elif not is_nothing(after):
            # Case: addition
            self._process_event(
                action=ChangeAction.Add,
                logical_resource_id=name,
                event_status=OperationStatus.IN_PROGRESS,
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
                action=ChangeAction.Add,
                logical_resource_id=name,
                event_status=event.status,
                resource_type=after.resource_type,
                reason=event.message,
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
        before_properties: PreprocProperties | None,
        after_properties: PreprocProperties | None,
        part_of_replacement: bool = False,
    ) -> ProgressEvent:
        LOG.debug("Executing resource action: %s for resource '%s'", action, logical_resource_id)
        payload = self.create_resource_provider_payload(
            action=action,
            logical_resource_id=logical_resource_id,
            resource_type=resource_type,
            before_properties=before_properties,
            after_properties=after_properties,
        )
        resource_provider = self.resource_provider_executor.try_load_resource_provider(
            resource_type
        )
        track_resource_operation(action, resource_type, missing=resource_provider is not None)

        extra_resource_properties = {}
        if resource_provider is not None:
            try:
                event = self.resource_provider_executor.deploy_loop(
                    resource_provider, extra_resource_properties, payload
                )
            except Exception as e:
                reason = str(e)
                LOG.warning(
                    "Resource provider operation failed: '%s'",
                    reason,
                    exc_info=LOG.isEnabledFor(logging.DEBUG) and config.CFN_VERBOSE_ERRORS,
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
            if "CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES" not in os.environ:
                LOG.warning(
                    "Deployment of resource type %s succeeded, but will fail in upcoming LocalStack releases unless CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES is explicitly enabled.",
                    resource_type,
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

        if part_of_replacement and action == ChangeAction.Remove:
            # Early return as we don't want to update internal state of the executor if this is a
            # cleanup of an old resource. The new resource has already been created and the state
            # updated
            return event

        status_from_action = EventOperationFromAction[action.value]
        resolved_resource = ResolvedResource(
            Properties=event.resource_model,
            LogicalResourceId=logical_resource_id,
            Type=resource_type,
            LastUpdatedTimestamp=datetime.now(UTC),
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

                # Don't update the resolved resources if we have deleted that resource
                if action != ChangeAction.Remove:
                    physical_resource_id = (
                        extra_resource_properties["PhysicalResourceId"]
                        if resource_provider
                        else MOCKED_REFERENCE
                    )
                    resolved_resource["PhysicalResourceId"] = physical_resource_id
                    resolved_resource["ResourceStatus"] = ResourceStatus(
                        f"{status_from_action}_COMPLETE"
                    )
                    # TODO: do we actually need this line?
                    resolved_resource.update(extra_resource_properties)

            case OperationStatus.FAILED:
                reason = event.message
                LOG.warning(
                    "Resource provider operation failed: '%s'",
                    reason,
                )
                resolved_resource["ResourceStatus"] = ResourceStatus(f"{status_from_action}_FAILED")
                resolved_resource["ResourceStatusReason"] = reason
            case other:
                raise NotImplementedError(f"Event status '{other}' not handled")

        self.resources[logical_resource_id] = resolved_resource
        return event

    def create_resource_provider_payload(
        self,
        action: ChangeAction,
        logical_resource_id: str,
        resource_type: str,
        before_properties: PreprocProperties | None,
        after_properties: PreprocProperties | None,
    ) -> ResourceProviderPayload | None:
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

    def _maybe_perform_on_delta(
        self, delta: PreprocEntityDelta, f: Callable[[_T], _T]
    ) -> PreprocEntityDelta:
        # we only care about the after state
        if isinstance(delta.after, str):
            delta.after = f(delta.after)
        return delta
