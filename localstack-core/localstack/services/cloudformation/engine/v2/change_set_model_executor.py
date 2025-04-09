import logging
import uuid
from typing import Any, Final, Optional

from localstack.aws.api.cloudformation import ChangeAction
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeResource,
    NodeTemplate,
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
    get_resource_type,
)

LOG = logging.getLogger(__name__)


class ChangeSetModelExecutor(ChangeSetModelPreproc):
    account_id: Final[str]
    region: Final[str]

    def __init__(
        self,
        node_template: NodeTemplate,
        account_id: str,
        region: str,
        stack_name: str,
        stack_id: str,
    ):
        super().__init__(node_template)
        self.account_id = account_id
        self.region = region
        self.stack_name = stack_name
        self.stack_id = stack_id
        self.resources = {}

    def execute(self) -> dict:
        self.process()
        return self.resources

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        delta = super().visit_node_resource(node_resource=node_resource)
        self._execute_on_resource_change(
            name=node_resource.name, before=delta.before, after=delta.after
        )
        return delta

    def _reduce_intrinsic_function_ref_value(self, preproc_value: Any) -> Any:
        # TODO: this should be implemented to compute the runtime reference value for node entities.
        return super()._reduce_intrinsic_function_ref_value(preproc_value=preproc_value)

    def _execute_on_resource_change(
        self, name: str, before: Optional[PreprocResource], after: Optional[PreprocResource]
    ) -> None:
        # TODO: this logic is a POC and should be revised.
        if before is not None and after is not None:
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                self._execute_resource_action(
                    action=ChangeAction.Modify,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before.properties,
                    after_properties=after.properties,
                )
            # Case: type migration.
            # TODO: Add test to assert that on type change the resources are replaced.
            else:
                # Register a Removed for the previous type.
                self._execute_resource_action(
                    action=ChangeAction.Remove,
                    logical_resource_id=name,
                    resource_type=before.resource_type,
                    before_properties=before.properties,
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
            self._execute_resource_action(
                action=ChangeAction.Remove,
                logical_resource_id=name,
                resource_type=before.resource_type,
                before_properties=before.properties,
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

    def _execute_resource_action(
        self,
        action: ChangeAction,
        logical_resource_id: str,
        resource_type: str,
        before_properties: Optional[PreprocProperties],
        after_properties: Optional[PreprocProperties],
    ) -> None:
        resource_provider_executor = ResourceProviderExecutor(
            stack_name=self.stack_name, stack_id=self.stack_id
        )
        # TODO
        resource_type = get_resource_type({"Type": resource_type})
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
            event = resource_provider_executor.deploy_loop(
                resource_provider, extra_resource_properties, payload
            )
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
        if action == ChangeAction.Remove:
            resource_properties = before_properties_value
            previous_resource_properties = None
        else:
            after_properties_value = after_properties.properties if after_properties else None
            resource_properties = after_properties_value
            previous_resource_properties = before_properties_value
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
                # TODO: assign before and previous according on the action type.
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
