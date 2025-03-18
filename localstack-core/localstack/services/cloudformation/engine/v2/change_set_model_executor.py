import logging
import uuid
from typing import Final

from localstack.aws.api.cloudformation import ChangeAction
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeResource,
    NodeTemplate,
)
from localstack.services.cloudformation.engine.v2.change_set_model_describer import (
    ChangeSetModelDescriber,
    DescribeUnit,
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


class ChangeSetModelExecutor(ChangeSetModelDescriber):
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
        self.visit(self._node_template)
        return self.resources

    def visit_node_resource(self, node_resource: NodeResource):
        resource_provider_executor = ResourceProviderExecutor(
            stack_name=self.stack_name, stack_id=self.stack_id
        )

        # TODO: investigate effects on type changes
        properties_describe_unit = self.visit_node_properties(node_resource.properties)
        LOG.info("SRW: describe unit: %s", properties_describe_unit)

        action = node_resource.change_type.to_action()
        if action is None:
            raise RuntimeError(
                f"Action should always be present, got change type: {node_resource.change_type}"
            )

        resource_type = get_resource_type(node_resource.as_dict())
        payload = self.create_resource_provider_payload(
            properties_describe_unit,
            action,
            node_resource.name,
            resource_type,
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

        self.resources.setdefault(node_resource.name, {"Properties": {}})
        match event.status:
            case OperationStatus.SUCCESS:
                # merge the resources state with the external state
                # TODO: this is likely a duplicate of updating from extra_resource_properties
                self.resources[node_resource.name]["Properties"].update(event.resource_model)
                self.resources[node_resource.name].update(extra_resource_properties)
            case any:
                raise NotImplementedError(f"Event status '{any}' not handled")

    def create_resource_provider_payload(
        self,
        describe_unit: DescribeUnit,
        action: ChangeAction,
        logical_resource_id: str,
        resource_type: str,
    ) -> ResourceProviderPayload:
        # FIXME: use proper credentials
        creds: Credentials = {
            "accessKeyId": self.account_id,
            "secretAccessKey": INTERNAL_AWS_SECRET_ACCESS_KEY,
            "sessionToken": "",
        }
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
                "resourceProperties": describe_unit.after_context["Properties"],
                "previousResourceProperties": describe_unit.before_context["Properties"],
                "callerCredentials": creds,
                "providerCredentials": creds,
                "systemTags": {},
                "previousSystemTags": {},
                "stackTags": {},
                "previousStackTags": {},
            },
        }
        return resource_provider_payload
