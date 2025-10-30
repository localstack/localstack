from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeResource,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)
from localstack.utils.catalog.catalog import (
    AwsServicesSupportStatus,
    CatalogPlugin,
    CfnResourceSupportStatus,
)
from localstack.utils.catalog.common import (
    AwsServicesSupportInLatest,
    AwsServiceSupportAtRuntime,
    CloudFormationResourcesSupportAtRuntime,
    CloudFormationResourcesSupportInLatest,
)
from localstack.utils.catalog.plugins import get_aws_catalog


# TODO handle all available resource types
def _get_service_name(resource_type: str) -> str | None:
    parts = resource_type.split("::")
    if len(parts) == 1:
        return None

    match parts:
        case _ if "Cognito::IdentityPool" in resource_type:
            return "cognito-identity"
        case [*_, "Cognito", "UserPool"]:
            return "cognito-idp"
        case [*_, "Cognito", _]:
            return "cognito-idp"
        case [*_, "Elasticsearch", _]:
            return "es"
        case [*_, "OpenSearchService", _]:
            return "opensearch"
        case [*_, "KinesisFirehose", _]:
            return "firehose"
        case [*_, "ResourceGroups", _]:
            return "resource-groups"
        case [*_, "CertificateManager", _]:
            return "acm"
        case _ if "ElasticLoadBalancing::" in resource_type:
            return "elb"
        case _ if "ElasticLoadBalancingV2::" in resource_type:
            return "elbv2"
        case _ if "ApplicationAutoScaling::" in resource_type:
            return "application-autoscaling"
        case _ if "MSK::" in resource_type:
            return "kafka"
        case _ if "Timestream::" in resource_type:
            return "timestream-write"
        case [_, service, *_]:
            return service.lower()


class ChangeSetResourceSupportChecker(ChangeSetModelVisitor):
    catalog: CatalogPlugin

    _RESOURCE_SUPPORT_STATUS_TEMPLATES = {
        CloudFormationResourcesSupportAtRuntime.NOT_IMPLEMENTED: "Sorry, the {resource} resource (from the {service} service) is not supported by this version of LocalStack, but is available in the latest version.",
        CloudFormationResourcesSupportInLatest.NOT_SUPPORTED: "Sorry, the {resource} resource (from the {service} service) is not currently supported by LocalStack.",
        AwsServiceSupportAtRuntime.AVAILABLE_WITH_LICENSE_UPGRADE: "Sorry, the {service} service (for the {resource} resource) is not included within your LocalStack license, but is available in an upgraded license.",
        AwsServiceSupportAtRuntime.NOT_IMPLEMENTED: "The API for service {service} (for the {resource} resource) is either not included in your current license plan or has not yet been emulated by LocalStack.",
        AwsServicesSupportInLatest.NOT_SUPPORTED: "Sorry, the {service} (for the {resource} resource) service is not currently supported by LocalStack.",
        AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE: "Sorry, the {service} service (for the {resource} resource) is not supported by this version of LocalStack, but is available in the latest version if you upgrade to the latest stable version.",
    }
    _DEFAULT_RESOURCE_SUPPORT_TEMPLATE = (
        "Sorry, the {resource} resource in the {service} service is not supported."
    )

    TITLE_MESSAGE = "Unsupported resources detected:"

    def __init__(self):
        self._resource_failure_messages: dict[str, str] = {}
        self.catalog = get_aws_catalog()

    def visit_node_resource(self, node_resource: NodeResource):
        resource_type = node_resource.type_.value
        if resource_type not in self._resource_failure_messages:
            support_status = self._resource_support_status(resource_type)
            if support_status == CloudFormationResourcesSupportAtRuntime.AVAILABLE:
                pass
            else:
                failure_message = self._build_resource_failure_message(
                    resource_type, support_status
                )
                self._resource_failure_messages[resource_type] = failure_message
        super().visit_node_resource(node_resource)

    def _resource_support_status(
        self, resource_type: str
    ) -> AwsServicesSupportStatus | CfnResourceSupportStatus:
        service_name = _get_service_name(resource_type)
        return self.catalog.get_cloudformation_resource_status(resource_type, service_name, True)

    @property
    def failure_messages(self) -> list[str]:
        return list(self._resource_failure_messages.values())

    def _build_resource_failure_message(
        self, resource_type: str, status: AwsServicesSupportStatus | CfnResourceSupportStatus
    ) -> str:
        service_name = _get_service_name(resource_type) or "malformed"
        template = self._RESOURCE_SUPPORT_STATUS_TEMPLATES.get(
            status,
            self._RESOURCE_SUPPORT_STATUS_TEMPLATES.get(
                status, self._DEFAULT_RESOURCE_SUPPORT_TEMPLATE
            ),
        )
        return template.format(
            resource=resource_type,
            service=service_name,
        )
