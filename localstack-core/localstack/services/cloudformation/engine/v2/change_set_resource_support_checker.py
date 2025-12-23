from localstack.aws.api.cloudformation import ChangeSetType
from localstack.services.cloudformation.engine.v2.change_set_model import NodeResource
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)
from localstack.services.cloudformation.engine.v2.unsupported_resource import (
    should_ignore_unsupported_resource_type,
)
from localstack.services.cloudformation.resources import AWS_AVAILABLE_CFN_RESOURCES
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


def _build_resource_failure_message(
    resource_type: str, status: AwsServicesSupportStatus | CfnResourceSupportStatus
) -> str:
    service_name = _get_service_name(resource_type) or "malformed"
    template = "Sorry, the {resource} resource in the {service} service is not supported."
    match status:
        case CloudFormationResourcesSupportAtRuntime.NOT_IMPLEMENTED:
            template = "Sorry, the {resource} resource (from the {service} service) is not supported by this version of LocalStack, but is available in the latest version."
        case CloudFormationResourcesSupportInLatest.NOT_SUPPORTED:
            template = "Sorry, the {resource} resource (from the {service} service) is not currently supported by LocalStack."
        case AwsServiceSupportAtRuntime.AVAILABLE_WITH_LICENSE_UPGRADE:
            template = "Sorry, the {service} service (for the {resource} resource) is not included within your LocalStack license, but is available in an upgraded license."
        case AwsServiceSupportAtRuntime.NOT_IMPLEMENTED:
            template = "The API for service {service} (for the {resource} resource) is either not included in your current license plan or has not yet been emulated by LocalStack."
        case AwsServicesSupportInLatest.NOT_SUPPORTED:
            template = "Sorry, the {service} (for the {resource} resource) service is not currently supported by LocalStack."
        case AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE:
            template = "Sorry, the {service} service (for the {resource} resource) is not supported by this version of LocalStack, but is available in the latest version if you upgrade to the latest stable version."
    return template.format(
        resource=resource_type,
        service=service_name,
    )


class ChangeSetResourceSupportChecker(ChangeSetModelVisitor):
    change_set_type: ChangeSetType
    catalog: CatalogPlugin

    TITLE_MESSAGE = "Unsupported resources detected:"

    def __init__(self, change_set_type: ChangeSetType):
        self._resource_failure_messages: dict[str, str] = {}
        self.change_set_type = change_set_type
        self.catalog = get_aws_catalog()

    def visit_node_resource(self, node_resource: NodeResource):
        resource_type = node_resource.type_.value
        ignore_unsupported = should_ignore_unsupported_resource_type(
            resource_type=resource_type, change_set_type=self.change_set_type
        )

        if resource_type not in self._resource_failure_messages and not ignore_unsupported:
            if resource_type not in AWS_AVAILABLE_CFN_RESOURCES:
                # Ignore non-AWS resources
                pass
            support_status = self._resource_support_status(resource_type)
            if support_status == CloudFormationResourcesSupportAtRuntime.AVAILABLE:
                pass
            else:
                failure_message = _build_resource_failure_message(resource_type, support_status)
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
