from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class OpenSearchServiceDomainProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::OpenSearchService::Domain"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.opensearch.resource_providers.aws_opensearchservice_domain import (
            OpenSearchServiceDomainProvider,
        )

        self.factory = OpenSearchServiceDomainProvider
