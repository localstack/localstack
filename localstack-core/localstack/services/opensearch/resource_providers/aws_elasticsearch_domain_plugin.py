from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ElasticsearchDomainProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Elasticsearch::Domain"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.opensearch.resource_providers.aws_elasticsearch_domain import (
            ElasticsearchDomainProvider,
        )

        self.factory = ElasticsearchDomainProvider
