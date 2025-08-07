from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class DynamoDBTableProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::DynamoDB::Table"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.dynamodb.resource_providers.aws_dynamodb_table import (
            DynamoDBTableProvider,
        )

        self.factory = DynamoDBTableProvider
