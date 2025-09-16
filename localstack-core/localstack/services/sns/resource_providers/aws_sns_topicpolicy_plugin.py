from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SNSTopicPolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SNS::TopicPolicy"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.sns.resource_providers.aws_sns_topicpolicy import (
            SNSTopicPolicyProvider,
        )

        self.factory = SNSTopicPolicyProvider
