from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SSMMaintenanceWindowProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::MaintenanceWindow"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.ssm.resource_providers.aws_ssm_maintenancewindow import (
            SSMMaintenanceWindowProvider,
        )

        self.factory = SSMMaintenanceWindowProvider
