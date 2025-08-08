from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SchedulerScheduleGroupProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Scheduler::ScheduleGroup"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.scheduler.resource_providers.aws_scheduler_schedulegroup import (
            SchedulerScheduleGroupProvider,
        )

        self.factory = SchedulerScheduleGroupProvider
