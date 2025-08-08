from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SchedulerScheduleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Scheduler::Schedule"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.scheduler.resource_providers.aws_scheduler_schedule import (
            SchedulerScheduleProvider,
        )

        self.factory = SchedulerScheduleProvider
