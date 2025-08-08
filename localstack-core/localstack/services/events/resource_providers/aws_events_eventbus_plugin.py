from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EventsEventBusProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Events::EventBus"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.events.resource_providers.aws_events_eventbus import (
            EventsEventBusProvider,
        )

        self.factory = EventsEventBusProvider
