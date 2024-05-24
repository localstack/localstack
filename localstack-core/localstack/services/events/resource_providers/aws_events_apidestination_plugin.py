from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EventsApiDestinationProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Events::ApiDestination"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.events.resource_providers.aws_events_apidestination import (
            EventsApiDestinationProvider,
        )

        self.factory = EventsApiDestinationProvider
