"""Adapters to expose various ways of handling service requests as Service plugins. The Service.listener is attached
to the ServiceRouter as a handler. """
from typing import Any

from localstack.services.plugins import Service, ServiceLifecycleHook

from .chain import Handler, HandlerChain, HandlerChainAdapter


class ServiceProvider(Service):
    """
    Exposes a Provider (something that can be resolved as a Skeleton) as a Service.
    """

    provider: Any

    def __init__(self, provider, service_name: str = None, check=None, start=None):
        if isinstance(provider, ServiceLifecycleHook):
            lifecycle_hook = provider
        else:
            lifecycle_hook = None

        self.provider = provider

        if not service_name:
            service_name = provider.service

        super().__init__(
            service_name, listener=provider, check=check, start=start, lifecycle_hook=lifecycle_hook
        )


class HandlerServiceAdapter(Service):
    """
    Exposes a Handler a Service.
    """

    handler: Handler

    def __init__(self, service: str, handler: Handler, check=None, start=None, lifecycle_hook=None):
        super().__init__(
            service, listener=handler, check=check, start=start, lifecycle_hook=lifecycle_hook
        )
        self.handler = handler


class HandlerChainServiceAdapter(HandlerServiceAdapter):
    """
    Exposes a HandlerChain a Service.
    """

    handler: Handler

    def __init__(
        self, service: str, handler: HandlerChain, check=None, start=None, lifecycle_hook=None
    ):
        super().__init__(
            service,
            HandlerChainAdapter(handler),
            check=check,
            start=start,
            lifecycle_hook=lifecycle_hook,
        )
