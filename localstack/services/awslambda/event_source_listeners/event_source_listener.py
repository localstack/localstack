from typing import Dict, Any, Type

from localstack.utils.objects import SubtypesInstanceManager
from localstack.utils.threads import start_worker_thread


class EventSourceListener(SubtypesInstanceManager):
    INSTANCES: Dict[str, "EventSourceListener"] = {}

    @staticmethod
    def source_type() -> str:
        """Type discriminator - to be implemented by subclasses."""
        raise NotImplementedError

    def start(self):
        """Start listener in the background (for polling mode) - to be implemented by subclasses."""
        pass

    def process_event(self, event: Any):
        """Process the given event (for reactive mode)"""
        pass

    @staticmethod
    def start_listeners(event_source_mapping: Dict):
        source_arn = event_source_mapping.get("EventSourceArn") or ""
        parts = source_arn.split(":")
        service_type = parts[2] if len(parts) > 2 else ""
        if not service_type:
            self_managed_endpoints = event_source_mapping.get("SelfManagedEventSource", {}).get(
                "Endpoints", {}
            )
            if self_managed_endpoints.get("KAFKA_BOOTSTRAP_SERVERS"):
                service_type = "kafka"
        foo = EventSourceListener.instances().keys()
        instance = EventSourceListener.get(service_type, raise_if_missing=False)
        if instance:
            instance.start()

    @staticmethod
    def process_event_via_listener(service_type: str, event: Any):
        """Process event for the given service type (for reactive mode)"""
        instance = EventSourceListener.get(service_type, raise_if_missing=False)
        if not instance:
            return

        def _process(*args):
            instance.process_event(event)

        # start processing in background
        start_worker_thread(_process)

    @classmethod
    def impl_name(cls) -> str:
        return cls.source_type()

    @classmethod
    def get_base_type(cls) -> Type:
        return EventSourceListener