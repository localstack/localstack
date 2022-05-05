from typing import Dict, Optional, Type

from localstack.utils.objects import SubtypesInstanceManager


class EventSourceListener(SubtypesInstanceManager):
    INSTANCES: Dict[str, "EventSourceListener"] = {}

    @staticmethod
    def source_type() -> Optional[str]:
        """Type discriminator - to be implemented by subclasses."""
        return None

    def start(self):
        """Start listener in the background (for polling mode) - to be implemented by subclasses."""
        pass

    @staticmethod
    def start_listeners(event_source_mapping: Dict):
        # force import EventSourceListener subclasses
        # otherwise they will not be detected by EventSourceListener.get(service_type)
        from . import dynamodb_event_source_listener  # noqa: F401
        from . import kinesis_event_source_listener  # noqa: F401
        from . import sqs_event_source_listener  # noqa: F401

        source_arn = event_source_mapping.get("EventSourceArn") or ""
        parts = source_arn.split(":")
        service_type = parts[2] if len(parts) > 2 else ""
        if not service_type:
            self_managed_endpoints = event_source_mapping.get("SelfManagedEventSource", {}).get(
                "Endpoints", {}
            )
            if self_managed_endpoints.get("KAFKA_BOOTSTRAP_SERVERS"):
                service_type = "kafka"
        instance = EventSourceListener.get(service_type, raise_if_missing=False)
        if instance:
            instance.start()

    @classmethod
    def impl_name(cls) -> str:
        return cls.source_type()

    @classmethod
    def get_base_type(cls) -> Type:
        return EventSourceListener
