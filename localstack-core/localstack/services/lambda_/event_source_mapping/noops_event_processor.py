import logging

from localstack.services.lambda_.event_source_mapping.event_processor import EventProcessor

LOG = logging.getLogger(__name__)


class NoOpsEventProcessor(EventProcessor):
    def process_events_batch(self, input_events: list[dict]) -> None:
        """Intentionally do nothing"""
        LOG.debug(f"Process input events {input_events} using NoOpsEventProcessor")
