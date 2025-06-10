from datetime import datetime

from localstack import config
from localstack.runtime import hooks
from localstack.utils.analytics import get_session_id
from localstack.utils.analytics.events import Event, EventMetadata
from localstack.utils.analytics.publisher import AnalyticsClientPublisher

from .registry import MetricRegistry


@hooks.on_infra_shutdown()
def publish_metrics() -> None:
    """
    Collects all the registered metrics and immediately sends them to the analytics service.
    Skips execution if event tracking is disabled (`config.DISABLE_EVENTS`).

    This function is automatically triggered on infrastructure shutdown.
    """
    if config.DISABLE_EVENTS:
        return

    collected_metrics = MetricRegistry().collect()
    if not collected_metrics.payload:  # Skip publishing if no metrics remain after filtering
        return

    metadata = EventMetadata(
        session_id=get_session_id(),
        client_time=str(datetime.now()),
    )

    if collected_metrics:
        publisher = AnalyticsClientPublisher()
        publisher.publish(
            [Event(name="ls_metrics", metadata=metadata, payload=collected_metrics.as_dict())]
        )
