from localstack.runtime import hooks


@hooks.on_runtime_ready()
def publish_provider_assignment():
    """
    Publishes the service provider assignment to the analytics service.
    """
    from datetime import datetime

    from localstack.config import SERVICE_PROVIDER_CONFIG
    from localstack.utils.analytics import get_session_id
    from localstack.utils.analytics.events import Event, EventMetadata
    from localstack.utils.analytics.publisher import AnalyticsClientPublisher

    provider_assignment = {
        service: f"localstack.aws.provider/{service}:{provider}"
        for service, provider in SERVICE_PROVIDER_CONFIG.items()
        if provider
    }
    metadata = EventMetadata(
        session_id=get_session_id(),
        client_time=str(datetime.now()),
    )

    event = Event(
        name="ls_service_provider_assignment", metadata=metadata, payload=provider_assignment
    )

    AnalyticsClientPublisher().publish([event])
