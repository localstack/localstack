from localstack.runtime import hooks


@hooks.on_runtime_ready()
def publish_provider_assignment():
    """
    Publishes the service provider assignment to the analytics service.
    """

    from localstack.config import SERVICE_PROVIDER_CONFIG
    from localstack.services.plugins import SERVICE_PLUGINS
    from localstack.utils.analytics import log

    provider_assignment = {
        service: f"localstack.aws.provider/{service}:{SERVICE_PROVIDER_CONFIG[service]}"
        for service in SERVICE_PLUGINS.list_available()
    }

    log.event("ls_service_provider_assignment", provider_assignment)
