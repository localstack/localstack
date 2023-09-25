from localstack.utils.objects import singleton_factory


@singleton_factory
def service_manager():
    from localstack.services.plugins import SERVICE_PLUGINS

    return SERVICE_PLUGINS


@singleton_factory
def gateway():
    from localstack.aws.app import LocalstackAwsGateway

    return LocalstackAwsGateway(service_manager())
