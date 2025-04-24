_COVERAGE_LINK_BASE = "https://docs.localstack.cloud/references/coverage"


def get_coverage_link_for_service(service_name: str, action_name: str) -> str:
    from localstack.services.plugins import SERVICE_PLUGINS

    available_services = SERVICE_PLUGINS.list_available()

    if service_name not in available_services:
        return (
            f"The API for service '{service_name}' is either not included in your current license plan "
            "or has not yet been emulated by LocalStack. "
            f"Please refer to {_COVERAGE_LINK_BASE} for more details."
        )
    else:
        return (
            f"The API action '{action_name}' for service '{service_name}' is either not available in "
            "your current license plan or has not yet been emulated by LocalStack. "
            f"Please refer to {_COVERAGE_LINK_BASE}/coverage_{service_name} for more information."
        )
