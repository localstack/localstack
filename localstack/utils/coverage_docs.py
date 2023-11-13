COVERAGE_LINK_BASE = "https://docs.localstack.cloud/references/coverage/"
MESSAGE_TEMPLATE = (
    f"API %sfor service '%s' not yet implemented or pro feature"
    f" - please check {COVERAGE_LINK_BASE}%s for further information"
)


def get_coverage_link_for_service(service_name: str, action_name: str) -> str:
    from localstack.services.plugins import SERVICE_PLUGINS

    available_services = SERVICE_PLUGINS.list_available()

    # TODO remove this once the sqs-query API has been phased out
    if service_name == "sqs-query":
        service_name = "sqs"

    if service_name not in available_services:
        return MESSAGE_TEMPLATE % ("", service_name, "")

    else:
        return MESSAGE_TEMPLATE % (
            f"action '{action_name}' ",
            service_name,
            f"coverage_{service_name}/",
        )
