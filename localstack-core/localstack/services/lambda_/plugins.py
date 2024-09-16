import logging

from werkzeug.routing import Rule

from localstack.config import LAMBDA_DOCKER_NETWORK
from localstack.packages import Package, package
from localstack.runtime import hooks
from localstack.services.edge import ROUTER
from localstack.services.lambda_.custom_endpoints import LambdaCustomEndpoints

LOG = logging.getLogger(__name__)

CUSTOM_ROUTER_RULES: list[Rule] = []


@package(name="lambda-runtime")
def lambda_runtime_package() -> Package:
    from localstack.services.lambda_.packages import lambda_runtime_package

    return lambda_runtime_package


@package(name="lambda-java-libs")
def lambda_java_libs() -> Package:
    from localstack.services.lambda_.packages import lambda_java_libs_package

    return lambda_java_libs_package


@hooks.on_infra_start()
def validate_configuration() -> None:
    if LAMBDA_DOCKER_NETWORK == "host":
        LOG.warning(
            "The configuration LAMBDA_DOCKER_NETWORK=host is currently not supported with the new lambda provider."
        )


@hooks.on_infra_start()
def register_custom_endpoints() -> None:
    global CUSTOM_ROUTER_RULES
    CUSTOM_ROUTER_RULES = ROUTER.add(LambdaCustomEndpoints())


@hooks.on_infra_shutdown()
def remove_custom_endpoints() -> None:
    ROUTER.remove(CUSTOM_ROUTER_RULES)
