import logging

from localstack.config import LAMBDA_DOCKER_NETWORK
from localstack.packages import Package, package
from localstack.runtime import hooks

LOG = logging.getLogger(__name__)


@package(name="awslambda-go-runtime")
def awslambda_go_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_go_runtime_package

    return awslambda_go_runtime_package


@package(name="awslambda-runtime")
def awslambda_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_runtime_package

    return awslambda_runtime_package


@package(name="lambda-java-libs")
def lambda_java_libs() -> Package:
    from localstack.services.awslambda.packages import lambda_java_libs_package

    return lambda_java_libs_package


@hooks.on_infra_start()
def validate_configuration() -> None:
    if LAMBDA_DOCKER_NETWORK == "host":
        LOG.warning(
            "The configuration LAMBDA_DOCKER_NETWORK=host is currently not supported with the new lambda provider."
        )
