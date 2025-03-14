from localstack import config
from localstack.services.cloudformation.engine.template_deployer.base import *  # noqa: F403


def template_deployer_factory() -> type:
    if config.CFN_ENGINE_V2:
        from localstack.services.cloudformation.engine.template_deployer.v2 import TemplateDeployer
    else:
        from localstack.services.cloudformation.engine.template_deployer.v1 import TemplateDeployer

    return TemplateDeployer
