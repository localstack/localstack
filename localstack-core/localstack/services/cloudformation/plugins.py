from rolo import Resource

from localstack.runtime import hooks


@hooks.on_infra_start()
def register_cloudformation_deploy_ui():
    from localstack.services.internal import get_internal_apis

    from .deploy_ui import CloudFormationUi

    get_internal_apis().add(Resource("/_localstack/cloudformation/deploy", CloudFormationUi()))
