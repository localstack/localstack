import os

from localstack.testing.pytest import markers


@markers.aws.validated
def test_unsupported(deploy_cfn_template):
    """
    Exercise the unsupported usage counters
    """
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_unsupported.yaml"
        )
    )
