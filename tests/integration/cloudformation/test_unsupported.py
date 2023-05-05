import os


def test_unsupported(deploy_cfn_template):
    deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/cfn_waitcondition.yaml")
    )
