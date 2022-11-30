import os


def test_get_template_summary(deploy_cfn_template, cfn_client):
    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        )
    )
    res = cfn_client.get_template_summary(StackName=deployment.stack_name)
    assert "Parameters" in res
