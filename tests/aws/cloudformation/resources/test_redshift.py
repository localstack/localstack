import os

from localstack.testing.pytest import markers


@markers.aws.unknown
def test_redshift_cluster(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/cfn_redshift.yaml")
    )

    # very basic test to check the cluster deploys
    assert stack.outputs["ClusterRef"] is not None
