import os

from localstack.testing.pytest import markers


# only runs in Docker when run against Pro (since it needs postgres on the system)
@markers.only_in_docker
@markers.aws.validated
def test_redshift_cluster(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_redshift.yaml"
        )
    )

    # very basic test to check the cluster deploys
    assert stack.outputs["ClusterRef"]
    assert stack.outputs["ClusterAttEndpointPort"]
    assert stack.outputs["ClusterAttEndpointAddress"]
