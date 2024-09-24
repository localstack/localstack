import os

import pytest

from localstack.testing.pytest import markers
from localstack.testing.pytest.fixtures import StackDeployError


class TestResourceAttributes:
    @pytest.mark.skip(reason="failing on unresolved attributes is not enabled yet")
    @markers.snapshot.skip_snapshot_verify
    @markers.aws.validated
    def test_invalid_getatt_fails(self, aws_client, deploy_cfn_template, snapshot):
        """
        Check how CloudFormation behaves on invalid attribute names for resources in a Fn::GetAtt

        Not yet completely correct yet since this should actually initiate a rollback and the stack resource status should be set accordingly
        """
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        with pytest.raises(StackDeployError) as exc_info:
            deploy_cfn_template(
                template_path=os.path.join(
                    os.path.dirname(__file__), "../../../templates/engine/cfn_invalid_getatt.yaml"
                )
            )
        stack_events = exc_info.value.events
        snapshot.match("stack_events", {"events": stack_events})

    @markers.aws.validated
    def test_dependency_on_attribute_with_dot_notation(
        self, deploy_cfn_template, aws_client, snapshot
    ):
        """
        Test that a resource can depend on another resource's attribute with dot notation
        """
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        deployment = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/engine/cfn_getatt_dot_dependency.yml"
            )
        )
        snapshot.match("outputs", deployment.outputs)
