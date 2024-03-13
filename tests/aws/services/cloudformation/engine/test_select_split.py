import os

from localstack.testing.pytest import markers


@markers.aws.validated
def test_select_split_stack_id(aws_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
                template_path=os.path.join(
                    os.path.dirname(__file__), "../../../templates/engine/cfn_select_split.yml"
                )
            )
    snapshot.match("outputs", stack.outputs)
